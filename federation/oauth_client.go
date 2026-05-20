package federation

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// ProviderType discriminates how the wrapper builds its oauth2/oidc config.
const (
	ProviderTypeOIDC   = "oidc"
	ProviderTypeOAuth2 = "oauth2"
)

// OAuthClient is everything a single federation request needs to talk to a
// provider: a configured oauth2.Config, an optional id_token verifier
// (OIDC only), and the resolved userinfo endpoint URL.
type OAuthClient struct {
	Config      *oauth2.Config
	Verifier    *oidc.IDTokenVerifier // nil for non-OIDC providers
	UserinfoURL string                // may be empty if the caller does not need it
	IsOIDC      bool
}

// HTTPContext returns a context carrying the builder's HTTP client so both
// go-oidc and golang.org/x/oauth2 honour the same timeouts and transport.
func (b *Builder) HTTPContext(parent context.Context) context.Context {
	if b.httpClient == nil {
		return parent
	}
	return oidc.ClientContext(parent, b.httpClient)
}

// Builder lazily constructs and caches the expensive parts of OIDC provider
// metadata (discovery doc + JWKS remote key set), keyed by provider ID and
// invalidated whenever the provider row is updated.
type Builder struct {
	mu         sync.Mutex
	cache      map[uuid.UUID]builderEntry
	httpClient *http.Client
}

type builderEntry struct {
	updatedAt   time.Time
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	userinfoURL string
	clientID    string
}

// NewBuilder returns a Builder with a sensible default HTTP client (15s
// timeout) shared across discovery, JWKS, and token-endpoint calls.
func NewBuilder() *Builder {
	return &Builder{
		cache:      map[uuid.UUID]builderEntry{},
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Invalidate drops the cached metadata for a provider. Called by the
// service whenever the underlying configuration changes (update / delete).
func (b *Builder) Invalidate(providerID uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.cache, providerID)
}

// ForProvider returns an OAuthClient ready to drive a single authorize +
// callback cycle. clientSecret must be the plaintext value (caller decrypts
// via Service.RevealSecret). redirectURL is the absolute callback URL the
// provider must redirect back to.
func (b *Builder) ForProvider(ctx context.Context, p *model.FederationProvider, clientSecret, redirectURL string) (*OAuthClient, error) {
	switch p.Type {
	case ProviderTypeOIDC:
		return b.forOIDC(ctx, p, clientSecret, redirectURL)
	case ProviderTypeOAuth2:
		return b.forOAuth2(p, clientSecret, redirectURL), nil
	default:
		return nil, pkg.ErrBadRequest(fmt.Sprintf("unsupported federation provider type %q", p.Type))
	}
}

func (b *Builder) forOIDC(ctx context.Context, p *model.FederationProvider, clientSecret, redirectURL string) (*OAuthClient, error) {
	if p.IssuerURL == nil || *p.IssuerURL == "" {
		return nil, pkg.ErrBadRequest("oidc provider requires issuer_url")
	}

	entry, err := b.oidcEntry(ctx, p)
	if err != nil {
		return nil, err
	}

	cfg := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     entry.provider.Endpoint(),
		Scopes:       append([]string(nil), p.Scopes...),
	}
	userinfoURL := entry.userinfoURL
	if p.UserinfoURL != nil && *p.UserinfoURL != "" {
		userinfoURL = *p.UserinfoURL
	}
	return &OAuthClient{
		Config:      cfg,
		Verifier:    entry.verifier,
		UserinfoURL: userinfoURL,
		IsOIDC:      true,
	}, nil
}

func (b *Builder) forOAuth2(p *model.FederationProvider, clientSecret, redirectURL string) *OAuthClient {
	authURL := ""
	if p.AuthorizationURL != nil {
		authURL = *p.AuthorizationURL
	}
	tokenURL := ""
	if p.TokenURL != nil {
		tokenURL = *p.TokenURL
	}
	userinfoURL := ""
	if p.UserinfoURL != nil {
		userinfoURL = *p.UserinfoURL
	}
	cfg := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: append([]string(nil), p.Scopes...),
	}
	return &OAuthClient{Config: cfg, UserinfoURL: userinfoURL, IsOIDC: false}
}

// oidcEntry returns a cached (or freshly discovered) OIDC provider entry.
// Cache is invalidated when the provider row's UpdatedAt advances or when
// the configured client_id changes.
func (b *Builder) oidcEntry(ctx context.Context, p *model.FederationProvider) (builderEntry, error) {
	b.mu.Lock()
	entry, ok := b.cache[p.ID]
	b.mu.Unlock()
	if ok && !p.UpdatedAt.After(entry.updatedAt) && entry.clientID == p.ClientID {
		return entry, nil
	}

	httpCtx := b.HTTPContext(ctx)
	oidcProvider, err := oidc.NewProvider(httpCtx, *p.IssuerURL)
	if err != nil {
		return builderEntry{}, pkg.ErrInternal("oidc discovery failed: " + err.Error())
	}

	var meta struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
		JWKSUri          string `json:"jwks_uri"`
	}
	if err := oidcProvider.Claims(&meta); err != nil {
		return builderEntry{}, pkg.ErrInternal("oidc discovery claims unreadable: " + err.Error())
	}

	verifier := oidcProvider.VerifierContext(httpCtx, &oidc.Config{
		ClientID:             p.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256, oidc.PS256},
	})

	entry = builderEntry{
		updatedAt:   p.UpdatedAt,
		provider:    oidcProvider,
		verifier:    verifier,
		userinfoURL: meta.UserinfoEndpoint,
		clientID:    p.ClientID,
	}
	b.mu.Lock()
	b.cache[p.ID] = entry
	b.mu.Unlock()
	return entry, nil
}
