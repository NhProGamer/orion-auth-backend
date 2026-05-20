package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/oauth2"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// authRequestTTL governs how long a generated state remains valid between
// the authorize redirect and the provider callback.
const authRequestTTL = 10 * time.Minute

// defaultAttributeMapper is the OIDC-standard claim-to-user-field mapping
// applied when a provider does not declare one explicitly.
var defaultAttributeMapper = json.RawMessage(`{"external_id":"sub","email":"email","email_verified":"email_verified","name":"name","picture":"picture"}`)

type Service struct {
	repo              RepositoryInterface
	stateRepo         StateRepositoryInterface
	builder           *Builder
	users             UserProvisioner
	registration      RegistrationGate
	invitations       InvitationValidator
	oauthResumer      OAuthResumer
	authUIBase        string
	issuer            string
	hmacEncryptionKey []byte
}

// NewService constructs the federation service. hmacEncryptionKey is the
// shared AES-256 key used to seal provider client_secrets at rest (same key
// used for OAuth client HMAC secrets). When nil, providers cannot be created
// or updated with a client_secret — operators must rotate via UpdateProvider
// once the key is configured. stateRepo and builder may be nil for legacy
// constructions; the real-OAuth code paths verify their presence at use.
func NewService(repo RepositoryInterface, issuer string, hmacEncryptionKey []byte) *Service {
	return &Service{
		repo:              repo,
		issuer:            issuer,
		hmacEncryptionKey: hmacEncryptionKey,
		builder:           NewBuilder(),
	}
}

// SetStateRepository wires the ephemeral state store. Required for the real
// authorize/callback OAuth dance (Phase 4+).
func (s *Service) SetStateRepository(repo StateRepositoryInterface) {
	s.stateRepo = repo
}

// SetBuilder lets tests inject a stub Builder.
func (s *Service) SetBuilder(b *Builder) {
	s.builder = b
}

// SetProvisioningDependencies wires the user provisioning, registration
// gate, and invitation validator. Required for ProcessCallback to actually
// log a user in (otherwise it returns the validated claims only).
func (s *Service) SetProvisioningDependencies(users UserProvisioner, reg RegistrationGate, invs InvitationValidator) {
	s.users = users
	s.registration = reg
	s.invitations = invs
}

// SetOAuthResumer wires the OrionAuth authorize-flow continuation. Required
// for federation callbacks to resume an /authorize in progress instead of
// just dropping the user on a generic post-login page.
func (s *Service) SetOAuthResumer(r OAuthResumer) {
	s.oauthResumer = r
}

// SetAuthUIBaseURL configures the SPA origin the federation handler
// redirects to for interactive flows (link confirmation, onboarding,
// consent, MFA). Falls back to the issuer URL when empty.
func (s *Service) SetAuthUIBaseURL(u string) {
	s.authUIBase = strings.TrimRight(u, "/")
}

// AuthUIBaseURL returns the configured AuthUI origin (or the issuer as
// fallback). Exposed so the handler can build redirect URLs.
func (s *Service) AuthUIBaseURL() string {
	if s.authUIBase != "" {
		return s.authUIBase
	}
	return strings.TrimRight(s.issuer, "/")
}

// OAuthResumer exposes the wired continuation client so handlers can call
// directly without needing another setter pair.
func (s *Service) OAuthResumerClient() OAuthResumer { return s.oauthResumer }

// sealSecret encrypts a provider client_secret with the server-side AES key.
// Returns the wire-format ciphertext (12-byte nonce || ciphertext+tag).
func (s *Service) sealSecret(plaintext string) ([]byte, error) {
	if len(s.hmacEncryptionKey) == 0 {
		return nil, pkg.ErrBadRequest("federation client_secret encryption is not configured (auth.hmac_secret_encryption_key is unset)")
	}
	return crypto.EncryptHMACSecret([]byte(plaintext), s.hmacEncryptionKey)
}

// RevealSecret returns the plaintext client_secret of a provider, decrypting
// it lazily. Prefers the encrypted column; falls back to the legacy plaintext
// column for backward compatibility with rows created before migration 039.
func (s *Service) RevealSecret(p *model.FederationProvider) (string, error) {
	if len(p.ClientSecretEncrypted) > 0 {
		if len(s.hmacEncryptionKey) == 0 {
			return "", pkg.ErrInternal("encrypted federation secret cannot be opened (auth.hmac_secret_encryption_key is unset)")
		}
		raw, err := crypto.DecryptHMACSecret(p.ClientSecretEncrypted, s.hmacEncryptionKey)
		if err != nil {
			return "", pkg.ErrInternal("failed to decrypt federation client_secret")
		}
		return string(raw), nil
	}
	if p.ClientSecret != nil && *p.ClientSecret != "" {
		return *p.ClientSecret, nil
	}
	return "", pkg.ErrInternal("federation provider has no client_secret configured")
}

// --- Admin Provider CRUD ---

type CreateProviderInput struct {
	Name                  string          `json:"name" binding:"required"`
	DisplayName           *string         `json:"display_name"`
	Type                  string          `json:"type" binding:"required"`
	ClientID              string          `json:"client_id" binding:"required"`
	ClientSecret          string          `json:"client_secret" binding:"required"`
	IssuerURL             *string         `json:"issuer_url"`
	AuthorizationURL      *string         `json:"authorization_url"`
	TokenURL              *string         `json:"token_url"`
	UserinfoURL           *string         `json:"userinfo_url"`
	JWKSUri               *string         `json:"jwks_uri,omitempty"`
	Scopes                []string        `json:"scopes"`
	AttributeMapper       json.RawMessage `json:"attribute_mapper,omitempty"`
	SyncOnLogin           *bool           `json:"sync_on_login,omitempty"`
	AllowLinkConfirmation *bool           `json:"allow_link_confirmation,omitempty"`
}

type UpdateProviderInput struct {
	DisplayName           *string         `json:"display_name"`
	ClientID              *string         `json:"client_id"`
	ClientSecret          *string         `json:"client_secret"`
	IssuerURL             *string         `json:"issuer_url"`
	AuthorizationURL      *string         `json:"authorization_url"`
	TokenURL              *string         `json:"token_url"`
	UserinfoURL           *string         `json:"userinfo_url"`
	JWKSUri               *string         `json:"jwks_uri,omitempty"`
	Scopes                []string        `json:"scopes"`
	AttributeMapper       json.RawMessage `json:"attribute_mapper,omitempty"`
	SyncOnLogin           *bool           `json:"sync_on_login,omitempty"`
	AllowLinkConfirmation *bool           `json:"allow_link_confirmation,omitempty"`
	Active                *bool           `json:"active"`
}

// validateAttributeMapper enforces a small allowlist of mapper keys to keep
// the provider configuration auditable. Values must be strings (claim names).
var allowedMapperKeys = map[string]struct{}{
	"external_id":    {},
	"email":          {},
	"email_verified": {},
	"name":           {},
	"picture":        {},
}

func validateAttributeMapper(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return pkg.ErrBadRequest("attribute_mapper must be a JSON object")
	}
	for k, v := range m {
		if _, ok := allowedMapperKeys[k]; !ok {
			return pkg.ErrBadRequest(fmt.Sprintf("attribute_mapper key %q is not allowed", k))
		}
		if _, ok := v.(string); !ok {
			return pkg.ErrBadRequest(fmt.Sprintf("attribute_mapper[%q] must be a string", k))
		}
	}
	return nil
}

func (s *Service) CreateProvider(input CreateProviderInput) (*model.FederationProvider, error) {
	existing, _ := s.repo.FindProviderByName(input.Name)
	if existing != nil {
		return nil, pkg.ErrConflict("provider name already exists")
	}
	if err := validateAttributeMapper(input.AttributeMapper); err != nil {
		return nil, err
	}

	sealed, err := s.sealSecret(input.ClientSecret)
	if err != nil {
		return nil, err
	}

	mapper := input.AttributeMapper
	if len(mapper) == 0 {
		mapper = append(json.RawMessage(nil), defaultAttributeMapper...)
	}

	p := &model.FederationProvider{
		Name:                  input.Name,
		DisplayName:           input.DisplayName,
		Type:                  input.Type,
		ClientID:              input.ClientID,
		ClientSecretEncrypted: sealed,
		IssuerURL:             input.IssuerURL,
		AuthorizationURL:      input.AuthorizationURL,
		TokenURL:              input.TokenURL,
		UserinfoURL:           input.UserinfoURL,
		JWKSUri:               input.JWKSUri,
		Scopes:                pq.StringArray(input.Scopes),
		AttributeMapper:       mapper,
		SyncOnLogin:           input.SyncOnLogin != nil && *input.SyncOnLogin,
		AllowLinkConfirmation: input.AllowLinkConfirmation != nil && *input.AllowLinkConfirmation,
		Active:                true,
	}

	if err := s.repo.CreateProvider(p); err != nil {
		return nil, pkg.ErrInternal("failed to create provider")
	}

	slog.Info("federation provider created", "name", p.Name)
	return p, nil
}

func (s *Service) GetProvider(id uuid.UUID) (*model.FederationProvider, error) {
	p, err := s.repo.FindProviderByID(id)
	if err != nil || p == nil {
		return nil, pkg.ErrNotFound("provider not found")
	}
	return p, nil
}

func (s *Service) ListProviders() ([]model.FederationProvider, error) {
	return s.repo.ListProviders()
}

// ListActiveProviders returns only active providers (for public exposure).
func (s *Service) ListActiveProviders() ([]model.FederationProvider, error) {
	providers, err := s.repo.ListProviders()
	if err != nil {
		return nil, err
	}
	var active []model.FederationProvider
	for _, p := range providers {
		if p.Active {
			active = append(active, p)
		}
	}
	return active, nil
}

func (s *Service) UpdateProvider(id uuid.UUID, input UpdateProviderInput) (*model.FederationProvider, error) {
	p, err := s.GetProvider(id)
	if err != nil {
		return nil, err
	}
	if err := validateAttributeMapper(input.AttributeMapper); err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		p.DisplayName = input.DisplayName
	}
	if input.ClientID != nil {
		p.ClientID = *input.ClientID
	}
	if input.ClientSecret != nil {
		sealed, err := s.sealSecret(*input.ClientSecret)
		if err != nil {
			return nil, err
		}
		p.ClientSecretEncrypted = sealed
		p.ClientSecret = nil // drop any legacy plaintext value
	}
	if input.IssuerURL != nil {
		p.IssuerURL = input.IssuerURL
	}
	if input.AuthorizationURL != nil {
		p.AuthorizationURL = input.AuthorizationURL
	}
	if input.TokenURL != nil {
		p.TokenURL = input.TokenURL
	}
	if input.UserinfoURL != nil {
		p.UserinfoURL = input.UserinfoURL
	}
	if input.JWKSUri != nil {
		p.JWKSUri = input.JWKSUri
	}
	if input.Scopes != nil {
		p.Scopes = pq.StringArray(input.Scopes)
	}
	if len(input.AttributeMapper) > 0 {
		p.AttributeMapper = input.AttributeMapper
	}
	if input.SyncOnLogin != nil {
		p.SyncOnLogin = *input.SyncOnLogin
	}
	if input.AllowLinkConfirmation != nil {
		p.AllowLinkConfirmation = *input.AllowLinkConfirmation
	}
	if input.Active != nil {
		p.Active = *input.Active
	}

	if err := s.repo.UpdateProvider(p); err != nil {
		return nil, pkg.ErrInternal("failed to update provider")
	}
	if s.builder != nil {
		s.builder.Invalidate(p.ID)
	}
	return p, nil
}

func (s *Service) DeleteProvider(id uuid.UUID) error {
	if _, err := s.GetProvider(id); err != nil {
		return err
	}
	if err := s.repo.DeleteProvider(id); err != nil {
		return err
	}
	if s.builder != nil {
		s.builder.Invalidate(id)
	}
	return nil
}

// --- Social Login ---

// InitOptions carries the continuation context the backend will restore on
// callback (return_to, OAuth authorize continuation, invitation token), plus
// the request metadata recorded for audit/diagnostics.
type InitOptions struct {
	ReturnTo        string
	OAuthRequestID  *uuid.UUID
	InvitationToken string
	IPAddress       string
	UserAgent       string
}

// InitSocialLogin builds the provider's authorization URL with state, PKCE
// (S256) and an OIDC nonce, persists the corresponding auth request so the
// callback can resume the flow, and returns the absolute URL to which the
// user should be redirected.
func (s *Service) InitSocialLogin(ctx context.Context, providerName string, opts InitOptions) (string, error) {
	if s.stateRepo == nil {
		return "", pkg.ErrInternal("federation state store is not configured")
	}
	provider, err := s.repo.FindProviderByName(providerName)
	if err != nil || provider == nil {
		return "", pkg.ErrNotFound("provider not found")
	}

	secret, err := s.RevealSecret(provider)
	if err != nil {
		return "", err
	}

	state, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate state")
	}
	codeVerifier, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate PKCE verifier")
	}
	nonce, err := crypto.GenerateRandomString(16)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate nonce")
	}

	callbackURL := s.callbackURL(provider)
	oc, err := s.builder.ForProvider(ctx, provider, secret, callbackURL)
	if err != nil {
		return "", err
	}

	challenge := pkceS256Challenge(codeVerifier)
	authURL := oc.Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
	)

	req := &model.FederationAuthRequest{
		State:           state,
		ProviderID:      provider.ID,
		CodeVerifier:    codeVerifier,
		Nonce:           nonce,
		ReturnTo:        nullableString(opts.ReturnTo),
		OAuthRequestID:  opts.OAuthRequestID,
		InvitationToken: nullableString(opts.InvitationToken),
		IPAddress:       nullableString(opts.IPAddress),
		UserAgent:       nullableString(opts.UserAgent),
		ExpiresAt:       time.Now().Add(authRequestTTL),
	}
	if err := s.stateRepo.InsertAuthRequest(req); err != nil {
		return "", pkg.ErrInternal("failed to persist federation auth request")
	}

	slog.Info("federation login initiated", "provider", provider.Name, "state", state)
	return authURL, nil
}

func (s *Service) callbackURL(p *model.FederationProvider) string {
	return fmt.Sprintf("%s/api/v1/auth/federation/%s/callback", s.issuer, p.Name)
}

func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

// CallbackResult represents the result of processing a federation callback.
type CallbackResult struct {
	UserID     uuid.UUID `json:"user_id"`
	ExternalID string    `json:"external_id"`
	Email      string    `json:"email,omitempty"`
	IsNewUser  bool      `json:"is_new_user"`
	IsNewLink  bool      `json:"is_new_link"`
}

// ProviderClaims is the normalised view of an authenticated external
// identity, derived from either an id_token or a userinfo response and
// shaped through the provider's configured attribute_mapper.
type ProviderClaims struct {
	ExternalID    string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Raw           map[string]any
}

// CallbackContext bundles everything the downstream provisioning logic
// (Phase 6) needs to act on a successful authorize callback: the provider
// row, the consumed auth-request (with its continuation context) and the
// validated claims.
type CallbackContext struct {
	Provider    *model.FederationProvider
	AuthRequest *model.FederationAuthRequest
	Claims      ProviderClaims
	RawIDToken  string // empty for non-OIDC providers
}

// ProcessCallback validates the state, exchanges the authorization code,
// verifies the id_token (OIDC) or fetches userinfo (OAuth 2.0), applies
// the attribute mapper, and returns the normalised claims plus the
// consumed auth request.
func (s *Service) ProcessCallback(ctx context.Context, providerName, code, state string) (*CallbackContext, error) {
	if s.stateRepo == nil {
		return nil, pkg.ErrInternal("federation state store is not configured")
	}
	if code == "" || state == "" {
		return nil, pkg.ErrBadRequest("code and state are required")
	}

	authReq, err := s.stateRepo.ConsumeAuthRequest(state)
	if err != nil {
		return nil, pkg.ErrInternal("failed to consume federation state")
	}
	if authReq == nil {
		return nil, pkg.ErrBadRequest("invalid or expired state")
	}

	provider, err := s.repo.FindProviderByName(providerName)
	if err != nil || provider == nil {
		return nil, pkg.ErrNotFound("provider not found")
	}
	if provider.ID != authReq.ProviderID {
		return nil, pkg.ErrBadRequest("state does not match provider")
	}

	secret, err := s.RevealSecret(provider)
	if err != nil {
		return nil, err
	}

	oc, err := s.builder.ForProvider(ctx, provider, secret, s.callbackURL(provider))
	if err != nil {
		return nil, err
	}

	httpCtx := s.builder.HTTPContext(ctx)
	tok, err := oc.Config.Exchange(httpCtx, code,
		oauth2.SetAuthURLParam("code_verifier", authReq.CodeVerifier),
	)
	if err != nil {
		slog.Warn("federation code exchange failed", "provider", providerName, "error", err)
		return nil, pkg.ErrBadRequest("code exchange failed: " + err.Error())
	}

	rawClaims, rawIDToken, err := s.extractClaims(httpCtx, oc, tok, authReq.Nonce)
	if err != nil {
		return nil, err
	}

	claims, err := applyAttributeMapper(rawClaims, provider.AttributeMapper)
	if err != nil {
		return nil, err
	}
	claims.Raw = rawClaims

	return &CallbackContext{
		Provider:    provider,
		AuthRequest: authReq,
		Claims:      claims,
		RawIDToken:  rawIDToken,
	}, nil
}

// extractClaims pulls either id_token claims (OIDC) or userinfo claims
// (OAuth 2.0) out of a token response. For OIDC providers, the id_token's
// signature, issuer, audience, expiry and nonce are validated.
func (s *Service) extractClaims(ctx context.Context, oc *OAuthClient, tok *oauth2.Token, expectedNonce string) (map[string]any, string, error) {
	if oc.IsOIDC {
		rawIDToken, _ := tok.Extra("id_token").(string)
		if rawIDToken == "" {
			return nil, "", pkg.ErrBadRequest("provider response missing id_token")
		}
		idToken, err := oc.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, "", pkg.ErrBadRequest("id_token verification failed: " + err.Error())
		}
		if idToken.Nonce != expectedNonce {
			return nil, "", pkg.ErrBadRequest("id_token nonce mismatch")
		}
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			return nil, "", pkg.ErrInternal("failed to decode id_token claims")
		}
		return claims, rawIDToken, nil
	}

	if oc.UserinfoURL == "" {
		return nil, "", pkg.ErrBadRequest("oauth2 provider requires userinfo_url")
	}
	client := oc.Config.Client(ctx, tok)
	resp, err := client.Get(oc.UserinfoURL)
	if err != nil {
		return nil, "", pkg.ErrBadRequest("userinfo fetch failed: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, "", pkg.ErrBadRequest(fmt.Sprintf("userinfo returned HTTP %d", resp.StatusCode))
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, "", pkg.ErrBadRequest("userinfo response is not JSON")
	}
	return claims, "", nil
}

// applyAttributeMapper reads the provider's claim-to-field mapping (with a
// safe default fallback) and projects the raw claim map onto a structured
// ProviderClaims value.
func applyAttributeMapper(raw map[string]any, mapper json.RawMessage) (ProviderClaims, error) {
	m := map[string]string{}
	source := mapper
	if len(source) == 0 {
		source = defaultAttributeMapper
	}
	if err := json.Unmarshal(source, &m); err != nil {
		return ProviderClaims{}, pkg.ErrInternal("invalid attribute_mapper stored on provider")
	}
	pick := func(key string) string {
		claim, ok := m[key]
		if !ok || claim == "" {
			return ""
		}
		v, ok := raw[claim]
		if !ok || v == nil {
			return ""
		}
		s, _ := v.(string)
		return s
	}
	pickBool := func(key string) bool {
		claim, ok := m[key]
		if !ok || claim == "" {
			return false
		}
		v, ok := raw[claim]
		if !ok || v == nil {
			return false
		}
		b, _ := v.(bool)
		return b
	}
	return ProviderClaims{
		ExternalID:    pick("external_id"),
		Email:         pick("email"),
		EmailVerified: pickBool("email_verified"),
		Name:          pick("name"),
		Picture:       pick("picture"),
	}, nil
}

// --- Linked Accounts ---

func (s *Service) GetLinkedAccounts(userID uuid.UUID) ([]model.FederationLink, error) {
	return s.repo.FindLinksByUser(userID)
}

func (s *Service) UnlinkAccount(linkID, userID uuid.UUID) error {
	link, err := s.repo.FindLinkByID(linkID)
	if err != nil || link == nil {
		return pkg.ErrNotFound("linked account not found")
	}
	if link.UserID != userID {
		return pkg.ErrForbidden("linked account does not belong to user")
	}
	return s.repo.DeleteLink(linkID)
}
