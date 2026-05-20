package federation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// defaultAttributeMapper is the OIDC-standard claim-to-user-field mapping
// applied when a provider does not declare one explicitly.
var defaultAttributeMapper = json.RawMessage(`{"external_id":"sub","email":"email","email_verified":"email_verified","name":"name","picture":"picture"}`)

type Service struct {
	repo              RepositoryInterface
	issuer            string
	hmacEncryptionKey []byte
}

// NewService constructs the federation service. hmacEncryptionKey is the
// shared AES-256 key used to seal provider client_secrets at rest (same key
// used for OAuth client HMAC secrets). When nil, providers cannot be created
// or updated with a client_secret — operators must rotate via UpdateProvider
// once the key is configured.
func NewService(repo RepositoryInterface, issuer string, hmacEncryptionKey []byte) *Service {
	return &Service{repo: repo, issuer: issuer, hmacEncryptionKey: hmacEncryptionKey}
}

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
	return p, nil
}

func (s *Service) DeleteProvider(id uuid.UUID) error {
	if _, err := s.GetProvider(id); err != nil {
		return err
	}
	return s.repo.DeleteProvider(id)
}

// --- Social Login ---

// InitSocialLogin returns the authorization URL to redirect the user to.
func (s *Service) InitSocialLogin(providerName string) (string, error) {
	provider, err := s.repo.FindProviderByName(providerName)
	if err != nil || provider == nil {
		return "", pkg.ErrNotFound("provider not found")
	}

	if provider.AuthorizationURL == nil {
		return "", pkg.ErrBadRequest("provider has no authorization URL configured")
	}

	callbackURL := fmt.Sprintf("%s/api/v1/auth/federation/%s/callback", s.issuer, provider.Name)
	scopes := strings.Join(provider.Scopes, " ")

	params := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {callbackURL},
		"response_type": {"code"},
		"scope":         {scopes},
	}

	authURL := *provider.AuthorizationURL + "?" + params.Encode()
	return authURL, nil
}

// CallbackResult represents the result of processing a federation callback.
type CallbackResult struct {
	UserID     uuid.UUID `json:"user_id"`
	ExternalID string    `json:"external_id"`
	Email      string    `json:"email,omitempty"`
	IsNewUser  bool      `json:"is_new_user"`
	IsNewLink  bool      `json:"is_new_link"`
}

// ProcessCallback processes the callback from the external provider.
// In a real implementation, this would exchange the code for tokens and fetch user info.
// For now, it accepts the external user info directly (the consuming app handles the token exchange).
type CallbackInput struct {
	ExternalID string          `json:"external_id" binding:"required"`
	Email      string          `json:"email"`
	Metadata   json.RawMessage `json:"metadata"`
}

func (s *Service) ProcessCallback(providerName string, input CallbackInput, existingUserID *uuid.UUID) (*CallbackResult, error) {
	provider, err := s.repo.FindProviderByName(providerName)
	if err != nil || provider == nil {
		return nil, pkg.ErrNotFound("provider not found")
	}

	// Check if this external account is already linked
	link, _ := s.repo.FindLink(provider.ID, input.ExternalID)

	if link != nil {
		// Account already linked, return the user
		return &CallbackResult{
			UserID:     link.UserID,
			ExternalID: input.ExternalID,
			Email:      input.Email,
		}, nil
	}

	// New link
	if existingUserID == nil {
		return nil, pkg.ErrBadRequest("no user ID provided for account linking; user must be authenticated")
	}

	emailPtr := &input.Email
	if input.Email == "" {
		emailPtr = nil
	}

	newLink := &model.FederationLink{
		UserID:     *existingUserID,
		ProviderID: provider.ID,
		ExternalID: input.ExternalID,
		Email:      emailPtr,
		Metadata:   input.Metadata,
	}

	if err := s.repo.CreateLink(newLink); err != nil {
		return nil, pkg.ErrInternal("failed to create federation link")
	}

	slog.Info("federation link created", "user_id", existingUserID, "provider", providerName, "external_id", input.ExternalID)
	return &CallbackResult{
		UserID:     *existingUserID,
		ExternalID: input.ExternalID,
		Email:      input.Email,
		IsNewLink:  true,
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
