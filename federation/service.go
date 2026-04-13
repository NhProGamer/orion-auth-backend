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

type Service struct {
	repo   *Repository
	issuer string
}

func NewService(repo *Repository, issuer string) *Service {
	return &Service{repo: repo, issuer: issuer}
}

// --- Admin Provider CRUD ---

type CreateProviderInput struct {
	Name             string   `json:"name" binding:"required"`
	DisplayName      *string  `json:"display_name"`
	Type             string   `json:"type" binding:"required"`
	ClientID         string   `json:"client_id" binding:"required"`
	ClientSecret     string   `json:"client_secret" binding:"required"`
	IssuerURL        *string  `json:"issuer_url"`
	AuthorizationURL *string  `json:"authorization_url"`
	TokenURL         *string  `json:"token_url"`
	UserinfoURL      *string  `json:"userinfo_url"`
	Scopes           []string `json:"scopes"`
}

type UpdateProviderInput struct {
	DisplayName      *string  `json:"display_name"`
	ClientID         *string  `json:"client_id"`
	ClientSecret     *string  `json:"client_secret"`
	IssuerURL        *string  `json:"issuer_url"`
	AuthorizationURL *string  `json:"authorization_url"`
	TokenURL         *string  `json:"token_url"`
	UserinfoURL      *string  `json:"userinfo_url"`
	Scopes           []string `json:"scopes"`
	Active           *bool    `json:"active"`
}

func (s *Service) CreateProvider(input CreateProviderInput) (*model.FederationProvider, error) {
	existing, _ := s.repo.FindProviderByName(input.Name)
	if existing != nil {
		return nil, pkg.ErrConflict("provider name already exists")
	}

	p := &model.FederationProvider{
		Name:             input.Name,
		DisplayName:      input.DisplayName,
		Type:             input.Type,
		ClientID:         input.ClientID,
		ClientSecret:     input.ClientSecret,
		IssuerURL:        input.IssuerURL,
		AuthorizationURL: input.AuthorizationURL,
		TokenURL:         input.TokenURL,
		UserinfoURL:      input.UserinfoURL,
		Scopes:           pq.StringArray(input.Scopes),
		Active:           true,
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

func (s *Service) UpdateProvider(id uuid.UUID, input UpdateProviderInput) (*model.FederationProvider, error) {
	p, err := s.GetProvider(id)
	if err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		p.DisplayName = input.DisplayName
	}
	if input.ClientID != nil {
		p.ClientID = *input.ClientID
	}
	if input.ClientSecret != nil {
		p.ClientSecret = *input.ClientSecret
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
	if input.Scopes != nil {
		p.Scopes = pq.StringArray(input.Scopes)
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

	state, err := crypto.GenerateRandomString(16)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate state")
	}

	callbackURL := fmt.Sprintf("%s/api/v1/auth/federation/%s/callback", s.issuer, provider.Name)
	scopes := strings.Join(provider.Scopes, " ")

	params := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {callbackURL},
		"response_type": {"code"},
		"scope":         {scopes},
		"state":         {state},
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
