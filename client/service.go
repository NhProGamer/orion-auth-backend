package client

import (
	"log/slog"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Service struct {
	repo              RepositoryInterface
	hasher            *crypto.Argon2Hasher
	hmacEncryptionKey []byte
}

// NewService constructs the client service. hmacEncryptionKey is the
// server-side AES-256 key used to seal per-client HMAC secrets for
// client_secret_jwt. When nil, client_secret_jwt provisioning fails with a
// clear error and rotation skips HMAC regeneration.
func NewService(repo RepositoryInterface, hasher *crypto.Argon2Hasher, hmacEncryptionKey []byte) *Service {
	return &Service{repo: repo, hasher: hasher, hmacEncryptionKey: hmacEncryptionKey}
}

type CreateInput struct {
	Name            string   `json:"name" binding:"required"`
	Description     *string  `json:"description"`
	RedirectURIs    []string `json:"redirect_uris" binding:"required"`
	GrantTypes      []string `json:"grant_types" binding:"required"`
	ResponseTypes   []string `json:"response_types"`
	Scopes          []string `json:"scopes" binding:"required"`
	TokenAuthMethod *string  `json:"token_auth_method"`
	IsPublic        bool     `json:"is_public"`
	IsFirstParty    bool     `json:"is_first_party"`
	RequirePKCE     *bool    `json:"require_pkce"`
	AccessTokenTTL  *int     `json:"access_token_ttl"`
	RefreshTokenTTL *int     `json:"refresh_token_ttl"`
	IDTokenTTL      *int     `json:"id_token_ttl"`
}

type UpdateInput struct {
	Name            *string  `json:"name"`
	Description     *string  `json:"description"`
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	Scopes          []string `json:"scopes"`
	TokenAuthMethod *string  `json:"token_auth_method"`
	IsFirstParty    *bool    `json:"is_first_party"`
	RequirePKCE     *bool    `json:"require_pkce"`
	AccessTokenTTL  *int     `json:"access_token_ttl"`
	RefreshTokenTTL *int     `json:"refresh_token_ttl"`
	IDTokenTTL      *int     `json:"id_token_ttl"`
	Active          *bool    `json:"active"`
}

type CreateResponse struct {
	Client       *model.OAuthClient `json:"client"`
	ClientSecret string             `json:"client_secret,omitempty"`
	// HMACSecret is the base64 raw URL-encoded shared secret returned ONCE
	// when the client is provisioned with client_secret_jwt auth. The server
	// only stores it sealed (AES-GCM); it can never be retrieved again.
	HMACSecret string `json:"client_hmac_secret,omitempty"`
}

func (s *Service) Create(input CreateInput) (*CreateResponse, error) {
	authMethod := "client_secret_basic"
	if input.TokenAuthMethod != nil {
		authMethod = *input.TokenAuthMethod
	}
	if input.IsPublic {
		authMethod = "none"
	}

	responseTypes := input.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	client := &model.OAuthClient{
		Name:            input.Name,
		Description:     input.Description,
		RedirectURIs:    pq.StringArray(input.RedirectURIs),
		GrantTypes:      pq.StringArray(input.GrantTypes),
		ResponseTypes:   pq.StringArray(responseTypes),
		Scopes:          pq.StringArray(input.Scopes),
		TokenAuthMethod: authMethod,
		IsPublic:        input.IsPublic,
		IsFirstParty:    input.IsFirstParty,
		RequirePKCE:     true,
		Active:          true,
	}
	if input.RequirePKCE != nil {
		client.RequirePKCE = *input.RequirePKCE
	}

	if input.AccessTokenTTL != nil {
		client.AccessTokenTTL = *input.AccessTokenTTL
	}
	if input.RefreshTokenTTL != nil {
		client.RefreshTokenTTL = *input.RefreshTokenTTL
	}
	if input.IDTokenTTL != nil {
		client.IDTokenTTL = *input.IDTokenTTL
	}

	var rawSecret string
	if !input.IsPublic {
		secret, err := crypto.GenerateRandomString(32)
		if err != nil {
			return nil, pkg.ErrInternal("failed to generate client secret")
		}
		rawSecret = secret

		hash, err := s.hasher.Hash(secret)
		if err != nil {
			return nil, pkg.ErrInternal("failed to hash client secret")
		}
		client.SecretHash = &hash
	}

	var rawHMACSecret string
	if authMethod == "client_secret_jwt" {
		hmacB64, sealed, err := s.generateAndSealHMACSecret()
		if err != nil {
			return nil, err
		}
		client.SecretHMACKey = sealed
		rawHMACSecret = hmacB64
	}

	if err := s.repo.Create(client); err != nil {
		slog.Error("failed to create client", "error", err)
		return nil, pkg.ErrInternal("failed to create client")
	}

	slog.Info("oauth client created", "client_id", client.ID, "name", client.Name)
	return &CreateResponse{Client: client, ClientSecret: rawSecret, HMACSecret: rawHMACSecret}, nil
}

// generateAndSealHMACSecret returns the URL-safe base64 secret to hand back
// to the operator and the AES-GCM-sealed bytes to persist on the row. Errors
// when the server has no encryption key configured.
func (s *Service) generateAndSealHMACSecret() (b64 string, sealed []byte, err error) {
	if len(s.hmacEncryptionKey) == 0 {
		return "", nil, pkg.ErrBadRequest("client_secret_jwt is not enabled on this server (auth.hmac_secret_encryption_key is unset)")
	}
	raw, encoded, err := crypto.GenerateHMACSecret()
	if err != nil {
		return "", nil, pkg.ErrInternal("failed to generate hmac secret")
	}
	cipher, err := crypto.EncryptHMACSecret(raw, s.hmacEncryptionKey)
	if err != nil {
		return "", nil, pkg.ErrInternal("failed to seal hmac secret")
	}
	return encoded, cipher, nil
}

func (s *Service) GetByID(id uuid.UUID) (*model.OAuthClient, error) {
	client, err := s.repo.FindByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find client")
	}
	if client == nil {
		return nil, pkg.ErrNotFound("client not found")
	}
	return client, nil
}

func (s *Service) Update(id uuid.UUID, input UpdateInput) (*model.OAuthClient, error) {
	client, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		client.Name = *input.Name
	}
	if input.Description != nil {
		client.Description = input.Description
	}
	if input.RedirectURIs != nil {
		client.RedirectURIs = pq.StringArray(input.RedirectURIs)
	}
	if input.GrantTypes != nil {
		client.GrantTypes = pq.StringArray(input.GrantTypes)
	}
	if input.ResponseTypes != nil {
		client.ResponseTypes = pq.StringArray(input.ResponseTypes)
	}
	if input.Scopes != nil {
		client.Scopes = pq.StringArray(input.Scopes)
	}
	if input.TokenAuthMethod != nil {
		client.TokenAuthMethod = *input.TokenAuthMethod
	}
	if input.IsFirstParty != nil {
		client.IsFirstParty = *input.IsFirstParty
	}
	if input.RequirePKCE != nil {
		client.RequirePKCE = *input.RequirePKCE
	}
	if input.AccessTokenTTL != nil {
		client.AccessTokenTTL = *input.AccessTokenTTL
	}
	if input.RefreshTokenTTL != nil {
		client.RefreshTokenTTL = *input.RefreshTokenTTL
	}
	if input.IDTokenTTL != nil {
		client.IDTokenTTL = *input.IDTokenTTL
	}
	if input.Active != nil {
		client.Active = *input.Active
	}

	if err := s.repo.Update(client); err != nil {
		return nil, pkg.ErrInternal("failed to update client")
	}
	return client, nil
}

func (s *Service) List(page, perPage int) ([]model.OAuthClient, int64, error) {
	return s.repo.List(page, perPage)
}

func (s *Service) Delete(id uuid.UUID) error {
	_, err := s.GetByID(id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(id); err != nil {
		return pkg.ErrInternal("failed to delete client")
	}
	slog.Info("oauth client deleted", "client_id", id)
	return nil
}

func (s *Service) RotateSecret(id uuid.UUID) (string, error) {
	client, err := s.GetByID(id)
	if err != nil {
		return "", err
	}
	if client.IsPublic {
		return "", pkg.ErrBadRequest("cannot rotate secret for public client")
	}

	secret, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate client secret")
	}

	hash, err := s.hasher.Hash(secret)
	if err != nil {
		return "", pkg.ErrInternal("failed to hash client secret")
	}

	client.SecretHash = &hash
	if err := s.repo.Update(client); err != nil {
		return "", pkg.ErrInternal("failed to update client secret")
	}

	slog.Info("client secret rotated", "client_id", id)
	return secret, nil
}

// RotateHMACSecret regenerates the per-client HMAC key used for
// client_secret_jwt assertions. The previous key is dropped (any in-flight
// JWT assertion signed with it will fail). Returns the new secret in
// base64 URL-safe form; the caller must hand it to the operator exactly once.
func (s *Service) RotateHMACSecret(id uuid.UUID) (string, error) {
	client, err := s.GetByID(id)
	if err != nil {
		return "", err
	}
	if client.TokenAuthMethod != "client_secret_jwt" {
		return "", pkg.ErrBadRequest("client is not configured for client_secret_jwt")
	}
	b64, sealed, err := s.generateAndSealHMACSecret()
	if err != nil {
		return "", err
	}
	client.SecretHMACKey = sealed
	if err := s.repo.Update(client); err != nil {
		return "", pkg.ErrInternal("failed to update client hmac secret")
	}
	slog.Info("client hmac secret rotated", "client_id", id)
	return b64, nil
}
