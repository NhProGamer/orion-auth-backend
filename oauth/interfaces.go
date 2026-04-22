package oauth

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// RepositoryInterface defines the contract for OAuth data access.
type RepositoryInterface interface {
	// Client lookup
	findClient(clientIDStr string) (*model.OAuthClient, error)

	// Authorization requests
	CreateAuthRequest(req *model.AuthorizationRequest) error
	FindAuthRequest(id uuid.UUID) (*model.AuthorizationRequest, error)
	UpdateAuthRequest(req *model.AuthorizationRequest) error
	DeleteAuthRequest(id uuid.UUID) error

	// Authorization codes
	CreateAuthCode(code *model.AuthorizationCode) error
	FindAuthCode(codeHash string) (*model.AuthorizationCode, error)
	MarkAuthCodeUsed(codeHash string) error

	// Access tokens
	CreateAccessToken(token *model.AccessToken) error
	FindAccessToken(id string) (*model.AccessToken, error)
	RevokeAccessToken(id string) error
	RevokeAccessTokensByRefreshToken(refreshTokenID string) error
	RevokeAccessTokensBySession(sessionID uuid.UUID) error

	// Refresh tokens
	CreateRefreshToken(token *model.RefreshToken) error
	FindRefreshToken(id string) (*model.RefreshToken, error)
	RotateRefreshToken(id string) error
	RevokeRefreshTokenFamily(familyID uuid.UUID) error
	RevokeRefreshTokensBySession(sessionID uuid.UUID) error

	// Consents
	FindActiveConsent(userID, clientID uuid.UUID) (*model.Consent, error)
	CreateConsent(consent *model.Consent) error
	UpdateConsent(consent *model.Consent) error

	// Device codes
	CreateDeviceCode(dc *model.DeviceCode) error
	FindDeviceCode(codeHash string) (*model.DeviceCode, error)
	FindDeviceCodeByUserCode(userCode string) (*model.DeviceCode, error)
	UpdateDeviceCode(dc *model.DeviceCode) error

	// Transactions
	Transaction(fn func(tx RepositoryInterface) error) error
}
