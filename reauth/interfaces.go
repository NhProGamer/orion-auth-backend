package reauth

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// RepositoryInterface defines storage operations on reauth_tokens.
type RepositoryInterface interface {
	Create(t *model.ReauthToken) error
	FindByHash(hash string) (*model.ReauthToken, error)
	MarkUsed(hash, consumedBy string) error
	DeleteExpired() (int64, error)
	DeleteForSession(sessionID uuid.UUID) error
}

// PasswordVerifier checks a user's current password. Implemented by user.Service.
type PasswordVerifier interface {
	VerifyPassword(userID uuid.UUID, password string) (bool, error)
}

// MFAValidator validates a TOTP code or a backup code. Implemented by mfa.Service.
type MFAValidator interface {
	ValidateCode(userID uuid.UUID, code string) (bool, error)
	HasMFA(userID uuid.UUID) (bool, error)
}

// PasskeyValidator validates a passkey assertion response and returns the
// matching user. The response payload is opaque JSON; the implementation pairs
// it with a challenge stored under the reauth challenge ID.
type PasskeyValidator interface {
	ValidateReauthAssertion(userID uuid.UUID, challengeID uuid.UUID, response []byte) (bool, error)
}
