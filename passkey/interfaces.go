package passkey

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	// Passkeys
	Create(p *model.Passkey) error
	FindByCredentialID(credentialID []byte) (*model.Passkey, error)
	FindByID(id uuid.UUID) (*model.Passkey, error)
	ListByUser(userID uuid.UUID) ([]model.Passkey, error)
	UpdateName(id uuid.UUID, userID uuid.UUID, name string) error
	UpdateSignCount(id uuid.UUID, signCount uint32, lastUsedAt int64) error
	SetCloneWarning(id uuid.UUID, value bool) error
	Delete(id uuid.UUID, userID uuid.UUID) error

	// Challenges
	CreateChallenge(c *model.PasskeyChallenge) error
	FindChallenge(id uuid.UUID) (*model.PasskeyChallenge, error)
	DeleteChallenge(id uuid.UUID) error
	DeleteExpiredChallenges() (int64, error)
}

// UserFinder is implemented by user.Service. Kept as an interface to avoid a
// package import cycle and to let tests provide a stub.
type UserFinder interface {
	GetByID(id uuid.UUID) (*model.User, error)
}
