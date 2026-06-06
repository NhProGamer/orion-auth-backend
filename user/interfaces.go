package user

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// RepositoryInterface defines the contract for user data access.
//
// WithTx returns a repository view bound to the supplied Tx so the
// service can run user-table writes inside the same transaction as
// role assignments and outbox enqueues. Implementations must NOT
// modify the receiver — they return a new value pointing at tx.
type RepositoryInterface interface {
	WithTx(tx *gorm.DB) RepositoryInterface
	Create(user *model.User) error
	FindByID(id uuid.UUID) (*model.User, error)
	FindByEmail(email string) (*model.User, error)
	Update(user *model.User) error
	UpdateFields(id uuid.UUID, fields map[string]any) error
	List(page, perPage int) ([]model.User, int64, error)
	Search(q string, page, perPage int) ([]model.User, int64, error)
	Delete(id uuid.UUID) error
	FindByResetToken(tokenHash string) (*model.User, error)
	FindByVerifyToken(tokenHash string) (*model.User, error)
	FindByEmailChangeToken(tokenHash string) (*model.User, error)
	FindByDeletionToken(tokenHash string) (*model.User, error)
}
