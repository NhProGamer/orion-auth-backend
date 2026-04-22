package user

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// RepositoryInterface defines the contract for user data access.
type RepositoryInterface interface {
	Create(user *model.User) error
	FindByID(id uuid.UUID) (*model.User, error)
	FindByEmail(email string) (*model.User, error)
	Update(user *model.User) error
	UpdateFields(id uuid.UUID, fields map[string]any) error
	List(page, perPage int) ([]model.User, int64, error)
	Delete(id uuid.UUID) error
	FindByResetToken(tokenHash string) (*model.User, error)
	FindByVerifyToken(tokenHash string) (*model.User, error)
}
