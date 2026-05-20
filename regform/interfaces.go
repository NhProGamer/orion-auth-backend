package regform

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// RepositoryInterface defines the storage contract for registration
// fields. Kept narrow so the service can be unit-tested with an
// in-memory mock.
type RepositoryInterface interface {
	List() ([]model.RegistrationField, error)
	ListForContext(context string) ([]model.RegistrationField, error)
	FindByID(id uuid.UUID) (*model.RegistrationField, error)
	FindByKey(key string) (*model.RegistrationField, error)
	Create(f *model.RegistrationField) error
	Update(f *model.RegistrationField) error
	Delete(id uuid.UUID) error
	Reorder(orderedIDs []uuid.UUID) error
}
