package policy

import (
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	Create(policy *model.Policy) error
	FindByID(id uuid.UUID) (*model.Policy, error)
	FindByName(name string) (*model.Policy, error)
	List() ([]model.Policy, error)
	ListByType(policyType string) ([]model.Policy, error)
	ListActive(policyType string) ([]model.Policy, error)
	ListAllActive() ([]model.Policy, error)
	Update(policy *model.Policy) error
	Delete(id uuid.UUID) error
	Stats(from, to time.Time, limit int) (*Stats, error)
}
