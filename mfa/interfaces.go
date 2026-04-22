package mfa

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	Create(m *model.MFAMethod) error
	FindByUserAndType(userID uuid.UUID, mfaType string) (*model.MFAMethod, error)
	FindVerifiedByUser(userID uuid.UUID) (*model.MFAMethod, error)
	Update(m *model.MFAMethod) error
	Delete(id uuid.UUID) error
}
