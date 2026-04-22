package invitation

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	Create(inv *model.Invitation) error
	FindByToken(tokenHash string) (*model.Invitation, error)
	FindByID(id uuid.UUID) (*model.Invitation, error)
	List(page, perPage int) ([]model.Invitation, int64, error)
	MarkUsed(inv *model.Invitation) error
	Delete(id uuid.UUID) error
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
	GetAllSettings() ([]model.Setting, error)
}
