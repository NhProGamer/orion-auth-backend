package session

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	Create(session *model.Session) error
	FindByID(id uuid.UUID) (*model.Session, error)
	FindActiveByUser(userID uuid.UUID) ([]model.Session, error)
	Revoke(id uuid.UUID) error
	RevokeAllForUser(userID uuid.UUID, exceptID *uuid.UUID) (int64, error)
	UpdateLastActive(id uuid.UUID) error
}
