package client

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	Create(client *model.OAuthClient) error
	FindByID(id uuid.UUID) (*model.OAuthClient, error)
	FindActiveByID(id uuid.UUID) (*model.OAuthClient, error)
	Update(client *model.OAuthClient) error
	List(page, perPage int) ([]model.OAuthClient, int64, error)
	Delete(id uuid.UUID) error
}
