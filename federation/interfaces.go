package federation

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	CreateProvider(p *model.FederationProvider) error
	FindProviderByID(id uuid.UUID) (*model.FederationProvider, error)
	FindProviderByName(name string) (*model.FederationProvider, error)
	ListProviders() ([]model.FederationProvider, error)
	UpdateProvider(p *model.FederationProvider) error
	DeleteProvider(id uuid.UUID) error
	CreateLink(l *model.FederationLink) error
	FindLink(providerID uuid.UUID, externalID string) (*model.FederationLink, error)
	FindLinksByUser(userID uuid.UUID) ([]model.FederationLink, error)
	DeleteLink(id uuid.UUID) error
	FindLinkByID(id uuid.UUID) (*model.FederationLink, error)
}
