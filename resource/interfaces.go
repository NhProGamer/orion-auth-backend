package resource

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
	// API Resources
	Create(r *model.APIResource) error
	FindByID(id uuid.UUID) (*model.APIResource, error)
	FindByIdentifier(identifier string) (*model.APIResource, error)
	FindActiveByIdentifier(identifier string) (*model.APIResource, error)
	Update(r *model.APIResource) error
	List(page, perPage int) ([]model.APIResource, int64, error)
	Delete(id uuid.UUID) error

	// Permissions
	CreatePermission(p *model.ResourcePermission) error
	FindPermissionByID(id uuid.UUID) (*model.ResourcePermission, error)
	FindPermissionsByResource(resourceID uuid.UUID) ([]model.ResourcePermission, error)
	FindPermissionsByNames(resourceID uuid.UUID, names []string) ([]model.ResourcePermission, error)
	DeletePermission(id uuid.UUID) error

	// Client-Resource Permissions
	SetClientPermissions(clientID uuid.UUID, permissionIDs []uuid.UUID) error
	GetClientPermissions(clientID uuid.UUID) ([]model.ResourcePermission, error)
	GetClientPermissionsForResource(clientID, resourceID uuid.UUID) ([]model.ResourcePermission, error)
	ValidateClientScopes(clientID, resourceID uuid.UUID, scopeNames []string) ([]string, error)

	// For OIDC discovery
	GetAllActiveScopes() ([]string, error)
}
