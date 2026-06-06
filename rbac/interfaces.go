package rbac

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// RepositoryInterface defines the RBAC persistence surface. WithTx is
// the entry point services use to bind subsequent writes (role
// assignments, permission updates) to an externally-managed transaction
// — letting the caller atomically create a user + assign roles + enqueue
// an email rather than risk a half-committed registration.
type RepositoryInterface interface {
	WithTx(tx *gorm.DB) RepositoryInterface
	CreateRole(role *model.Role) error
	FindRoleByID(id uuid.UUID) (*model.Role, error)
	FindRoleByName(name string) (*model.Role, error)
	ListRoles() ([]model.Role, error)
	UpdateRole(role *model.Role) error
	DeleteRole(id uuid.UUID) error
	ListPermissions() ([]model.Permission, error)
	FindPermissionsByIDs(ids []uuid.UUID) ([]model.Permission, error)
	SetRolePermissions(roleID uuid.UUID, permissionIDs []uuid.UUID) error
	GetUserRoles(userID uuid.UUID) ([]model.Role, error)
	AssignRole(userID, roleID uuid.UUID) error
	RemoveRole(userID, roleID uuid.UUID) error
	GetUserPermissions(userID uuid.UUID) ([]string, error)
}
