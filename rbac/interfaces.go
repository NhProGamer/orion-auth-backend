package rbac

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type RepositoryInterface interface {
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
