package rbac

import (
	"log/slog"

	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Service struct {
	repo RepositoryInterface
}

func NewService(repo RepositoryInterface) *Service {
	return &Service{repo: repo}
}

// --- Roles ---

type CreateRoleInput struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

type UpdateRoleInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (s *Service) CreateRole(input CreateRoleInput) (*model.Role, error) {
	existing, _ := s.repo.FindRoleByName(input.Name)
	if existing != nil {
		return nil, pkg.ErrConflict("role name already exists")
	}

	role := &model.Role{
		Name:        input.Name,
		Description: input.Description,
	}
	if err := s.repo.CreateRole(role); err != nil {
		return nil, pkg.ErrInternal("failed to create role")
	}

	slog.Info("role created", "role_id", role.ID, "name", role.Name)
	return role, nil
}

func (s *Service) GetRole(id uuid.UUID) (*model.Role, error) {
	role, err := s.repo.FindRoleByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find role")
	}
	if role == nil {
		return nil, pkg.ErrNotFound("role not found")
	}
	return role, nil
}

func (s *Service) ListRoles() ([]model.Role, error) {
	return s.repo.ListRoles()
}

func (s *Service) UpdateRole(id uuid.UUID, input UpdateRoleInput) (*model.Role, error) {
	role, err := s.GetRole(id)
	if err != nil {
		return nil, err
	}
	if input.Name != nil {
		role.Name = *input.Name
	}
	if input.Description != nil {
		role.Description = input.Description
	}
	if err := s.repo.UpdateRole(role); err != nil {
		slog.Error("failed to update role", "role_id", id, "error", err)
		return nil, pkg.ErrInternal("failed to update role")
	}
	return role, nil
}

func (s *Service) DeleteRole(id uuid.UUID) error {
	if _, err := s.GetRole(id); err != nil {
		return err
	}
	if err := s.repo.DeleteRole(id); err != nil {
		return pkg.ErrInternal("failed to delete role")
	}
	slog.Info("role deleted", "role_id", id)
	return nil
}

// --- Permissions ---

func (s *Service) ListPermissions() ([]model.Permission, error) {
	return s.repo.ListPermissions()
}

type SetPermissionsInput struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" binding:"required"`
}

func (s *Service) SetRolePermissions(roleID uuid.UUID, permIDs []uuid.UUID) error {
	if _, err := s.GetRole(roleID); err != nil {
		return err
	}
	if err := s.repo.SetRolePermissions(roleID, permIDs); err != nil {
		slog.Error("failed to set role permissions", "role_id", roleID, "error", err)
		return pkg.ErrInternal("failed to set permissions")
	}
	slog.Info("role permissions updated", "role_id", roleID)
	return nil
}

// --- User Roles ---

type AssignRoleInput struct {
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

func (s *Service) AssignRole(userID, roleID uuid.UUID) error {
	if _, err := s.GetRole(roleID); err != nil {
		return err
	}
	if err := s.repo.AssignRole(userID, roleID); err != nil {
		return pkg.ErrInternal("failed to assign role")
	}
	slog.Info("role assigned", "user_id", userID, "role_id", roleID)
	return nil
}

func (s *Service) RemoveRole(userID, roleID uuid.UUID) error {
	if err := s.repo.RemoveRole(userID, roleID); err != nil {
		return pkg.ErrInternal("failed to remove role")
	}
	slog.Info("role removed", "user_id", userID, "role_id", roleID)
	return nil
}

func (s *Service) GetUserRoles(userID uuid.UUID) ([]model.Role, error) {
	return s.repo.GetUserRoles(userID)
}

// GetUserPermissions returns all permission names for a user.
func (s *Service) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	return s.repo.GetUserPermissions(userID)
}

// HasPermission checks if a user has a specific permission.
func (s *Service) HasPermission(userID uuid.UUID, permission string) (bool, error) {
	perms, err := s.repo.GetUserPermissions(userID)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}
