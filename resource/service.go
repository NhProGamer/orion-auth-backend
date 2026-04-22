package resource

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

type CreateInput struct {
	Name           string  `json:"name" binding:"required"`
	Identifier     string  `json:"identifier" binding:"required"`
	Description    *string `json:"description"`
	SigningAlg     *string `json:"signing_alg"`
	AccessTokenTTL *int    `json:"access_token_ttl"`
}

type UpdateInput struct {
	Name           *string `json:"name"`
	Description    *string `json:"description"`
	SigningAlg     *string `json:"signing_alg"`
	AccessTokenTTL *int    `json:"access_token_ttl"`
	Active         *bool   `json:"active"`
}

type AddPermissionInput struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

type SetClientPermissionsInput struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" binding:"required"`
}

// CRUD

func (s *Service) Create(input CreateInput) (*model.APIResource, error) {
	existing, err := s.repo.FindByIdentifier(input.Identifier)
	if err != nil {
		return nil, pkg.ErrInternal("failed to check identifier uniqueness")
	}
	if existing != nil {
		return nil, pkg.ErrConflict("a resource with this identifier already exists")
	}

	res := &model.APIResource{
		Name:       input.Name,
		Identifier: input.Identifier,
		Active:     true,
	}
	if input.Description != nil {
		res.Description = input.Description
	}
	if input.SigningAlg != nil {
		res.SigningAlg = *input.SigningAlg
	}
	if input.AccessTokenTTL != nil {
		res.AccessTokenTTL = *input.AccessTokenTTL
	}

	if err := s.repo.Create(res); err != nil {
		slog.Error("failed to create api resource", "error", err)
		return nil, pkg.ErrInternal("failed to create resource")
	}

	slog.Info("api resource created", "resource_id", res.ID, "identifier", res.Identifier)
	return res, nil
}

func (s *Service) GetByID(id uuid.UUID) (*model.APIResource, error) {
	res, err := s.repo.FindByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find resource")
	}
	if res == nil {
		return nil, pkg.ErrNotFound("resource not found")
	}
	return res, nil
}

func (s *Service) Update(id uuid.UUID, input UpdateInput) (*model.APIResource, error) {
	res, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		res.Name = *input.Name
	}
	if input.Description != nil {
		res.Description = input.Description
	}
	if input.SigningAlg != nil {
		res.SigningAlg = *input.SigningAlg
	}
	if input.AccessTokenTTL != nil {
		res.AccessTokenTTL = *input.AccessTokenTTL
	}
	if input.Active != nil {
		res.Active = *input.Active
	}

	if err := s.repo.Update(res); err != nil {
		return nil, pkg.ErrInternal("failed to update resource")
	}
	return res, nil
}

func (s *Service) List(page, perPage int) ([]model.APIResource, int64, error) {
	return s.repo.List(page, perPage)
}

func (s *Service) Delete(id uuid.UUID) error {
	_, err := s.GetByID(id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(id); err != nil {
		return pkg.ErrInternal("failed to delete resource")
	}
	slog.Info("api resource deleted", "resource_id", id)
	return nil
}

// Permissions

func (s *Service) AddPermission(resourceID uuid.UUID, input AddPermissionInput) (*model.ResourcePermission, error) {
	_, err := s.GetByID(resourceID)
	if err != nil {
		return nil, err
	}

	perm := &model.ResourcePermission{
		ResourceID:  resourceID,
		Name:        input.Name,
		Description: input.Description,
	}

	if err := s.repo.CreatePermission(perm); err != nil {
		slog.Error("failed to create permission", "error", err)
		return nil, pkg.ErrInternal("failed to create permission")
	}

	slog.Info("resource permission added", "resource_id", resourceID, "permission", input.Name)
	return perm, nil
}

func (s *Service) RemovePermission(resourceID, permissionID uuid.UUID) error {
	perm, err := s.repo.FindPermissionByID(permissionID)
	if err != nil {
		return pkg.ErrInternal("failed to find permission")
	}
	if perm == nil {
		return pkg.ErrNotFound("permission not found")
	}
	if perm.ResourceID != resourceID {
		return pkg.ErrNotFound("permission not found")
	}

	if err := s.repo.DeletePermission(permissionID); err != nil {
		return pkg.ErrInternal("failed to delete permission")
	}
	slog.Info("resource permission removed", "resource_id", resourceID, "permission_id", permissionID)
	return nil
}

func (s *Service) GetPermissions(resourceID uuid.UUID) ([]model.ResourcePermission, error) {
	_, err := s.GetByID(resourceID)
	if err != nil {
		return nil, err
	}
	return s.repo.FindPermissionsByResource(resourceID)
}

// Client permissions

func (s *Service) SetClientPermissions(clientID uuid.UUID, input SetClientPermissionsInput) error {
	if err := s.repo.SetClientPermissions(clientID, input.PermissionIDs); err != nil {
		slog.Error("failed to set client permissions", "error", err)
		return pkg.ErrInternal("failed to set client permissions")
	}
	slog.Info("client resource permissions updated", "client_id", clientID)
	return nil
}

func (s *Service) GetClientPermissions(clientID uuid.UUID) ([]model.ResourcePermission, error) {
	perms, err := s.repo.GetClientPermissions(clientID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to get client permissions")
	}
	return perms, nil
}

// Validation (used by OAuth)

func (s *Service) ValidateAudience(audience string) (*model.APIResource, error) {
	res, err := s.repo.FindActiveByIdentifier(audience)
	if err != nil {
		return nil, pkg.ErrInternal("failed to validate audience")
	}
	if res == nil {
		return nil, pkg.ErrNotFound("resource not found")
	}
	return res, nil
}

func (s *Service) ValidateClientScopes(clientID, resourceID uuid.UUID, scopes []string) ([]string, error) {
	return s.repo.ValidateClientScopes(clientID, resourceID, scopes)
}

// Discovery

func (s *Service) GetAllActiveScopes() ([]string, error) {
	return s.repo.GetAllActiveScopes()
}
