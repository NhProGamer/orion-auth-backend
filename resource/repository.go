package resource

import (
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// API Resources

func (r *Repository) Create(res *model.APIResource) error {
	return r.db.Create(res).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.APIResource, error) {
	var res model.APIResource
	err := r.db.Preload("Permissions").Where("id = ?", id).First(&res).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &res, err
}

func (r *Repository) FindByIdentifier(identifier string) (*model.APIResource, error) {
	var res model.APIResource
	err := r.db.Where("identifier = ?", identifier).First(&res).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &res, err
}

func (r *Repository) FindActiveByIdentifier(identifier string) (*model.APIResource, error) {
	var res model.APIResource
	err := r.db.Preload("Permissions").Where("identifier = ? AND active = TRUE", identifier).First(&res).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &res, err
}

func (r *Repository) Update(res *model.APIResource) error {
	return r.db.Save(res).Error
}

func (r *Repository) List(page, perPage int) ([]model.APIResource, int64, error) {
	var resources []model.APIResource
	var total int64

	r.db.Model(&model.APIResource{}).Count(&total)

	offset := (page - 1) * perPage
	err := r.db.Offset(offset).Limit(perPage).Order("created_at DESC").Find(&resources).Error
	return resources, total, err
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&model.APIResource{}).Error
}

// Permissions

func (r *Repository) CreatePermission(p *model.ResourcePermission) error {
	return r.db.Create(p).Error
}

func (r *Repository) FindPermissionByID(id uuid.UUID) (*model.ResourcePermission, error) {
	var perm model.ResourcePermission
	err := r.db.Where("id = ?", id).First(&perm).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &perm, err
}

func (r *Repository) FindPermissionsByResource(resourceID uuid.UUID) ([]model.ResourcePermission, error) {
	var perms []model.ResourcePermission
	err := r.db.Where("resource_id = ?", resourceID).Order("created_at ASC").Find(&perms).Error
	return perms, err
}

func (r *Repository) FindPermissionsByNames(resourceID uuid.UUID, names []string) ([]model.ResourcePermission, error) {
	var perms []model.ResourcePermission
	err := r.db.Where("resource_id = ? AND name IN (?)", resourceID, names).Find(&perms).Error
	return perms, err
}

func (r *Repository) DeletePermission(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&model.ResourcePermission{}).Error
}

// Client-Resource Permissions

func (r *Repository) SetClientPermissions(clientID uuid.UUID, permissionIDs []uuid.UUID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", clientID).Delete(&model.ClientResourcePermission{}).Error; err != nil {
			return err
		}

		for _, pid := range permissionIDs {
			crp := model.ClientResourcePermission{
				ClientID:     clientID,
				PermissionID: pid,
			}
			if err := tx.Create(&crp).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repository) GetClientPermissions(clientID uuid.UUID) ([]model.ResourcePermission, error) {
	var perms []model.ResourcePermission
	err := r.db.
		Joins("JOIN client_resource_permissions ON client_resource_permissions.permission_id = resource_permissions.id").
		Where("client_resource_permissions.client_id = ?", clientID).
		Find(&perms).Error
	return perms, err
}

func (r *Repository) GetClientPermissionsForResource(clientID, resourceID uuid.UUID) ([]model.ResourcePermission, error) {
	var perms []model.ResourcePermission
	err := r.db.
		Joins("JOIN client_resource_permissions ON client_resource_permissions.permission_id = resource_permissions.id").
		Where("client_resource_permissions.client_id = ? AND resource_permissions.resource_id = ?", clientID, resourceID).
		Find(&perms).Error
	return perms, err
}

func (r *Repository) ValidateClientScopes(clientID, resourceID uuid.UUID, scopeNames []string) ([]string, error) {
	var names []string
	err := r.db.
		Model(&model.ResourcePermission{}).
		Joins("JOIN client_resource_permissions ON client_resource_permissions.permission_id = resource_permissions.id").
		Where("client_resource_permissions.client_id = ? AND resource_permissions.resource_id = ? AND resource_permissions.name IN (?)", clientID, resourceID, scopeNames).
		Pluck("resource_permissions.name", &names).Error
	return names, err
}

// OIDC Discovery

func (r *Repository) GetAllActiveScopes() ([]string, error) {
	var names []string
	err := r.db.
		Model(&model.ResourcePermission{}).
		Joins("JOIN api_resources ON api_resources.id = resource_permissions.resource_id").
		Where("api_resources.active = TRUE").
		Pluck("resource_permissions.name", &names).Error
	return names, err
}
