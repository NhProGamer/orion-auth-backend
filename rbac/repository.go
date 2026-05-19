package rbac

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

// --- Roles ---

func (r *Repository) CreateRole(role *model.Role) error {
	return r.db.Create(role).Error
}

func (r *Repository) FindRoleByID(id uuid.UUID) (*model.Role, error) {
	var role model.Role
	err := r.db.Preload("Permissions").Where("id = ?", id).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &role, err
}

func (r *Repository) FindRoleByName(name string) (*model.Role, error) {
	var role model.Role
	err := r.db.Preload("Permissions").Where("name = ?", name).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &role, err
}

func (r *Repository) ListRoles() ([]model.Role, error) {
	var roles []model.Role
	err := r.db.Preload("Permissions").Order("name ASC").Find(&roles).Error
	return roles, err
}

func (r *Repository) UpdateRole(role *model.Role) error {
	// Omit Permissions so GORM doesn't try to round-trip the many2many
	// association (which would re-insert/replace rows in role_permissions
	// and can fail on seeded data with explicit IDs). Use SetRolePermissions
	// to mutate the join table.
	return r.db.Omit("Permissions").Save(role).Error
}

func (r *Repository) DeleteRole(id uuid.UUID) error {
	return r.db.Delete(&model.Role{}, "id = ?", id).Error
}

// --- Permissions ---

func (r *Repository) ListPermissions() ([]model.Permission, error) {
	var perms []model.Permission
	err := r.db.Order("name ASC").Find(&perms).Error
	return perms, err
}

func (r *Repository) FindPermissionsByIDs(ids []uuid.UUID) ([]model.Permission, error) {
	var perms []model.Permission
	err := r.db.Where("id IN ?", ids).Find(&perms).Error
	return perms, err
}

// --- Role Permissions ---

func (r *Repository) SetRolePermissions(roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Remove existing
		if err := tx.Where("role_id = ?", roleID).Delete(&model.RolePermission{}).Error; err != nil {
			return err
		}
		// Add new
		for _, pid := range permissionIDs {
			rp := model.RolePermission{RoleID: roleID.String(), PermissionID: pid.String()}
			if err := tx.Create(&rp).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// --- User Roles ---

func (r *Repository) GetUserRoles(userID uuid.UUID) ([]model.Role, error) {
	var roles []model.Role
	err := r.db.
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ?", userID).
		Preload("Permissions").
		Find(&roles).Error
	return roles, err
}

func (r *Repository) AssignRole(userID, roleID uuid.UUID) error {
	ur := model.UserRole{UserID: userID.String(), RoleID: roleID.String()}
	return r.db.Create(&ur).Error
}

func (r *Repository) RemoveRole(userID, roleID uuid.UUID) error {
	return r.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&model.UserRole{}).Error
}

func (r *Repository) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	var permissions []string
	err := r.db.Table("permissions").
		Select("DISTINCT permissions.name").
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Pluck("name", &permissions).Error
	return permissions, err
}
