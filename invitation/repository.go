package invitation

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

func (r *Repository) Create(inv *model.Invitation) error {
	return r.db.Create(inv).Error
}

func (r *Repository) FindByToken(tokenHash string) (*model.Invitation, error) {
	var inv model.Invitation
	err := r.db.Where("token = ? AND used = FALSE AND expires_at > NOW()", tokenHash).First(&inv).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &inv, err
}

func (r *Repository) FindByID(id uuid.UUID) (*model.Invitation, error) {
	var inv model.Invitation
	err := r.db.Where("id = ?", id).First(&inv).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &inv, err
}

func (r *Repository) List(page, perPage int) ([]model.Invitation, int64, error) {
	var invitations []model.Invitation
	var total int64

	r.db.Model(&model.Invitation{}).Count(&total)

	offset := (page - 1) * perPage
	err := r.db.Offset(offset).Limit(perPage).Order("created_at DESC").Find(&invitations).Error
	return invitations, total, err
}

func (r *Repository) MarkUsed(inv *model.Invitation) error {
	return r.db.Save(inv).Error
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.Invitation{}, "id = ?", id).Error
}

// Settings

func (r *Repository) GetSetting(key string) (string, error) {
	var setting model.Setting
	err := r.db.Where("key = ?", key).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	return setting.Value, err
}

func (r *Repository) SetSetting(key, value string) error {
	return r.db.Save(&model.Setting{Key: key, Value: value}).Error
}

func (r *Repository) GetAllSettings() ([]model.Setting, error) {
	var settings []model.Setting
	err := r.db.Find(&settings).Error
	return settings, err
}
