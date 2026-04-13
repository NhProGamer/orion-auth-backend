package mfa

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

func (r *Repository) Create(m *model.MFAMethod) error {
	return r.db.Create(m).Error
}

func (r *Repository) FindByUserAndType(userID uuid.UUID, mfaType string) (*model.MFAMethod, error) {
	var m model.MFAMethod
	err := r.db.Where("user_id = ? AND type = ?", userID, mfaType).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &m, err
}

func (r *Repository) FindVerifiedByUser(userID uuid.UUID) (*model.MFAMethod, error) {
	var m model.MFAMethod
	err := r.db.Where("user_id = ? AND verified = TRUE", userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &m, err
}

func (r *Repository) Update(m *model.MFAMethod) error {
	return r.db.Save(m).Error
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.MFAMethod{}, "id = ?", id).Error
}
