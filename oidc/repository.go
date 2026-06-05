package oidc

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// SigningKeyRepository is the persistence surface for OIDC RSA
// signing keys. Extracted so the Service no longer holds a raw
// *gorm.DB — the same pattern as audit/, user/, etc.
type SigningKeyRepository interface {
	FindActive() (*model.SigningKey, error)
	FindAllValid(now time.Time) ([]model.SigningKey, error)
	DeactivateActive(grace time.Time) error
	Create(key *model.SigningKey) error
}

type gormSigningKeyRepository struct {
	db *gorm.DB
}

func NewSigningKeyRepository(db *gorm.DB) SigningKeyRepository {
	return &gormSigningKeyRepository{db: db}
}

func (r *gormSigningKeyRepository) FindActive() (*model.SigningKey, error) {
	var key model.SigningKey
	err := r.db.Where("active = TRUE").Order("created_at DESC").First(&key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *gormSigningKeyRepository) FindAllValid(now time.Time) ([]model.SigningKey, error) {
	var keys []model.SigningKey
	err := r.db.
		Where("active = TRUE OR (expires_at IS NOT NULL AND expires_at > ?)", now).
		Order("created_at DESC").
		Find(&keys).Error
	return keys, err
}

func (r *gormSigningKeyRepository) DeactivateActive(grace time.Time) error {
	return r.db.Model(&model.SigningKey{}).Where("active = TRUE").Updates(map[string]any{
		"active":     false,
		"expires_at": grace,
	}).Error
}

func (r *gormSigningKeyRepository) Create(key *model.SigningKey) error {
	return r.db.Create(key).Error
}
