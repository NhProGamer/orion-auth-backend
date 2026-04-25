package client

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

func (r *Repository) Create(client *model.OAuthClient) error {
	return r.db.Create(client).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.OAuthClient, error) {
	var client model.OAuthClient
	err := r.db.Where("id = ?", id).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &client, err
}

func (r *Repository) FindActiveByID(id uuid.UUID) (*model.OAuthClient, error) {
	var client model.OAuthClient
	err := r.db.Where("id = ? AND active = TRUE", id).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &client, err
}

func (r *Repository) Update(client *model.OAuthClient) error {
	return r.db.Save(client).Error
}

func (r *Repository) List(page, perPage int) ([]model.OAuthClient, int64, error) {
	var clients []model.OAuthClient
	var total int64

	r.db.Model(&model.OAuthClient{}).Count(&total)

	offset := (page - 1) * perPage
	err := r.db.Offset(offset).Limit(perPage).Order("created_at DESC").Find(&clients).Error
	return clients, total, err
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&model.OAuthClient{}).Error
}

func (r *Repository) FindClientsWithBackchannelLogout(userID uuid.UUID) ([]model.OAuthClient, error) {
	var clients []model.OAuthClient
	err := r.db.Where("backchannel_logout_uri IS NOT NULL AND active = TRUE AND id IN (?)",
		r.db.Table("consents").Select("client_id").Where("user_id = ? AND revoked_at IS NULL", userID),
	).Find(&clients).Error
	return clients, err
}

func (r *Repository) FindClientsWithFrontchannelLogout() ([]model.OAuthClient, error) {
	var clients []model.OAuthClient
	err := r.db.Where("frontchannel_logout_uri IS NOT NULL AND active = TRUE").Find(&clients).Error
	return clients, err
}
