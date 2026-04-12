package client

import (
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"OrionAuth/model"
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
	return r.db.Model(&model.OAuthClient{}).Where("id = ?", id).Update("active", false).Error
}
