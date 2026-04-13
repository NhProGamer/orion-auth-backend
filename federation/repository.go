package federation

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

// --- Providers ---

func (r *Repository) CreateProvider(p *model.FederationProvider) error {
	return r.db.Create(p).Error
}

func (r *Repository) FindProviderByID(id uuid.UUID) (*model.FederationProvider, error) {
	var p model.FederationProvider
	err := r.db.Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) FindProviderByName(name string) (*model.FederationProvider, error) {
	var p model.FederationProvider
	err := r.db.Where("name = ? AND active = TRUE", name).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) ListProviders() ([]model.FederationProvider, error) {
	var providers []model.FederationProvider
	err := r.db.Order("name ASC").Find(&providers).Error
	return providers, err
}

func (r *Repository) UpdateProvider(p *model.FederationProvider) error {
	return r.db.Save(p).Error
}

func (r *Repository) DeleteProvider(id uuid.UUID) error {
	return r.db.Delete(&model.FederationProvider{}, "id = ?", id).Error
}

// --- Links ---

func (r *Repository) CreateLink(l *model.FederationLink) error {
	return r.db.Create(l).Error
}

func (r *Repository) FindLink(providerID uuid.UUID, externalID string) (*model.FederationLink, error) {
	var l model.FederationLink
	err := r.db.Where("provider_id = ? AND external_id = ?", providerID, externalID).First(&l).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &l, err
}

func (r *Repository) FindLinksByUser(userID uuid.UUID) ([]model.FederationLink, error) {
	var links []model.FederationLink
	err := r.db.Where("user_id = ?", userID).Find(&links).Error
	return links, err
}

func (r *Repository) DeleteLink(id uuid.UUID) error {
	return r.db.Delete(&model.FederationLink{}, "id = ?", id).Error
}

func (r *Repository) FindLinkByID(id uuid.UUID) (*model.FederationLink, error) {
	var l model.FederationLink
	err := r.db.Where("id = ?", id).First(&l).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &l, err
}
