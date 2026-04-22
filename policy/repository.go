package policy

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

func (r *Repository) Create(policy *model.Policy) error {
	return r.db.Create(policy).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.Policy, error) {
	var p model.Policy
	err := r.db.Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) FindByName(name string) (*model.Policy, error) {
	var p model.Policy
	err := r.db.Where("name = ?", name).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) List() ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Order("type ASC, priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListByType(policyType string) ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("type = ?", policyType).Order("priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListActive(policyType string) ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("type = ? AND active = true", policyType).Order("priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListAllActive() ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("active = true").Order("type ASC, priority DESC").Find(&policies).Error
	return policies, err
}

func (r *Repository) Update(policy *model.Policy) error {
	return r.db.Save(policy).Error
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.Policy{}, "id = ?", id).Error
}
