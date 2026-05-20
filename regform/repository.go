package regform

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

func (r *Repository) List() ([]model.RegistrationField, error) {
	var fields []model.RegistrationField
	err := r.db.Order("display_order ASC, created_at ASC").Find(&fields).Error
	return fields, err
}

// ListForContext returns enabled fields whose applies_to includes the
// requested context (register or federation), ordered for direct
// rendering by the AuthUI.
func (r *Repository) ListForContext(context string) ([]model.RegistrationField, error) {
	var fields []model.RegistrationField
	err := r.db.
		Where("enabled = TRUE AND ? = ANY (applies_to)", context).
		Order("display_order ASC, created_at ASC").
		Find(&fields).Error
	return fields, err
}

func (r *Repository) FindByID(id uuid.UUID) (*model.RegistrationField, error) {
	var f model.RegistrationField
	if err := r.db.Where("id = ?", id).First(&f).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}

func (r *Repository) FindByKey(key string) (*model.RegistrationField, error) {
	var f model.RegistrationField
	if err := r.db.Where("field_key = ?", key).First(&f).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}

func (r *Repository) Create(f *model.RegistrationField) error {
	return r.db.Create(f).Error
}

func (r *Repository) Update(f *model.RegistrationField) error {
	return r.db.Save(f).Error
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.RegistrationField{}, "id = ?", id).Error
}

// Reorder updates display_order for every row in a single transaction
// so the persisted order matches the slice. Rows whose IDs are not
// present in the input keep their existing display_order.
func (r *Repository) Reorder(orderedIDs []uuid.UUID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for idx, id := range orderedIDs {
			if err := tx.Model(&model.RegistrationField{}).
				Where("id = ?", id).
				Update("display_order", idx).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
