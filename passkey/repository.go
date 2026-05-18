package passkey

import (
	"errors"
	"time"

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

func (r *Repository) Create(p *model.Passkey) error {
	return r.db.Create(p).Error
}

func (r *Repository) FindByCredentialID(credentialID []byte) (*model.Passkey, error) {
	var p model.Passkey
	err := r.db.Where("credential_id = ?", credentialID).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) FindByID(id uuid.UUID) (*model.Passkey, error) {
	var p model.Passkey
	err := r.db.Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) ListByUser(userID uuid.UUID) ([]model.Passkey, error) {
	var ps []model.Passkey
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&ps).Error
	return ps, err
}

func (r *Repository) UpdateName(id, userID uuid.UUID, name string) error {
	res := r.db.Model(&model.Passkey{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("name", name)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *Repository) UpdateSignCount(id uuid.UUID, signCount uint32, lastUsedUnix int64) error {
	last := time.Unix(lastUsedUnix, 0)
	return r.db.Model(&model.Passkey{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"sign_count":   signCount,
			"last_used_at": last,
		}).Error
}

func (r *Repository) Delete(id, userID uuid.UUID) error {
	res := r.db.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Passkey{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Challenges

func (r *Repository) CreateChallenge(c *model.PasskeyChallenge) error {
	return r.db.Create(c).Error
}

func (r *Repository) FindChallenge(id uuid.UUID) (*model.PasskeyChallenge, error) {
	var c model.PasskeyChallenge
	err := r.db.Where("id = ?", id).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func (r *Repository) DeleteChallenge(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&model.PasskeyChallenge{}).Error
}

func (r *Repository) DeleteExpiredChallenges() (int64, error) {
	res := r.db.Where("expires_at < ?", time.Now()).Delete(&model.PasskeyChallenge{})
	return res.RowsAffected, res.Error
}
