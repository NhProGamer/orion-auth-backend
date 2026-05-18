package reauth

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

func (r *Repository) Create(t *model.ReauthToken) error {
	return r.db.Create(t).Error
}

func (r *Repository) FindByHash(hash string) (*model.ReauthToken, error) {
	var t model.ReauthToken
	err := r.db.Where("id = ?", hash).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &t, err
}

func (r *Repository) MarkUsed(hash, consumedBy string) error {
	now := time.Now()
	return r.db.Model(&model.ReauthToken{}).
		Where("id = ? AND used = FALSE", hash).
		Updates(map[string]any{
			"used":        true,
			"used_at":     now,
			"consumed_by": consumedBy,
		}).Error
}

func (r *Repository) DeleteExpired() (int64, error) {
	res := r.db.Where("expires_at < ?", time.Now()).Delete(&model.ReauthToken{})
	return res.RowsAffected, res.Error
}

func (r *Repository) DeleteForSession(sessionID uuid.UUID) error {
	return r.db.Where("session_id = ?", sessionID).Delete(&model.ReauthToken{}).Error
}
