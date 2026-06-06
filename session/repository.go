package session

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

// WithTx returns a Repository bound to tx so account.Service can revoke
// sessions inside the same transaction that updates the user row.
func (r *Repository) WithTx(tx *gorm.DB) RepositoryInterface {
	return &Repository{db: tx}
}

func (r *Repository) Create(session *model.Session) error {
	return r.db.Create(session).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.Session, error) {
	var session model.Session
	err := r.db.Where("id = ?", id).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &session, err
}

func (r *Repository) FindActiveByUser(userID uuid.UUID) ([]model.Session, error) {
	var sessions []model.Session
	err := r.db.
		Where("user_id = ? AND revoked = FALSE AND expires_at > ?", userID, time.Now()).
		Order("last_active_at DESC").
		Find(&sessions).Error
	return sessions, err
}

func (r *Repository) Revoke(id uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.Session{}).
		Where("id = ?", id).
		Updates(map[string]any{"revoked": true, "revoked_at": now}).Error
}

func (r *Repository) RevokeAllForUser(userID uuid.UUID, exceptID *uuid.UUID) (int64, error) {
	now := time.Now()
	query := r.db.Model(&model.Session{}).
		Where("user_id = ? AND revoked = FALSE", userID)

	if exceptID != nil {
		query = query.Where("id != ?", *exceptID)
	}

	result := query.Updates(map[string]any{"revoked": true, "revoked_at": now})
	return result.RowsAffected, result.Error
}

func (r *Repository) UpdateLastActive(id uuid.UUID) error {
	return r.db.Model(&model.Session{}).
		Where("id = ?", id).
		Update("last_active_at", time.Now()).Error
}
