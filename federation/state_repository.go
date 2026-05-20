package federation

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// StateRepositoryInterface exposes the persistence operations needed for
// the federation auth-request and pending-link state stores.
type StateRepositoryInterface interface {
	InsertAuthRequest(req *model.FederationAuthRequest) error
	ConsumeAuthRequest(state string) (*model.FederationAuthRequest, error)
	DeleteExpiredAuthRequests() (int64, error)

	InsertPendingLink(p *model.FederationPendingLink) error
	ConsumePendingLink(tokenHash string) (*model.FederationPendingLink, error)
	DeleteExpiredPendingLinks() (int64, error)
}

type StateRepository struct {
	db *gorm.DB
}

func NewStateRepository(db *gorm.DB) *StateRepository {
	return &StateRepository{db: db}
}

// InsertAuthRequest persists a brand-new authorize state. The caller is
// responsible for setting ExpiresAt.
func (r *StateRepository) InsertAuthRequest(req *model.FederationAuthRequest) error {
	return r.db.Create(req).Error
}

// ConsumeAuthRequest looks up an auth request by state and atomically
// deletes it (delete-on-read). Returns nil if no row, expired, or already
// consumed.
func (r *StateRepository) ConsumeAuthRequest(state string) (*model.FederationAuthRequest, error) {
	var req model.FederationAuthRequest
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("state = ?", state).First(&req).Error; err != nil {
			return err
		}
		return tx.Delete(&model.FederationAuthRequest{}, "state = ?", state).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(req.ExpiresAt) {
		return nil, nil
	}
	return &req, nil
}

func (r *StateRepository) DeleteExpiredAuthRequests() (int64, error) {
	res := r.db.Where("expires_at < ?", time.Now()).Delete(&model.FederationAuthRequest{})
	return res.RowsAffected, res.Error
}

func (r *StateRepository) InsertPendingLink(p *model.FederationPendingLink) error {
	return r.db.Create(p).Error
}

func (r *StateRepository) ConsumePendingLink(tokenHash string) (*model.FederationPendingLink, error) {
	var p model.FederationPendingLink
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("token_hash = ?", tokenHash).First(&p).Error; err != nil {
			return err
		}
		return tx.Delete(&model.FederationPendingLink{}, "token_hash = ?", tokenHash).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(p.ExpiresAt) {
		return nil, nil
	}
	return &p, nil
}

func (r *StateRepository) DeleteExpiredPendingLinks() (int64, error) {
	res := r.db.Where("expires_at < ?", time.Now()).Delete(&model.FederationPendingLink{})
	return res.RowsAffected, res.Error
}
