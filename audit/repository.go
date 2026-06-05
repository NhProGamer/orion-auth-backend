package audit

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// Repository abstracts the audit log persistence layer so the service
// can be unit-tested with a fake. The concrete GORM implementation
// lives in gormRepository.
type Repository interface {
	Create(log *model.AuditLog) error
	Query(input QueryInput) ([]model.AuditLog, int64, error)
}

// QueryInput moves here (next to the interface that consumes it) so a
// future SQL/NoSQL repository implementation has access to the full
// filter contract without importing back into service.go.
type QueryInput struct {
	ID           *uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ActionPrefix string
	From         *time.Time
	To           *time.Time
	Page         int
	PerPage      int
}

type gormRepository struct {
	db *gorm.DB
}

// NewRepository returns the production GORM-backed Repository.
func NewRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

func (r *gormRepository) Create(log *model.AuditLog) error {
	return r.db.Create(log).Error
}

func (r *gormRepository) Query(input QueryInput) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	query := r.db.Model(&model.AuditLog{})

	if input.ID != nil {
		query = query.Where("id = ?", *input.ID)
	}
	if input.UserID != nil {
		query = query.Where("user_id = ?", *input.UserID)
	}
	if input.Action != "" {
		query = query.Where("action = ?", input.Action)
	}
	if input.ActionPrefix != "" {
		query = query.Where("action LIKE ?", input.ActionPrefix+"%")
	}
	if input.From != nil {
		query = query.Where("created_at >= ?", *input.From)
	}
	if input.To != nil {
		query = query.Where("created_at <= ?", *input.To)
	}

	query.Session(&gorm.Session{}).Count(&total)

	offset := (input.Page - 1) * input.PerPage
	err := query.Order("created_at DESC").Offset(offset).Limit(input.PerPage).Find(&logs).Error
	return logs, total, err
}
