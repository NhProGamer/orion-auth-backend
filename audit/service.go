package audit

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

type LogEntry struct {
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	Action    string
	IPAddress string
	UserAgent string
	Metadata  map[string]any
}

// Log records an audit event.
func (s *Service) Log(entry LogEntry) {
	id, _ := uuid.NewV7()

	var metaJSON json.RawMessage
	if entry.Metadata != nil {
		metaJSON, _ = json.Marshal(entry.Metadata)
	} else {
		metaJSON = json.RawMessage("{}")
	}

	var ip *string
	if entry.IPAddress != "" {
		ip = &entry.IPAddress
	}
	var ua *string
	if entry.UserAgent != "" {
		ua = &entry.UserAgent
	}

	log := model.AuditLog{
		ID:        id,
		UserID:    entry.UserID,
		ClientID:  entry.ClientID,
		Action:    entry.Action,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metaJSON,
	}

	if err := s.db.Create(&log).Error; err != nil {
		slog.Error("failed to write audit log", "action", entry.Action, "error", err)
	}
}

type QueryInput struct {
	ID      *uuid.UUID
	UserID  *uuid.UUID
	Action  string
	From    *time.Time
	To      *time.Time
	Page    int
	PerPage int
}

func (s *Service) Query(input QueryInput) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	query := s.db.Model(&model.AuditLog{})

	if input.ID != nil {
		query = query.Where("id = ?", *input.ID)
	}
	if input.UserID != nil {
		query = query.Where("user_id = ?", *input.UserID)
	}
	if input.Action != "" {
		query = query.Where("action = ?", input.Action)
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
