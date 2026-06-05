package audit

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

type Service struct {
	repo Repository
}

// NewService is the production constructor used by main.go. It wires
// the default GORM-backed repository so existing call sites continue
// to work unchanged.
func NewService(db *gorm.DB) *Service {
	return &Service{repo: NewRepository(db)}
}

// NewServiceWithRepository is the testing constructor: callers
// inject a fake Repository to exercise Log/Query without a DB.
func NewServiceWithRepository(repo Repository) *Service {
	return &Service{repo: repo}
}

type LogEntry struct {
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	Action    string
	IPAddress string
	UserAgent string
	Metadata  map[string]any
}

// Log records an audit event. Failures are logged but never propagated:
// an audit-write outage must not block a request.
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

	if err := s.repo.Create(&log); err != nil {
		slog.Error("failed to write audit log", "action", entry.Action, "error", err)
	}
}

func (s *Service) Query(input QueryInput) ([]model.AuditLog, int64, error) {
	return s.repo.Query(input)
}
