package model

import (
	"time"

	"github.com/google/uuid"
)

// OutboundEmail is the persistent record backing the email outbox.
// Rows are inserted by the OutboxSender on every Send* call and
// drained by the outbox worker. We keep `sent` rows around for audit
// forensics (per the operator runbook); retention is enforced
// separately.
type OutboundEmail struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	Recipient    string     `gorm:"not null" json:"recipient"`
	Subject      string     `gorm:"not null" json:"subject"`
	BodyHTML     string     `gorm:"column:body_html;not null" json:"body_html"`
	Status       string     `gorm:"type:varchar(16);not null;default:'pending'" json:"status"`
	Attempts     int        `gorm:"not null;default:0" json:"attempts"`
	MaxAttempts  int        `gorm:"not null;default:5" json:"max_attempts"`
	NextRetryAt  time.Time  `gorm:"not null;default:now()" json:"next_retry_at"`
	LastError    *string    `json:"last_error,omitempty"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
}

func (OutboundEmail) TableName() string { return "outbound_emails" }

const (
	OutboundStatusPending = "pending"
	OutboundStatusSent    = "sent"
	OutboundStatusFailed  = "failed"
)
