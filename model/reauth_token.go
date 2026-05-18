package model

import (
	"time"

	"github.com/google/uuid"
)

// ReauthToken backs the short-lived step-up reauthentication tokens issued by
// POST /api/v1/me/reauth. Each row's ID is the SHA-256 hash of the raw token
// returned to the client; raw tokens are never persisted.
type ReauthToken struct {
	ID         string     `gorm:"type:varchar(64);primaryKey" json:"-"`
	UserID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	SessionID  uuid.UUID  `gorm:"type:uuid;index;not null" json:"session_id"`
	Method     string     `gorm:"type:varchar(20);not null" json:"method"`
	ExpiresAt  time.Time  `gorm:"not null" json:"expires_at"`
	Used       bool       `gorm:"default:false" json:"used"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	ConsumedBy *string    `gorm:"type:varchar(100)" json:"consumed_by,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (ReauthToken) TableName() string {
	return "reauth_tokens"
}

func (t *ReauthToken) IsValid() bool {
	return !t.Used && t.ExpiresAt.After(time.Now())
}
