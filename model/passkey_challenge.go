package model

import (
	"time"

	"github.com/google/uuid"
)

// PasskeyChallenge stores webauthn.SessionData between begin/finish calls.
// UserID is nullable to support usernameless login flows.
type PasskeyChallenge struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`
	Purpose     string     `gorm:"type:varchar(20);not null" json:"purpose"`
	SessionData []byte     `gorm:"type:bytea;not null" json:"-"`
	ExpiresAt   time.Time  `gorm:"index;not null" json:"expires_at"`
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (PasskeyChallenge) TableName() string {
	return "passkey_challenges"
}

func (c *PasskeyChallenge) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}
