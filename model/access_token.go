package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type AccessToken struct {
	ID             string         `gorm:"type:varchar(64);primaryKey" json:"-"`
	ClientID       uuid.UUID      `gorm:"type:uuid;index;not null" json:"client_id"`
	UserID         *uuid.UUID     `gorm:"type:uuid;index" json:"user_id,omitempty"`
	SessionID      *uuid.UUID     `gorm:"type:uuid;index" json:"session_id,omitempty"`
	RefreshTokenID *string        `gorm:"type:varchar(64);index" json:"-"`
	Scopes         pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	Audience       *string        `gorm:"type:varchar(512)" json:"audience,omitempty"`
	// JTI is set only for JWT access tokens (RFC 9068). NULL means the
	// token is opaque and the primary key ID = sha256(raw).
	JTI       *string   `gorm:"type:varchar(255);index" json:"-"`
	ExpiresAt time.Time `gorm:"index;not null" json:"expires_at"`
	Revoked   bool      `gorm:"default:false" json:"revoked"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (AccessToken) TableName() string {
	return "access_tokens"
}

func (t *AccessToken) IsValid() bool {
	return !t.Revoked && t.ExpiresAt.After(time.Now())
}
