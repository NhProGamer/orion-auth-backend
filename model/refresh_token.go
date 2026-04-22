package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type RefreshToken struct {
	ID        string         `gorm:"type:varchar(64);primaryKey" json:"-"`
	ClientID  uuid.UUID      `gorm:"type:uuid;index;not null" json:"client_id"`
	UserID    uuid.UUID      `gorm:"type:uuid;index;not null" json:"user_id"`
	SessionID uuid.UUID      `gorm:"type:uuid;index;not null" json:"session_id"`
	Scopes    pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	Audience  *string        `gorm:"type:varchar(512)" json:"audience,omitempty"`
	FamilyID  uuid.UUID      `gorm:"type:uuid;index;not null" json:"-"`
	ParentID  *string        `gorm:"type:varchar(64)" json:"-"`
	ExpiresAt time.Time      `gorm:"index;not null" json:"expires_at"`
	Revoked   bool           `gorm:"default:false" json:"-"`
	RotatedAt *time.Time     `json:"-"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (t *RefreshToken) IsValid() bool {
	return !t.Revoked && t.RotatedAt == nil && t.ExpiresAt.After(time.Now())
}

func (t *RefreshToken) WasRotated() bool {
	return t.RotatedAt != nil
}
