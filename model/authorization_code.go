package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type AuthorizationCode struct {
	CodeHash            string         `gorm:"type:varchar(64);primaryKey" json:"-"`
	ClientID            uuid.UUID      `gorm:"type:uuid;index;not null" json:"client_id"`
	UserID              uuid.UUID      `gorm:"type:uuid;not null" json:"user_id"`
	RedirectURI         string         `gorm:"type:varchar(512);not null" json:"redirect_uri"`
	Scopes              pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	CodeChallenge       *string        `gorm:"type:varchar(128)" json:"-"`
	CodeChallengeMethod *string        `gorm:"type:varchar(10)" json:"-"`
	Nonce               *string        `gorm:"type:varchar(128)" json:"-"`
	SessionID           *uuid.UUID     `gorm:"type:uuid" json:"-"`
	ExpiresAt           time.Time      `gorm:"index;not null" json:"expires_at"`
	Used                bool           `gorm:"default:false" json:"-"`
	CreatedAt           time.Time      `gorm:"autoCreateTime" json:"created_at"`
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

func (c *AuthorizationCode) IsValid() bool {
	return !c.Used && c.ExpiresAt.After(time.Now())
}

func (c *AuthorizationCode) HasPKCE() bool {
	return c.CodeChallenge != nil && *c.CodeChallenge != ""
}
