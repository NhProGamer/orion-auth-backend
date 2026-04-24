package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Consent struct {
	BaseModel
	UserID     uuid.UUID      `gorm:"type:uuid;index;not null" json:"user_id"`
	ClientID   uuid.UUID      `gorm:"type:uuid;not null" json:"client_id"`
	ResourceID *uuid.UUID     `gorm:"type:uuid" json:"resource_id,omitempty"`
	Scopes     pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	GrantedAt  time.Time      `gorm:"default:now()" json:"granted_at"`
	RevokedAt  *time.Time     `json:"revoked_at,omitempty"`
}

func (Consent) TableName() string {
	return "consents"
}

func (c *Consent) IsActive() bool {
	return c.RevokedAt == nil
}

// CoversScopes checks if the consented scopes cover all requested scopes.
func (c *Consent) CoversScopes(requested []string) bool {
	scopeSet := make(map[string]bool, len(c.Scopes))
	for _, s := range c.Scopes {
		scopeSet[s] = true
	}
	for _, r := range requested {
		if !scopeSet[r] {
			return false
		}
	}
	return true
}
