package model

import (
	"time"

	"github.com/google/uuid"
)

type SigningKey struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	PrivateKeyPEM string     `gorm:"type:text;not null" json:"-"`
	PublicKeyPEM  string     `gorm:"type:text;not null" json:"-"`
	Algorithm     string     `gorm:"type:varchar(10);default:'RS256'" json:"algorithm"`
	Active        bool       `gorm:"default:true" json:"active"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (SigningKey) TableName() string {
	return "signing_keys"
}
