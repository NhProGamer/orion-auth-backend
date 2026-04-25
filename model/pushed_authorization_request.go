package model

import (
	"time"

	"github.com/google/uuid"
)

type PushedAuthorizationRequest struct {
	RequestURI string    `gorm:"type:varchar(128);primaryKey" json:"request_uri"`
	ClientID   uuid.UUID `gorm:"type:uuid;not null" json:"client_id"`
	Params     string    `gorm:"type:jsonb;not null" json:"-"`
	ExpiresAt  time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (PushedAuthorizationRequest) TableName() string {
	return "pushed_authorization_requests"
}

func (p *PushedAuthorizationRequest) IsExpired() bool {
	return p.ExpiresAt.Before(time.Now())
}
