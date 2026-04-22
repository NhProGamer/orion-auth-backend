package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type AuthorizationRequest struct {
	BaseModel
	ClientID            uuid.UUID      `gorm:"type:uuid;not null" json:"client_id"`
	RedirectURI         string         `gorm:"type:varchar(512);not null" json:"redirect_uri"`
	ResponseType        string         `gorm:"type:varchar(50);not null" json:"response_type"`
	Scopes              pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	State               *string        `gorm:"type:varchar(255)" json:"state,omitempty"`
	Nonce               *string        `gorm:"type:varchar(128)" json:"nonce,omitempty"`
	CodeChallenge       *string        `gorm:"type:varchar(128)" json:"-"`
	CodeChallengeMethod *string        `gorm:"type:varchar(10)" json:"-"`
	UserID              *uuid.UUID     `gorm:"type:uuid" json:"user_id,omitempty"`
	Authenticated       bool           `gorm:"default:false" json:"authenticated"`
	ConsentGiven        bool           `gorm:"default:false" json:"consent_given"`
	Audience            *string        `gorm:"type:varchar(512)" json:"audience,omitempty"`
	ExpiresAt           time.Time      `gorm:"not null" json:"expires_at"`
}

func (AuthorizationRequest) TableName() string {
	return "authorization_requests"
}

func (r *AuthorizationRequest) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

func (r *AuthorizationRequest) IsReady() bool {
	return r.Authenticated && r.ConsentGiven && !r.IsExpired()
}
