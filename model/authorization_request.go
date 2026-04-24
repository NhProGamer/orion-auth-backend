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
	Prompt              *string        `gorm:"type:varchar(50)" json:"-"`
	MaxAge              *int           `gorm:"type:int" json:"-"`
	Display             *string        `gorm:"type:varchar(20)" json:"-"`
	UILocales           *string        `gorm:"type:varchar(255)" json:"-"`
	ClaimsLocales       *string        `gorm:"type:varchar(255)" json:"-"`
	ACRValues           *string        `gorm:"type:varchar(512)" json:"-"`
	LoginHint           *string        `gorm:"type:varchar(255)" json:"-"`
	ClaimsParam         *string        `gorm:"type:jsonb;column:claims_param" json:"-"`
	IDTokenHint         *string        `gorm:"type:text" json:"-"`
	AuthTime            *time.Time     `gorm:"type:timestamptz" json:"-"`
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
