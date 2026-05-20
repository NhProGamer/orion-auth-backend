package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// FederationAuthRequest is the one-shot record persisted between the
// authorize redirect and the provider callback. It carries the CSRF state,
// the PKCE verifier and the OIDC nonce, plus the continuation context.
type FederationAuthRequest struct {
	State           string     `gorm:"primaryKey;type:varchar(128)" json:"state"`
	ProviderID      uuid.UUID  `gorm:"type:uuid;not null" json:"provider_id"`
	CodeVerifier    string     `gorm:"type:varchar(128);not null" json:"-"`
	Nonce           string     `gorm:"type:varchar(128);not null" json:"-"`
	ReturnTo        *string    `gorm:"type:varchar(2048)" json:"return_to,omitempty"`
	OAuthRequestID  *uuid.UUID `gorm:"column:oauth_request_id;type:uuid" json:"oauth_request_id,omitempty"`
	InvitationToken *string    `gorm:"type:varchar(255)" json:"-"`
	IPAddress       *string    `gorm:"column:ip_address;type:inet" json:"ip_address,omitempty"`
	UserAgent       *string    `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	CreatedAt       time.Time  `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt       time.Time  `gorm:"not null" json:"expires_at"`
}

func (FederationAuthRequest) TableName() string { return "federation_auth_requests" }

// FederationPendingLink stages a social identity that matched an existing
// local account; the user must POST /confirm-link with the local password
// to finalize the link.
type FederationPendingLink struct {
	TokenHash       string          `gorm:"primaryKey;type:varchar(64)" json:"-"`
	UserID          uuid.UUID       `gorm:"type:uuid;not null" json:"user_id"`
	ProviderID      uuid.UUID       `gorm:"type:uuid;not null" json:"provider_id"`
	ExternalID      string          `gorm:"type:varchar(255);not null" json:"external_id"`
	Email           *string         `gorm:"type:varchar(255)" json:"email,omitempty"`
	RawClaims       json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"raw_claims,omitempty"`
	OAuthRequestID  *uuid.UUID      `gorm:"column:oauth_request_id;type:uuid" json:"oauth_request_id,omitempty"`
	ReturnTo        *string         `gorm:"type:varchar(2048)" json:"return_to,omitempty"`
	IPAddress       *string         `gorm:"column:ip_address;type:inet" json:"ip_address,omitempty"`
	UserAgent       *string         `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	CreatedAt       time.Time       `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt       time.Time       `gorm:"not null" json:"expires_at"`
}

func (FederationPendingLink) TableName() string { return "federation_pending_links" }
