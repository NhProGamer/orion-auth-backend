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
	// LinkUserID is set when the auth request was initiated by an already-
	// authenticated user who wants to attach this federation identity to their
	// existing local account. The callback short-circuits on this value:
	// instead of provisioning or logging in, it creates a federation_link for
	// LinkUserID and redirects to ReturnTo.
	LinkUserID *uuid.UUID `gorm:"column:link_user_id;type:uuid" json:"link_user_id,omitempty"`
	IPAddress  *string    `gorm:"column:ip_address;type:inet" json:"ip_address,omitempty"`
	UserAgent  *string    `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt  time.Time  `gorm:"not null" json:"expires_at"`
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

// FederationPendingSignup stages an externally-authenticated identity that
// has no matching local account yet. The User and FederationLink rows are
// only materialised when the user POSTs to /complete-signup with a chosen
// local password. Abandoned rows expire and clean up via the standard
// cleanup ticker, leaving no orphan accounts behind.
type FederationPendingSignup struct {
	TokenHash       string          `gorm:"primaryKey;type:varchar(64)" json:"-"`
	ProviderID      uuid.UUID       `gorm:"type:uuid;not null" json:"provider_id"`
	ExternalID      string          `gorm:"type:varchar(255);not null" json:"external_id"`
	Email           string          `gorm:"type:varchar(255);not null" json:"email"`
	EmailVerified   bool            `gorm:"not null;default:false" json:"email_verified"`
	DisplayName     *string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	AvatarURL       *string         `gorm:"type:varchar(512)" json:"avatar_url,omitempty"`
	RawClaims       json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"raw_claims,omitempty"`
	OAuthRequestID  *uuid.UUID      `gorm:"column:oauth_request_id;type:uuid" json:"oauth_request_id,omitempty"`
	ReturnTo        *string         `gorm:"type:varchar(2048)" json:"return_to,omitempty"`
	InvitationToken *string         `gorm:"type:varchar(255)" json:"-"`
	IPAddress       *string         `gorm:"column:ip_address;type:inet" json:"ip_address,omitempty"`
	UserAgent       *string         `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	CreatedAt       time.Time       `gorm:"autoCreateTime" json:"created_at"`
	ExpiresAt       time.Time       `gorm:"not null" json:"expires_at"`
}

func (FederationPendingSignup) TableName() string { return "federation_pending_signups" }
