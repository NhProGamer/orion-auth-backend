package model

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type FederationProvider struct {
	BaseModel
	Name                  string          `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	DisplayName           *string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	Type                  string          `gorm:"type:varchar(20);default:'oidc'" json:"type"`
	ClientID              string          `gorm:"type:varchar(255);not null" json:"client_id"`
	ClientSecret          *string         `gorm:"type:varchar(255)" json:"-"`
	ClientSecretEncrypted []byte          `gorm:"type:bytea" json:"-"`
	IssuerURL             *string         `gorm:"type:varchar(512)" json:"issuer_url,omitempty"`
	AuthorizationURL      *string         `gorm:"type:varchar(512)" json:"authorization_url,omitempty"`
	TokenURL              *string         `gorm:"type:varchar(512)" json:"token_url,omitempty"`
	UserinfoURL           *string         `gorm:"type:varchar(512)" json:"userinfo_url,omitempty"`
	JWKSUri               *string         `gorm:"column:jwks_uri;type:varchar(512)" json:"jwks_uri,omitempty"`
	Scopes                pq.StringArray  `gorm:"type:text[];default:'{}'" json:"scopes"`
	AttributeMapper       json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"attribute_mapper"`
	SyncOnLogin           bool            `gorm:"not null;default:false" json:"sync_on_login"`
	AllowLinkConfirmation bool            `gorm:"not null;default:false" json:"allow_link_confirmation"`
	Active                bool            `gorm:"default:true" json:"active"`
}

func (FederationProvider) TableName() string {
	return "federation_providers"
}

type FederationLink struct {
	BaseModel
	UserID     uuid.UUID       `gorm:"type:uuid;index;not null" json:"user_id"`
	ProviderID uuid.UUID       `gorm:"type:uuid;not null" json:"provider_id"`
	ExternalID string          `gorm:"type:varchar(255);not null" json:"external_id"`
	Email      *string         `gorm:"type:varchar(255)" json:"email,omitempty"`
	Metadata   json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
}

func (FederationLink) TableName() string {
	return "federation_links"
}
