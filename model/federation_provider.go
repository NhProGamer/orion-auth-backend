package model

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type FederationProvider struct {
	BaseModel
	Name             string         `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	DisplayName      *string        `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	Type             string         `gorm:"type:varchar(20);default:'oidc'" json:"type"`
	ClientID         string         `gorm:"type:varchar(255);not null" json:"client_id"`
	ClientSecret     string         `gorm:"type:varchar(255);not null" json:"-"`
	IssuerURL        *string        `gorm:"type:varchar(512)" json:"issuer_url,omitempty"`
	AuthorizationURL *string        `gorm:"type:varchar(512)" json:"authorization_url,omitempty"`
	TokenURL         *string        `gorm:"type:varchar(512)" json:"token_url,omitempty"`
	UserinfoURL      *string        `gorm:"type:varchar(512)" json:"userinfo_url,omitempty"`
	Scopes           pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	Active           bool           `gorm:"default:true" json:"active"`
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
