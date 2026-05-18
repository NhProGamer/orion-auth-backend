package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Passkey is a WebAuthn credential bound to a user. The credential ID is the
// authenticator-issued ID (unique across users); PublicKey is CBOR-encoded.
// Flags stores the raw uint8 ProtocolValue so we survive future spec changes,
// per the go-webauthn recommendation.
type Passkey struct {
	BaseModel
	UserID          uuid.UUID      `gorm:"type:uuid;index;not null" json:"user_id"`
	CredentialID    []byte         `gorm:"type:bytea;uniqueIndex;not null" json:"-"`
	PublicKey       []byte         `gorm:"type:bytea;not null" json:"-"`
	AttestationType string         `gorm:"type:varchar(50);default:''" json:"attestation_type"`
	AAGUID          []byte         `gorm:"type:bytea" json:"-"`
	SignCount       uint32         `gorm:"default:0" json:"sign_count"`
	Transports      pq.StringArray `gorm:"type:text[];default:'{}'" json:"transports"`
	Flags           uint8          `gorm:"default:0" json:"flags"`
	CloneWarning    bool           `gorm:"default:false" json:"clone_warning"`
	Name            string         `gorm:"type:varchar(100);default:'Passkey'" json:"name"`
	LastUsedAt      *time.Time     `json:"last_used_at,omitempty"`
}

func (Passkey) TableName() string {
	return "passkeys"
}

// PublicView returns a user-safe representation (no credential material).
func (p *Passkey) PublicView() map[string]any {
	return map[string]any{
		"id":           p.ID,
		"name":         p.Name,
		"transports":   []string(p.Transports),
		"created_at":   p.CreatedAt,
		"last_used_at": p.LastUsedAt,
	}
}
