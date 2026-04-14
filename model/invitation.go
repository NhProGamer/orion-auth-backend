package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Invitation struct {
	BaseModel
	Email     string         `gorm:"type:varchar(255);not null" json:"email"`
	Token     string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"-"`
	RoleIDs   pq.StringArray `gorm:"type:uuid[];default:'{}'" json:"role_ids"`
	InvitedBy uuid.UUID      `gorm:"type:uuid;not null" json:"invited_by"`
	Used      bool           `gorm:"default:false" json:"used"`
	UsedAt    *time.Time     `json:"used_at,omitempty"`
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
}

func (Invitation) TableName() string {
	return "invitations"
}

func (i *Invitation) IsExpired() bool {
	return i.ExpiresAt.Before(time.Now())
}
