package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Session struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID          uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	IPAddress       *string    `gorm:"type:inet" json:"ip_address,omitempty"`
	UserAgent       *string    `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	DeviceInfo      *string    `gorm:"type:varchar(255)" json:"device_info,omitempty"`
	LastActiveAt    time.Time  `gorm:"default:now()" json:"last_active_at"`
	AuthenticatedAt time.Time  `gorm:"default:now()" json:"authenticated_at"`
	Revoked         bool       `gorm:"default:false" json:"revoked"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt       time.Time  `gorm:"index;not null" json:"expires_at"`
	CreatedAt       time.Time  `gorm:"autoCreateTime" json:"created_at"`

	// Extended records whether this session was opened with "remember me".
	// It governs the session TTL at creation and lets a silent SSO re-auth
	// inherit the persistent-cookie behaviour for the next session.
	Extended bool `gorm:"default:false" json:"-"`
	// CookieTokenHash is the SHA-256 of the opaque IdP session cookie. The
	// raw value lives only in the browser cookie; we store the hash so the
	// cookie is revocable and never recoverable from the database.
	CookieTokenHash string `gorm:"type:varchar(64);index" json:"-"`
	// CookieToken is the raw cookie value, populated only by Create at
	// issuance time and never persisted (gorm:"-"). Handlers read it to set
	// the cookie; it is empty on any session loaded from the database.
	CookieToken string `gorm:"-" json:"-"`
}

func (Session) TableName() string {
	return "sessions"
}

func (s *Session) BeforeCreate(_ *gorm.DB) error {
	if s.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		s.ID = id
	}
	return nil
}

func (s *Session) IsActive() bool {
	return !s.Revoked && s.ExpiresAt.After(time.Now())
}

func (s *Session) Revoke() {
	now := time.Now()
	s.Revoked = true
	s.RevokedAt = &now
}
