package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type User struct {
	BaseModel
	Email                  string          `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	EmailVerified          bool            `gorm:"default:false" json:"email_verified"`
	EmailVerifyToken       *string         `gorm:"type:varchar(255)" json:"-"`
	EmailVerifyExpiresAt   *time.Time      `json:"-"`
	PasswordHash           string          `gorm:"type:varchar(255);not null" json:"-"`
	PasswordResetToken     *string         `gorm:"type:varchar(255)" json:"-"`
	PasswordResetExpiresAt *time.Time      `json:"-"`
	DisplayName            *string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	AvatarURL              *string         `gorm:"type:varchar(512)" json:"avatar_url,omitempty"`
	Phone                  *string         `gorm:"type:varchar(50)" json:"phone,omitempty"`
	LockedUntil            *time.Time      `json:"locked_until,omitempty"`
	FailedLoginAttempts    int             `gorm:"default:0" json:"-"`
	Active                 bool            `gorm:"default:true" json:"active"`
	Metadata               json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
}

func (User) TableName() string {
	return "users"
}

func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

func (u *User) PublicProfile() map[string]any {
	profile := map[string]any{
		"id":             u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"active":         u.Active,
		"created_at":     u.CreatedAt,
		"updated_at":     u.UpdatedAt,
	}
	if u.DisplayName != nil {
		profile["display_name"] = *u.DisplayName
	}
	if u.AvatarURL != nil {
		profile["avatar_url"] = *u.AvatarURL
	}
	if u.Phone != nil {
		profile["phone"] = *u.Phone
	}
	return profile
}

// OIDCClaims returns claims for the userinfo endpoint based on granted scopes.
func (u *User) OIDCClaims(scopes []string) map[string]any {
	claims := map[string]any{
		"sub": u.ID.String(),
	}

	scopeSet := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = true
	}

	if scopeSet["profile"] {
		if u.DisplayName != nil {
			claims["name"] = *u.DisplayName
		}
		if u.AvatarURL != nil {
			claims["picture"] = *u.AvatarURL
		}
		if u.Phone != nil {
			claims["phone_number"] = *u.Phone
		}
		claims["updated_at"] = u.UpdatedAt.Unix()
	}

	if scopeSet["email"] {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}

	return claims
}

// AdminView returns the full user data for admin endpoints.
func (u *User) AdminView() map[string]any {
	view := u.PublicProfile()
	view["locked_until"] = u.LockedUntil
	view["failed_login_attempts"] = u.FailedLoginAttempts
	view["metadata"] = u.Metadata
	return view
}

// UserID is a helper type for foreign keys.
type UserID = uuid.UUID
