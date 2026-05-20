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
	PasswordHash           *string         `gorm:"type:varchar(255)" json:"-"`
	MustSetPassword        bool            `gorm:"not null;default:false" json:"must_set_password"`
	PasswordResetToken     *string         `gorm:"type:varchar(255)" json:"-"`
	PasswordResetExpiresAt *time.Time      `json:"-"`
	DisplayName            *string         `gorm:"type:varchar(255)" json:"display_name,omitempty"`
	AvatarURL              *string         `gorm:"type:varchar(512)" json:"avatar_url,omitempty"`
	Phone                  *string         `gorm:"type:varchar(50)" json:"phone,omitempty"`
	LockedUntil            *time.Time      `json:"locked_until,omitempty"`
	FailedLoginAttempts    int             `gorm:"default:0" json:"-"`
	Active                 bool            `gorm:"default:true" json:"active"`
	Metadata               json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	DeletedAt              *time.Time      `json:"deleted_at,omitempty"`
	DeletionToken          *string         `gorm:"type:varchar(255)" json:"-"`
	DeletionPurgeAfter     *time.Time      `gorm:"index" json:"deletion_purge_after,omitempty"`
	EmailChangeNew         *string         `gorm:"type:varchar(255)" json:"-"`
	EmailChangeToken       *string         `gorm:"type:varchar(255)" json:"-"`
	EmailChangeExpiresAt   *time.Time      `json:"-"`
}

// IsPendingDeletion reports whether the user has requested account deletion
// and the grace period has not yet elapsed.
func (u *User) IsPendingDeletion() bool {
	return u.DeletedAt != nil && u.DeletionPurgeAfter != nil && u.DeletionPurgeAfter.After(time.Now())
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
		claims["updated_at"] = u.UpdatedAt.Unix()

		meta := u.GetProfileMetadata()
		setIfNotNil(claims, "given_name", meta.GivenName)
		setIfNotNil(claims, "family_name", meta.FamilyName)
		setIfNotNil(claims, "middle_name", meta.MiddleName)
		setIfNotNil(claims, "nickname", meta.Nickname)
		setIfNotNil(claims, "preferred_username", meta.PreferredUsername)
		setIfNotNil(claims, "profile", meta.ProfileURL)
		setIfNotNil(claims, "website", meta.Website)
		setIfNotNil(claims, "gender", meta.Gender)
		setIfNotNil(claims, "birthdate", meta.Birthdate)
		setIfNotNil(claims, "zoneinfo", meta.Zoneinfo)
		setIfNotNil(claims, "locale", meta.Locale)
	}

	if scopeSet["email"] {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}

	if scopeSet["phone"] {
		if u.Phone != nil {
			claims["phone_number"] = *u.Phone
		}
		meta := u.GetProfileMetadata()
		if meta.PhoneVerified != nil {
			claims["phone_number_verified"] = *meta.PhoneVerified
		}
	}

	if scopeSet["address"] {
		meta := u.GetProfileMetadata()
		if meta.Address != nil {
			claims["address"] = meta.Address
		}
	}

	return claims
}

func setIfNotNil(claims map[string]any, key string, val *string) {
	if val != nil {
		claims[key] = *val
	}
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

// ProfileMetadata holds OIDC standard claims stored in the Metadata JSONB field.
type ProfileMetadata struct {
	GivenName         *string       `json:"given_name,omitempty"`
	FamilyName        *string       `json:"family_name,omitempty"`
	MiddleName        *string       `json:"middle_name,omitempty"`
	Nickname          *string       `json:"nickname,omitempty"`
	PreferredUsername *string       `json:"preferred_username,omitempty"`
	ProfileURL        *string       `json:"profile,omitempty"`
	Website           *string       `json:"website,omitempty"`
	Gender            *string       `json:"gender,omitempty"`
	Birthdate         *string       `json:"birthdate,omitempty"`
	Zoneinfo          *string       `json:"zoneinfo,omitempty"`
	Locale            *string       `json:"locale,omitempty"`
	PhoneVerified     *bool         `json:"phone_number_verified,omitempty"`
	Address           *AddressClaim `json:"address,omitempty"`
}

// AddressClaim represents the OIDC standard address claim (Section 5.1.1).
type AddressClaim struct {
	Formatted     *string `json:"formatted,omitempty"`
	StreetAddress *string `json:"street_address,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postal_code,omitempty"`
	Country       *string `json:"country,omitempty"`
}

// GetProfileMetadata unmarshals the Metadata JSONB into ProfileMetadata.
func (u *User) GetProfileMetadata() ProfileMetadata {
	var meta ProfileMetadata
	if len(u.Metadata) > 0 {
		_ = json.Unmarshal(u.Metadata, &meta)
	}
	return meta
}
