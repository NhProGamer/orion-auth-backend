package m2m

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// CreateUserInput is the body of POST /api/v1/m2m/users. `password` is
// optional — if omitted, a random one is generated server-side and returned
// once in the response payload.
type CreateUserInput struct {
	Email         string                 `json:"email" binding:"required,email"`
	Password      string                 `json:"password,omitempty"`
	DisplayName   *string                `json:"display_name,omitempty"`
	EmailVerified *bool                  `json:"email_verified,omitempty"`
	Active        *bool                  `json:"active,omitempty"`
	Phone         *string                `json:"phone,omitempty"`
	AvatarURL     *string                `json:"avatar_url,omitempty"`
	Metadata      *model.ProfileMetadata `json:"metadata,omitempty"`
	RoleIDs       []uuid.UUID            `json:"role_ids,omitempty"`
}

// UpdateUserInput permits any user field except id. Pointer-only so the
// caller's intent is unambiguous.
type UpdateUserInput struct {
	Email         *string                `json:"email,omitempty"`
	EmailVerified *bool                  `json:"email_verified,omitempty"`
	DisplayName   *string                `json:"display_name,omitempty"`
	AvatarURL     *string                `json:"avatar_url,omitempty"`
	Phone         *string                `json:"phone,omitempty"`
	Active        *bool                  `json:"active,omitempty"`
	Metadata      *model.ProfileMetadata `json:"metadata,omitempty"`
}

// SetPasswordInput is the body of PUT /api/v1/m2m/users/:id/password.
type SetPasswordInput struct {
	Password string `json:"password" binding:"required"`
}

// AssignRoleInput is the body of POST /api/v1/m2m/users/:id/roles.
type AssignRoleInput struct {
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

// CreateUserResult mirrors what the handler returns on user creation. The
// generated password is only present when the caller omitted one in the
// request — and it's returned exactly once (never persisted in plaintext).
type CreateUserResult struct {
	User              map[string]any `json:"user"`
	GeneratedPassword string         `json:"generated_password,omitempty"`
}
