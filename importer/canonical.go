// Package importer holds the IAM-agnostic core of the "migrate an existing IAM
// into OrionAuth" feature. A Source (e.g. importer/logto) reads a foreign IAM
// and produces CanonicalUser records; the Engine consumes them and writes them
// into OrionAuth. Adding another IAM means writing a new Source — the Engine
// never changes.
package importer

import (
	"context"

	"orion-auth-backend/model"
)

// CanonicalUser is the neutral representation every Source produces. Fields map
// onto OrionAuth's model.User plus the side tables (federation_links,
// user_roles); the Engine decides how to persist them.
type CanonicalUser struct {
	// ExternalID is the user's id in the source IAM, kept for provenance and
	// idempotency reporting (stored under metadata._import).
	ExternalID string

	Email       string // required; the Engine lowercases and dedupes on it
	DisplayName *string
	AvatarURL   *string
	Phone       *string
	Username    *string

	// EmailVerified is what the source knows. The Engine may additionally force
	// it true via Mapping.AssumeVerifiedEmail.
	EmailVerified bool

	// PasswordHash is a normalized, self-describing hash (native argon2id, a
	// foreign $argon2i$/$2b$ string, or a crypto.EncodeForeignHash envelope).
	// nil means no importable password: the user will be onboarded via reset.
	PasswordHash *string
	// PasswordUnsupported is set when the source HAD a password it could not
	// normalize (e.g. Logto "Legacy"). Distinguishes a genuine social-only
	// account (nil hash, false) from a lossy import the operator may want to
	// fail or skip on (see Mapping.OnUnsupportedPassword).
	PasswordUnsupported bool

	Active     bool
	Profile    model.ProfileMetadata
	CustomData map[string]any

	Identities []CanonicalIdentity
	// Roles are source role names, resolved against Mapping.Roles by the Engine.
	Roles []string
}

// CanonicalIdentity is one linked external/social identity in the source IAM.
type CanonicalIdentity struct {
	Target     string // source connector target, e.g. "google", "discord"
	ExternalID string // subject at the provider
	Email      *string
}

// Source reads a foreign IAM and yields canonical users. Implementations are
// read-only with respect to the source system.
type Source interface {
	// Name identifies the source in reports and provenance metadata.
	Name() string
	// Users loads every user to import. One-shot migrations favour a slice over
	// streaming; callers run this offline.
	Users(ctx context.Context) ([]CanonicalUser, error)
	// Close releases the source connection.
	Close() error
}
