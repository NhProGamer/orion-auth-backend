package model

import "github.com/google/uuid"

// Seed UUIDs match the literal strings used in the initial RBAC +
// client migrations. Centralised here so Go code never re-parses a
// magic UUID string scattered across packages. SQL migrations keep
// their string form for portability with `goose` tooling — when
// editing one, grep for the constant name below to find the matching
// migration.
const (
	AdminRoleIDString       = "00000000-0000-0000-0000-000000000001"
	AdminClientIDString     = "00000000-0000-0000-0000-000000000002"
	DefaultUserRoleIDString = "00000000-0000-0000-0000-000000000004"
)

// AdminRoleID is the seeded "admin" RBAC role granted full permissions
// (migration 011_create_roles_permissions.sql + all subsequent
// role_permissions inserts).
var AdminRoleID = uuid.MustParse(AdminRoleIDString)

// AdminClientID is the seeded first-party admin OAuth client used by
// the AdminUI (orion-auth-frontend) for password-grant + refresh
// flows during local development and the initial bootstrap.
var AdminClientID = uuid.MustParse(AdminClientIDString)

// DefaultUserRoleID is the role auto-assigned to self-registered
// users after seedDefaults. Distinct from AdminRoleID so the admin
// user (seeded first) does not pick up the user role on top of admin.
var DefaultUserRoleID = uuid.MustParse(DefaultUserRoleIDString)
