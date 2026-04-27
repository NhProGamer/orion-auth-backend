// Package inputs builds the input maps passed to OPA/Rego policy evaluation.
// It lives in its own subpackage so call sites in any layer (oauth, middleware,
// future hooks) can depend on it without creating an import cycle with the
// policy engine itself.
package inputs

import (
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// timeFields returns a stable representation of the current instant for policy
// rules. weekday is exposed as both string ("Monday") and int (0=Sunday) so
// authors can write either input.time.weekday == "Monday" or input.time.weekday_n != 0.
func timeFields() map[string]any {
	now := time.Now()
	return map[string]any{
		"hour":      now.Hour(),
		"weekday":   now.Weekday().String(),
		"weekday_n": int(now.Weekday()),
		"unix":      now.Unix(),
	}
}

func userFields(u *model.User) map[string]any {
	return map[string]any{
		"id":             u.ID.String(),
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"active":         u.Active,
	}
}

func clientFields(c *model.OAuthClient) map[string]any {
	return map[string]any{
		"id":             c.ID.String(),
		"name":           c.Name,
		"is_public":      c.IsPublic,
		"is_first_party": c.IsFirstParty,
	}
}

// BuildLoginInput is used at user authentication time (login policy type).
func BuildLoginInput(u *model.User, c *model.OAuthClient, ipAddress, userAgent string) map[string]any {
	input := map[string]any{
		"user":       userFields(u),
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"time":       timeFields(),
	}
	if c != nil {
		input["client"] = clientFields(c)
	}
	return input
}

// BuildTokenIssuanceInput is used right before access/refresh tokens are issued
// (token_issuance policy type). Modify result fields supported by the call
// site: access_token_ttl, refresh_token_ttl (both as seconds).
func BuildTokenIssuanceInput(c *model.OAuthClient, u *model.User, scopes []string, ipAddress string) map[string]any {
	input := map[string]any{
		"client":     clientFields(c),
		"scopes":     scopes,
		"ip_address": ipAddress,
		"time":       timeFields(),
	}
	if u != nil {
		input["user"] = userFields(u)
	}
	return input
}

// BuildAdminAPIInput is used by the RequirePolicy middleware on /api/v1/admin/*
// (admin_api policy type). Only deny is consulted; modify is ignored.
func BuildAdminAPIInput(userID uuid.UUID, permissions []string, method, path, ipAddress string) map[string]any {
	return map[string]any{
		"user": map[string]any{
			"id":          userID.String(),
			"permissions": permissions,
		},
		"request": map[string]any{
			"method": method,
			"path":   path,
		},
		"ip_address": ipAddress,
		"time":       timeFields(),
	}
}
