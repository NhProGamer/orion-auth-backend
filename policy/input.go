package policy

import (
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// BuildTokenIssuanceInput constructs input for token_issuance policies.
func BuildTokenIssuanceInput(client *model.OAuthClient, user *model.User, scopes []string, ipAddress string) map[string]any {
	now := time.Now()
	input := map[string]any{
		"client": map[string]any{
			"id":             client.ID.String(),
			"name":           client.Name,
			"is_public":      client.IsPublic,
			"is_first_party": client.IsFirstParty,
		},
		"scopes":     scopes,
		"ip_address": ipAddress,
		"time": map[string]any{
			"hour":    now.Hour(),
			"weekday": now.Weekday().String(),
			"unix":    now.Unix(),
		},
	}

	if user != nil {
		input["user"] = map[string]any{
			"id":             user.ID.String(),
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"active":         user.Active,
		}
	}

	return input
}

// BuildLoginInput constructs input for login policies.
func BuildLoginInput(user *model.User, client *model.OAuthClient, ipAddress, userAgent string) map[string]any {
	now := time.Now()
	input := map[string]any{
		"user": map[string]any{
			"id":             user.ID.String(),
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"active":         user.Active,
		},
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"time": map[string]any{
			"hour":    now.Hour(),
			"weekday": now.Weekday().String(),
			"unix":    now.Unix(),
		},
	}

	if client != nil {
		input["client"] = map[string]any{
			"id":             client.ID.String(),
			"name":           client.Name,
			"is_public":      client.IsPublic,
			"is_first_party": client.IsFirstParty,
		}
	}

	return input
}

// BuildAdminAPIInput constructs input for admin_api policies.
func BuildAdminAPIInput(userID uuid.UUID, permissions []string, method, path, ipAddress string) map[string]any {
	now := time.Now()
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
		"time": map[string]any{
			"hour":    now.Hour(),
			"weekday": now.Weekday().String(),
			"unix":    now.Unix(),
		},
	}
}
