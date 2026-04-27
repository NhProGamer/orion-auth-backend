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

// BuildRefreshInput is used at refresh token exchange (refresh policy type).
// Useful to bound refresh velocity, time-of-day, or scope re-evaluation
// independently from token_issuance.
func BuildRefreshInput(u *model.User, c *model.OAuthClient, requestedScopes, grantedScopes []string, sessionID string, ipAddress string) map[string]any {
	input := map[string]any{
		"client":           clientFields(c),
		"scopes_requested": requestedScopes,
		"scopes_granted":   grantedScopes,
		"session_id":       sessionID,
		"ip_address":       ipAddress,
		"time":             timeFields(),
	}
	if u != nil {
		input["user"] = userFields(u)
	}
	return input
}

// BuildConsentInput is used right before user consent is recorded for an
// authorization request (consent policy type). modify.scopes can narrow the
// granted scopes further.
func BuildConsentInput(u *model.User, c *model.OAuthClient, requestedScopes, grantedScopes []string, ipAddress, userAgent string) map[string]any {
	input := map[string]any{
		"user":             userFields(u),
		"client":           clientFields(c),
		"scopes_requested": requestedScopes,
		"scopes_granted":   grantedScopes,
		"ip_address":       ipAddress,
		"user_agent":       userAgent,
		"time":             timeFields(),
	}
	return input
}

// BuildDeviceApprovalInput is used right before a user-approved device code is
// marked authorized (device_approval policy type). Useful to enforce additional
// auth, restrict device approval by IP/UA fingerprint, or by time of day.
func BuildDeviceApprovalInput(u *model.User, c *model.OAuthClient, scopes []string, userCode, ipAddress, userAgent string) map[string]any {
	input := map[string]any{
		"user":       userFields(u),
		"scopes":     scopes,
		"user_code":  userCode,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"time":       timeFields(),
	}
	if c != nil {
		input["client"] = clientFields(c)
	}
	return input
}

// BuildIntrospectInput is used at /introspect right after the token is
// resolved. A deny here causes the response to look like an inactive token
// (per RFC 7662 — the caller learns nothing) which is the security-correct
// behavior for "this client may not introspect that token".
func BuildIntrospectInput(tokenType, tokenClientID, tokenUserID string, scopes []string, audience *string, requestingClientID, ipAddress string) map[string]any {
	token := map[string]any{
		"type":      tokenType,
		"client_id": tokenClientID,
		"scopes":    scopes,
	}
	if tokenUserID != "" {
		token["user_id"] = tokenUserID
	}
	if audience != nil {
		token["audience"] = *audience
	}
	return map[string]any{
		"token": token,
		"requesting_client": map[string]any{
			"id": requestingClientID,
		},
		"ip_address": ipAddress,
		"time":       timeFields(),
	}
}

// BuildClientAuthInput is used by the ClientAuth middleware right after a
// client is successfully authenticated on /token, /introspect, /revoke, /par,
// /device_authorization. authMethod is one of: client_secret_basic,
// client_secret_post, private_key_jwt, none.
func BuildClientAuthInput(c *model.OAuthClient, authMethod, method, path, ipAddress, userAgent string) map[string]any {
	return map[string]any{
		"client":      clientFields(c),
		"auth_method": authMethod,
		"request": map[string]any{
			"method": method,
			"path":   path,
		},
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"time":       timeFields(),
	}
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
