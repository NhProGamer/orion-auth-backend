package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/pkg"
)

const (
	ContextUserID    = "user_id"
	ContextSessionID = "session_id"
	ContextTokenID   = "token_id"
	ContextClientID  = "client_id"
	ContextScopes    = "scopes"
)

// ParseBearer extracts the raw token from an `Authorization: Bearer …` header.
// Returns "" if the header is missing or malformed.
func ParseBearer(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return ""
	}
	return parts[1]
}

// BearerAuth validates the Bearer token from the Authorization header by
// consulting the TokenLookup service (which hashes + checks revocation +
// expiry), then verifies the parent session is still alive when the token
// is user-bound. Both interfaces let the middleware be unit-tested without
// a database.
func BearerAuth(tokens TokenLookup, sessions SessionValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := ParseBearer(c.GetHeader("Authorization"))
		if raw == "" {
			pkg.HandleError(c, pkg.ErrUnauthorized("missing or invalid authorization header"))
			c.Abort()
			return
		}

		token, err := tokens.LookupActiveAccessToken(raw)
		if err != nil || token == nil {
			pkg.HandleError(c, pkg.ErrUnauthorized("invalid or expired token"))
			c.Abort()
			return
		}

		if token.SessionID != nil {
			active, err := sessions.IsActive(*token.SessionID)
			if err != nil || !active {
				pkg.HandleError(c, pkg.ErrUnauthorized("session expired or revoked"))
				c.Abort()
				return
			}
		}

		c.Set(ContextTokenID, token.ID)
		c.Set(ContextClientID, token.ClientID)
		if token.UserID != nil {
			c.Set(ContextUserID, *token.UserID)
		}
		if token.SessionID != nil {
			c.Set(ContextSessionID, *token.SessionID)
		}
		c.Set(ContextScopes, []string(token.Scopes))

		c.Next()
	}
}

// GetUserID extracts the user ID from the Gin context.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(ContextUserID)
	if !exists {
		return uuid.Nil, false
	}
	uid, ok := val.(uuid.UUID)
	return uid, ok
}

// GetClientID extracts the client ID from the Gin context.
func GetClientID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(ContextClientID)
	if !exists {
		return uuid.Nil, false
	}
	cid, ok := val.(uuid.UUID)
	return cid, ok
}

// GetSessionID extracts the session ID from the Gin context.
func GetSessionID(c *gin.Context) (uuid.UUID, bool) {
	val, exists := c.Get(ContextSessionID)
	if !exists {
		return uuid.Nil, false
	}
	sid, ok := val.(uuid.UUID)
	return sid, ok
}

// GetScopes extracts the token scopes from the Gin context.
func GetScopes(c *gin.Context) []string {
	val, exists := c.Get(ContextScopes)
	if !exists {
		return nil
	}
	scopes, ok := val.([]string)
	if !ok {
		return nil
	}
	return scopes
}
