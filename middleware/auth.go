package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/pkg"
)

const (
	ContextUserID    = "user_id"
	ContextSessionID = "session_id"
	ContextTokenID   = "token_id"
	ContextClientID  = "client_id"
	ContextScopes    = "scopes"
)

// AccessTokenRow is a lightweight struct for token lookup. Exported so other
// middleware (RequireClientScope, future audience-gated middlewares) can
// reuse LookupAccessToken without duplicating the schema mapping.
type AccessTokenRow struct {
	ID        string    `gorm:"column:id"`
	ClientID  string    `gorm:"column:client_id"`
	UserID    *string   `gorm:"column:user_id"`
	SessionID *string   `gorm:"column:session_id"`
	Scopes    string    `gorm:"column:scopes"`
	Audience  *string   `gorm:"column:audience"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Revoked   bool      `gorm:"column:revoked"`
}

// LookupAccessToken hashes the raw bearer and returns the matching row if it
// is non-revoked and unexpired. Returns (nil, nil) when no such token exists.
// Shared by BearerAuth and RequireClientScope.
func LookupAccessToken(db *gorm.DB, raw string) (*AccessTokenRow, error) {
	if raw == "" {
		return nil, nil
	}
	hash := hashTokenSHA256(raw)
	var row AccessTokenRow
	err := db.Table("access_tokens").
		Where("id = ? AND revoked = FALSE AND expires_at > ?", hash, time.Now()).
		First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

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

// BearerAuth validates the Bearer token from the Authorization header.
// It looks up the token hash in the access_tokens table.
func BearerAuth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := ParseBearer(c.GetHeader("Authorization"))
		if raw == "" {
			pkg.HandleError(c, pkg.ErrUnauthorized("missing or invalid authorization header"))
			c.Abort()
			return
		}

		token, err := LookupAccessToken(db, raw)
		if err != nil || token == nil {
			pkg.HandleError(c, pkg.ErrUnauthorized("invalid or expired token"))
			c.Abort()
			return
		}

		// Verify associated session is still active (if user-bound token)
		if token.SessionID != nil {
			var sessionActive bool
			err = db.Table("sessions").
				Select("COUNT(*) > 0").
				Where("id = ? AND revoked = FALSE AND expires_at > ?", *token.SessionID, time.Now()).
				Scan(&sessionActive).Error

			if err != nil || !sessionActive {
				pkg.HandleError(c, pkg.ErrUnauthorized("session expired or revoked"))
				c.Abort()
				return
			}
		}

		c.Set(ContextTokenID, token.ID)
		if cid, err := uuid.Parse(token.ClientID); err == nil {
			c.Set(ContextClientID, cid)
		}
		if token.UserID != nil {
			uid, _ := uuid.Parse(*token.UserID)
			c.Set(ContextUserID, uid)
		}
		if token.SessionID != nil {
			sid, _ := uuid.Parse(*token.SessionID)
			c.Set(ContextSessionID, sid)
		}
		c.Set(ContextScopes, parseScopes(token.Scopes))

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

func hashTokenSHA256(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func parseScopes(raw string) []string {
	// PostgreSQL text[] comes as {scope1,scope2}
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}
