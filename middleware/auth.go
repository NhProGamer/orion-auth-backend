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

// accessTokenRow is a lightweight struct for token lookup.
type accessTokenRow struct {
	ID        string    `gorm:"column:id"`
	ClientID  string    `gorm:"column:client_id"`
	UserID    *string   `gorm:"column:user_id"`
	SessionID *string   `gorm:"column:session_id"`
	Scopes    string    `gorm:"column:scopes"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Revoked   bool      `gorm:"column:revoked"`
}

// BearerAuth validates the Bearer token from the Authorization header.
// It looks up the token hash in the access_tokens table.
func BearerAuth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			pkg.HandleError(c, pkg.ErrUnauthorized("missing authorization header"))
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			pkg.HandleError(c, pkg.ErrUnauthorized("invalid authorization header format"))
			c.Abort()
			return
		}

		rawToken := parts[1]
		tokenHash := hashTokenSHA256(rawToken)

		var token accessTokenRow
		err := db.Table("access_tokens").
			Where("id = ? AND revoked = FALSE AND expires_at > ?", tokenHash, time.Now()).
			First(&token).Error

		if err != nil {
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
