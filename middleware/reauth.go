package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

const (
	// ContextReauthToken stores the resolved *model.ReauthToken for the request
	// so handlers can call ConsumeReauth(c) after a successful sensitive action.
	ContextReauthToken = "reauth_token"

	// HeaderReauth is the canonical header carrying the raw step-up token.
	HeaderReauth = "X-Reauth-Token"
)

// ReauthVerifier is satisfied by reauth.Service. Lives here to avoid importing
// the reauth package from middleware.
type ReauthVerifier interface {
	Verify(rawToken string, userID, sessionID uuid.UUID) (*model.ReauthToken, error)
	Consume(hash, consumedBy string) error
}

// RequireReauth blocks the request unless a valid, unused, session-bound
// reauth token is present in the X-Reauth-Token header. The token is NOT
// consumed automatically — handlers must call ConsumeReauth(c, action) after
// the sensitive operation succeeds. This avoids burning a token on failures.
func RequireReauth(svc ReauthVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader(HeaderReauth)
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, &pkg.AppError{
				Message:    "step-up reauthentication required",
				Code:       "reauth_required",
				StatusCode: http.StatusForbidden,
			})
			return
		}

		userID, ok := GetUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, pkg.ErrUnauthorized("not authenticated"))
			return
		}
		sessionID, ok := GetSessionID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, pkg.ErrUnauthorized("reauth requires a session-bound token"))
			return
		}

		t, err := svc.Verify(raw, userID, sessionID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, pkg.ErrInternal("failed to verify reauth token"))
			return
		}
		if t == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, &pkg.AppError{
				Message:    "invalid or expired reauth token",
				Code:       "reauth_invalid",
				StatusCode: http.StatusForbidden,
			})
			return
		}

		c.Set(ContextReauthToken, t)
		c.Next()
	}
}

// ConsumeReauth marks the request's reauth token as used and returns whether
// a token was actually present. Call this from sensitive handlers AFTER the
// underlying action succeeds.
func ConsumeReauth(c *gin.Context, svc ReauthVerifier, action string) bool {
	val, exists := c.Get(ContextReauthToken)
	if !exists {
		return false
	}
	t, ok := val.(*model.ReauthToken)
	if !ok {
		return false
	}
	_ = svc.Consume(t.ID, action)
	return true
}
