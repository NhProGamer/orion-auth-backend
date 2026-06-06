package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/pkg"
)

// RequireClientScope guards M2M endpoints. It accepts a bearer token issued
// via OAuth2 `client_credentials` carrying:
//
//   - audience == `audience` argument
//   - `requiredScope` in its `scopes` array
//   - **no** UserID (user-bound tokens are rejected to prevent privilege
//     elevation from a user's session into the M2M surface)
//
// On failure the response follows RFC 6750: a 403 with a structured
// `error.code` plus a `WWW-Authenticate: Bearer scope="..."` header so SDKs
// can surface the missing scope.
func RequireClientScope(tokens TokenLookup, requiredScope, audience string) gin.HandlerFunc {
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

		// M2M-only: a user-bound token cannot be used to call the M2M API,
		// even if it incidentally carries the right scope. This prevents
		// privilege confusion from a stolen user session.
		if token.UserID != nil {
			abortForbidden(c, http.StatusForbidden, "m2m_only",
				"this endpoint requires a client_credentials token (no user binding)", requiredScope)
			return
		}

		if token.Audience == nil || *token.Audience != audience {
			abortForbidden(c, http.StatusForbidden, "wrong_audience",
				fmt.Sprintf("token audience does not match %q", audience), requiredScope)
			return
		}

		scopes := []string(token.Scopes)
		if !containsScope(scopes, requiredScope) {
			abortForbidden(c, http.StatusForbidden, "insufficient_scope",
				fmt.Sprintf("token is missing required scope %q", requiredScope), requiredScope)
			return
		}

		c.Set(ContextClientID, token.ClientID)
		c.Set(ContextTokenID, token.ID)
		c.Set(ContextScopes, scopes)

		c.Next()
	}
}

func abortForbidden(c *gin.Context, status int, code, message, scope string) {
	c.Header("WWW-Authenticate",
		fmt.Sprintf(`Bearer error=%q, error_description=%q, scope=%q`,
			code, message, scope))
	c.AbortWithStatusJSON(status, &pkg.AppError{
		Message:    message,
		Code:       code,
		StatusCode: status,
	})
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
