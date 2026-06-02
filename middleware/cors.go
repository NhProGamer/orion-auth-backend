package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/config"
)

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
//
// Special-cases the '*' wildcard origin (Vuln 10): per the Fetch spec a
// server MUST NOT combine 'Access-Control-Allow-Origin: *' with
// 'Access-Control-Allow-Credentials: true'. The previous implementation
// reflected the request Origin and still set Allow-Credentials=true when
// '*' was configured — effectively turning a wildcard into a per-Origin
// credentialed grant. Wildcard mode is now strictly anonymous: no
// Allow-Credentials, literal '*' as Access-Control-Allow-Origin.
//
// config.Validate already refuses '*' in release mode; this is
// belt-and-braces for dev/test deployments that legitimately need it.
func CORS(cfg config.CORSConfig) gin.HandlerFunc {
	allowedOrigins := make(map[string]bool, len(cfg.AllowedOrigins))
	wildcard := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			wildcard = true
			continue
		}
		allowedOrigins[o] = true
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		switch {
		case allowedOrigins[origin]:
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", methods)
			c.Header("Access-Control-Allow-Headers", headers)
			c.Header("Access-Control-Max-Age", maxAge)
			c.Header("Access-Control-Allow-Credentials", "true")
		case wildcard:
			// Wildcard mode: anonymous-only, never credentialed.
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", methods)
			c.Header("Access-Control-Allow-Headers", headers)
			c.Header("Access-Control-Max-Age", maxAge)
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
