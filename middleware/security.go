package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders adds standard security headers to all responses.
//
// HSTS is emitted only when hstsEnabled is true (typically release mode).
// Over plain HTTP the header is ignored by browsers per RFC 6797 §7.2, but
// we still gate on the flag so operators developing on a local hostname
// they later reuse with HTTPS in prod don't accidentally pin a max-age.
func SecurityHeaders(hstsEnabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-XSS-Protection", "0")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if hstsEnabled {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}
