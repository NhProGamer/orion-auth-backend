package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders_HSTSGate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name           string
		hstsEnabled    bool
		expectHSTS     bool
		expectHSTSVal  string
		alwaysExpected []string
	}{
		{
			name:          "release: HSTS emitted",
			hstsEnabled:   true,
			expectHSTS:    true,
			expectHSTSVal: "max-age=31536000; includeSubDomains",
		},
		{
			name:        "dev: HSTS suppressed",
			hstsEnabled: false,
			expectHSTS:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(SecurityHeaders(tc.hstsEnabled))
			r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.ServeHTTP(w, req)

			got := w.Header().Get("Strict-Transport-Security")
			if tc.expectHSTS {
				if got != tc.expectHSTSVal {
					t.Errorf("HSTS header = %q, want %q", got, tc.expectHSTSVal)
				}
			} else if got != "" {
				t.Errorf("HSTS header should be absent, got %q", got)
			}

			// Sanity: the non-HSTS hardening headers always fire.
			for _, h := range []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"Referrer-Policy",
				"Content-Security-Policy",
			} {
				if w.Header().Get(h) == "" {
					t.Errorf("expected header %s to be set", h)
				}
			}
		})
	}
}
