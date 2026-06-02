package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/config"
)

// TestCORS_AllowedOriginGetsCredentials verifies an explicit allowlisted
// origin still receives Access-Control-Allow-Credentials: true so the
// authenticated SPA flows keep working.
func TestCORS_AllowedOriginGetsCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(config.CORSConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Authorization"},
		MaxAge:         3600,
	}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin: want app.example.com, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials must be true for explicit origin; got %q", got)
	}
}

// TestCORS_WildcardModeNoCredentials is the regression test for Vuln 10:
// when '*' is in allowed_origins, the middleware must serve a literal
// wildcard AND omit Access-Control-Allow-Credentials.
func TestCORS_WildcardModeNoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(config.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Authorization"},
		MaxAge:         3600,
	}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://anything.example/")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin: want literal '*', got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials must NOT be set under wildcard; got %q", got)
	}
}

// TestCORS_UnknownOriginGetsNothing makes sure a non-allowlisted origin
// without wildcard mode receives no CORS headers at all (browser will
// refuse the cross-origin request).
func TestCORS_UnknownOriginGetsNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORS(config.CORSConfig{
		AllowedOrigins: []string{"https://allowed.example"},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Authorization"},
		MaxAge:         3600,
	}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin: want empty, got %q", got)
	}
}
