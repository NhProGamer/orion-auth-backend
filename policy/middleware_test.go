package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRequirePolicy_FailsClosedOnNoUser asserts that the admin_api gate
// refuses to silently pass through when the upstream RBAC middleware has
// not populated user_id in the request context. The previous version
// called c.Next() in that path, which (combined with the other
// fail-open branches) let admin requests through even when the gate
// could not actually evaluate.
//
// Passing nil for both services is safe: the gate exits on the
// authentication check before touching them.
func TestRequirePolicy_FailsClosedOnNoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequirePolicy(nil, nil))
	called := false
	r.GET("/x", func(c *gin.Context) {
		called = true
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)

	if called {
		t.Fatal("handler was reached despite missing user_id")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user_id missing, got %d", w.Code)
	}
}
