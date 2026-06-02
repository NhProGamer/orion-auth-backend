package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/testutil"
)

// TestDCR_InitialAccessTokenGate verifies the operator-supplied
// registration gate (RFC 7591 §3). When configured, /register must
// require a matching Bearer token; mismatched or missing tokens get 401.
// When unset, the gate is a no-op (back-compat with open DCR).
func TestDCR_InitialAccessTokenGate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	makeHandler := func(token string) (*DCRHandler, *stubClientRepo) {
		repo := newStubClientRepo()
		svc := NewService(repo, testutil.FastHasher(), nil)
		h := NewDCRHandler(svc)
		h.SetInitialAccessToken(token)
		return h, repo
	}

	body := func() []byte {
		raw, _ := json.Marshal(map[string]any{
			"client_name":   "iat-test",
			"redirect_uris": []string{"https://app.example.com/cb"},
		})
		return raw
	}

	t.Run("no gate configured: open registration", func(t *testing.T) {
		h, repo := makeHandler("")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(body()))
		c.Request.Header.Set("Content-Type", "application/json")
		h.Register(c)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 without gate, got %d (body=%s)", w.Code, w.Body.String())
		}
		if repo.created != 1 {
			t.Errorf("expected 1 client persisted")
		}
	})

	t.Run("gate configured, missing token: 401", func(t *testing.T) {
		h, repo := makeHandler("operator-secret-token")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(body()))
		c.Request.Header.Set("Content-Type", "application/json")
		h.Register(c)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 with missing IAT, got %d", w.Code)
		}
		if repo.created != 0 {
			t.Errorf("expected nothing persisted, got %d", repo.created)
		}
	})

	t.Run("gate configured, wrong token: 401", func(t *testing.T) {
		h, repo := makeHandler("operator-secret-token")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(body()))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("Authorization", "Bearer wrong-token")
		h.Register(c)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 with wrong IAT, got %d", w.Code)
		}
		if repo.created != 0 {
			t.Errorf("expected nothing persisted, got %d", repo.created)
		}
	})

	t.Run("gate configured, correct token: 201", func(t *testing.T) {
		h, repo := makeHandler("operator-secret-token")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(body()))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("Authorization", "Bearer operator-secret-token")
		h.Register(c)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 with correct IAT, got %d (body=%s)", w.Code, w.Body.String())
		}
		if repo.created != 1 {
			t.Errorf("expected 1 client persisted")
		}
	})

	t.Run("Bearer prefix required", func(t *testing.T) {
		h, _ := makeHandler("operator-secret-token")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(body()))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("Authorization", "operator-secret-token") // raw without Bearer
		h.Register(c)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing Bearer prefix, got %d", w.Code)
		}
	})
}
