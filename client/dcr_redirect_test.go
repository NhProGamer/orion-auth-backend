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

// TestDCR_RejectsDangerousRedirectSchemes is the regression test for vuln 5:
// an unauthenticated DCR caller must not be able to register a client whose
// redirect_uri is an XSS vector (javascript:, data:, file:) or a non-loopback
// http URL. The check happens in client.Service.Create via
// netsafety.ValidateRedirectURIScheme — the request must fail with 400 and
// nothing reaches the repository.
func TestDCR_RejectsDangerousRedirectSchemes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name string
		uri  string
	}{
		{"javascript scheme", "javascript:alert(1)"},
		{"data URI", "data:text/html,<script>alert(1)</script>"},
		{"vbscript", "vbscript:msgbox(1)"},
		{"file scheme", "file:///etc/passwd"},
		{"http on remote host", "http://attacker.example/cb"},
		{"missing scheme", "/cb"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"client_name":   "redir-test",
				"redirect_uris": []string{tc.uri},
			}
			raw, _ := json.Marshal(body)

			repo := newStubClientRepo()
			svc := NewService(repo, testutil.FastHasher(), nil)
			h := NewDCRHandler(svc)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
			c.Request.Header.Set("Content-Type", "application/json")

			h.Register(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d (body=%s)", w.Code, w.Body.String())
			}
			if repo.created != 0 {
				t.Errorf("expected no client persisted, got %d", repo.created)
			}
		})
	}
}

// TestDCR_AcceptsLoopbackHTTPAndNativeSchemes is the positive control: the
// scheme allowlist must still accept the three legitimate redirect_uri
// shapes (https any host, http on loopback, RFC 8252 native reverse-DNS).
func TestDCR_AcceptsLoopbackHTTPAndNativeSchemes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	good := []string{
		"https://app.example.com/cb",
		"http://127.0.0.1:8080/cb",
		"http://localhost:3000/cb",
		"com.example.app:/oauth/cb",
	}
	body := map[string]any{
		"client_name":   "redir-test",
		"redirect_uris": good,
	}
	raw, _ := json.Marshal(body)

	repo := newStubClientRepo()
	svc := NewService(repo, testutil.FastHasher(), nil)
	h := NewDCRHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Register(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	if repo.created != 1 {
		t.Errorf("expected 1 client persisted, got %d", repo.created)
	}
}
