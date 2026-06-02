package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/testutil"
)

// TestDCR_RejectsPrivateJWKSURI is the SSRF regression test for vuln 1.
// A client registration that points jwks_uri at AWS IMDS must be refused
// immediately, before any HTTP fetch is attempted, with a clear error
// referencing the private-address policy.
func TestDCR_RejectsPrivateJWKSURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name string
		uri  string
	}{
		{"AWS IMDS link-local", "http://169.254.169.254/latest/meta-data/iam/"},
		{"RFC1918 10.x", "http://10.0.0.1/.well-known/jwks.json"},
		{"loopback IPv4", "http://127.0.0.1:8080/jwks"},
		{"loopback IPv6", "http://[::1]/jwks"},
		{"explicit localhost host", "http://localhost/jwks"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{
				"client_name":   "ssrf-test",
				"redirect_uris": []string{"https://app.example.com/cb"},
				"jwks_uri":      tc.uri,
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
			if !strings.Contains(w.Body.String(), "jwks_uri") {
				t.Errorf("error body should mention jwks_uri; got %s", w.Body.String())
			}
			if repo.created != 0 {
				t.Errorf("expected no client to be persisted on validation failure, got %d", repo.created)
			}
		})
	}
}

// TestDCR_AcceptsPublicHTTPSJWKSURI verifies the negative case: a valid
// https jwks_uri pointing at a public hostname is not rejected by the
// SSRF gate (the rest of the flow may still fail elsewhere).
func TestDCR_AcceptsPublicHTTPSJWKSURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := map[string]any{
		"client_name":   "ssrf-test",
		"redirect_uris": []string{"https://app.example.com/cb"},
		"jwks_uri":      "https://example.com/.well-known/jwks.json",
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

	// Expect 201 Created — the jwks_uri passed the SSRF gate and the
	// minimal Create flow returns a client.
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d (body=%s)", w.Code, w.Body.String())
	}
	if repo.created != 1 {
		t.Errorf("expected 1 client persisted, got %d", repo.created)
	}
}
