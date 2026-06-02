package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/testutil"
)

// register drives a fresh DCR POST and returns the persisted client +
// raw RAT it issued. Used by the lifecycle tests below.
func register(t *testing.T, h *DCRHandler) (*model.OAuthClient, string) {
	t.Helper()
	body := map[string]any{
		"client_name":   "rat-test",
		"redirect_uris": []string{"https://app.example.com/cb"},
	}
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Register(c)
	if w.Code != http.StatusCreated {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	var resp DCRResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id, err := uuid.Parse(resp.ClientID)
	if err != nil {
		t.Fatalf("bad client_id: %v", err)
	}
	client, err := h.service.repo.FindByID(id)
	if err != nil || client == nil {
		t.Fatalf("client not persisted: %v", err)
	}
	return client, resp.RegistrationAccessToken
}

// callRead drives GET /register/:client_id with the supplied RAT.
func callRead(t *testing.T, h *DCRHandler, clientID, rat string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/register/"+clientID, nil)
	c.Params = gin.Params{{Key: "client_id", Value: clientID}}
	if rat != "" {
		c.Request.Header.Set("Authorization", "Bearer "+rat)
	}
	h.ReadRegistration(c)
	return w
}

// TestRAT_HasExpirationSetOnRegistration locks in the expiry field is
// populated to ~ratLifetime in the future.
func TestRAT_HasExpirationSetOnRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newStubClientRepo()
	svc := NewService(repo, testutil.FastHasher(), nil)
	h := NewDCRHandler(svc)

	client, _ := register(t, h)
	if client.RegistrationAccessTokenExpiresAt == nil {
		t.Fatal("expected expiry to be set after Register")
	}
	if client.RegistrationAccessTokenExpiresAt.Before(time.Now().Add(ratLifetime - time.Hour)) {
		t.Fatal("expiry is too close to now")
	}
}

// TestRAT_RejectsExpiredToken is the regression test for Vuln 9: a RAT
// past its expires_at must not let the caller through, even if the hash
// matches. Operators are expected to rotate via PUT before the window
// closes.
func TestRAT_RejectsExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newStubClientRepo()
	svc := NewService(repo, testutil.FastHasher(), nil)
	h := NewDCRHandler(svc)

	client, rat := register(t, h)
	// Force the expiry into the past.
	past := time.Now().Add(-time.Minute)
	client.RegistrationAccessTokenExpiresAt = &past

	w := callRead(t, h, client.ID.String(), rat)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired RAT, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestRAT_RotatedOnUpdate verifies PUT /register/:client_id rotates the
// RAT. The response carries the new RAT, the old one stops working.
func TestRAT_RotatedOnUpdate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newStubClientRepo()
	svc := NewService(repo, testutil.FastHasher(), nil)
	h := NewDCRHandler(svc)

	client, oldRAT := register(t, h)

	// PUT to rotate.
	updateBody, _ := json.Marshal(map[string]any{"client_name": "rat-test-2"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPut, "/register/"+client.ID.String(), bytes.NewReader(updateBody))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Authorization", "Bearer "+oldRAT)
	c.Params = gin.Params{{Key: "client_id", Value: client.ID.String()}}
	h.UpdateRegistration(c)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT failed: %d %s", w.Code, w.Body.String())
	}
	var resp DCRResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RegistrationAccessToken == "" {
		t.Fatal("PUT response did not carry a rotated RAT")
	}
	if resp.RegistrationAccessToken == oldRAT {
		t.Fatal("rotated RAT must differ from the previous one")
	}

	// Old RAT must now be invalid.
	w2 := callRead(t, h, client.ID.String(), oldRAT)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with the OLD RAT after rotation, got %d", w2.Code)
	}

	// New RAT must work.
	w3 := callRead(t, h, client.ID.String(), resp.RegistrationAccessToken)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 with the NEW RAT, got %d", w3.Code)
	}
}

// TestRAT_RejectsWrongTokenOfRightLength confirms the constant-time
// comparison still rejects mismatched hashes. Note that exercising the
// timing property itself is impractical in unit tests; this is a
// behavioural lock-in.
func TestRAT_RejectsWrongTokenOfRightLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newStubClientRepo()
	svc := NewService(repo, testutil.FastHasher(), nil)
	h := NewDCRHandler(svc)
	client, rat := register(t, h)

	// Generate a different opaque token of the same shape.
	other, _, err := crypto.GenerateOpaqueToken()
	if err != nil || other == rat {
		t.Fatalf("could not generate distinct token: %v", err)
	}
	w := callRead(t, h, client.ID.String(), other)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for mismatched RAT, got %d", w.Code)
	}
}
