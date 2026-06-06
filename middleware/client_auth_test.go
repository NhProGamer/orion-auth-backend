package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
)

// stubEvaluator implements PolicyEvaluator for ClientAuth tests.
type stubEvaluator struct {
	deny   bool
	reason string
	err    error
}

func (s *stubEvaluator) Evaluate(_ context.Context, _ string, _ map[string]any) (bool, string, error) {
	return s.deny, s.reason, s.err
}

func newClientAuthRouter(mw gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/probe", mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func postForm(r *gin.Engine, basicAuth string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func fastHasher() *crypto.Argon2Hasher {
	return crypto.NewArgon2Hasher(config.Argon2Config{
		Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16,
	})
}

func TestClientAuth_MissingCredentials(t *testing.T) {
	mw := ClientAuth(&stubClients{}, fastHasher(), "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	w := postForm(r, "", url.Values{})
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Fatalf("missing creds: got %d", w.Code)
	}
}

func TestClientAuth_UnknownClient_Basic(t *testing.T) {
	cid := uuid.New()
	mw := ClientAuth(&stubClients{byID: map[uuid.UUID]*model.OAuthClient{}}, fastHasher(),
		"https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(cid.String()+":secret"))
	w := postForm(r, basic, url.Values{})
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
		t.Fatalf("unknown client: got %d", w.Code)
	}
}

func TestClientAuth_PublicClient_BasicNoSecret(t *testing.T) {
	cid := uuid.New()
	clients := &stubClients{byID: map[uuid.UUID]*model.OAuthClient{
		cid: {IsPublic: true, Active: true},
	}}
	clients.byID[cid].ID = cid

	mw := ClientAuth(clients, fastHasher(), "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	w := postForm(r, "", url.Values{
		"client_id": []string{cid.String()},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("public client should pass: got %d, body=%s", w.Code, w.Body.String())
	}
}

func TestClientAuth_ConfidentialClient_WrongSecret(t *testing.T) {
	cid := uuid.New()
	h := fastHasher()
	hashed, _ := h.Hash("correct-secret")
	clients := &stubClients{byID: map[uuid.UUID]*model.OAuthClient{
		cid: {IsPublic: false, Active: true, SecretHash: &hashed},
	}}
	clients.byID[cid].ID = cid

	mw := ClientAuth(clients, h, "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(cid.String()+":wrong"))
	w := postForm(r, basic, url.Values{})
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
		t.Fatalf("wrong secret: got %d", w.Code)
	}
}

func TestClientAuth_ConfidentialClient_CorrectSecret(t *testing.T) {
	cid := uuid.New()
	h := fastHasher()
	hashed, _ := h.Hash("correct-secret")
	clients := &stubClients{byID: map[uuid.UUID]*model.OAuthClient{
		cid: {IsPublic: false, Active: true, SecretHash: &hashed},
	}}
	clients.byID[cid].ID = cid

	mw := ClientAuth(clients, h, "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(cid.String()+":correct-secret"))
	w := postForm(r, basic, url.Values{})
	if w.Code != http.StatusOK {
		t.Fatalf("correct secret should pass: got %d, body=%s", w.Code, w.Body.String())
	}
}

func TestClientAuth_PolicyDeny(t *testing.T) {
	cid := uuid.New()
	clients := &stubClients{byID: map[uuid.UUID]*model.OAuthClient{
		cid: {IsPublic: true, Active: true},
	}}
	clients.byID[cid].ID = cid

	mw := ClientAuth(clients, fastHasher(), "https://issuer/token", NewJWKSCache(), nil,
		&stubEvaluator{deny: true, reason: "policy: blocked by config"})
	r := newClientAuthRouter(mw)
	w := postForm(r, "", url.Values{
		"client_id": []string{cid.String()},
	})
	if w.Code == http.StatusOK {
		t.Fatalf("policy deny should reject; got %d", w.Code)
	}
}

func TestClientAuth_MalformedBasic(t *testing.T) {
	mw := ClientAuth(&stubClients{}, fastHasher(), "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	w := postForm(r, "Basic !!!notbase64!!!", url.Values{})
	if w.Code == http.StatusOK {
		t.Fatalf("malformed basic should reject; got %d", w.Code)
	}
}

func TestClientAuth_InvalidClientIDBasic(t *testing.T) {
	mw := ClientAuth(&stubClients{}, fastHasher(), "https://issuer/token", NewJWKSCache(), nil, nil)
	r := newClientAuthRouter(mw)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("not-a-uuid:secret"))
	w := postForm(r, basic, url.Values{})
	if w.Code == http.StatusOK {
		t.Fatalf("non-uuid client_id should reject; got %d", w.Code)
	}
}
