package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"orion-auth-backend/middleware"
	"orion-auth-backend/model"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func startJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kid": kid,
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

func signRequestObject(t *testing.T, kid string, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestParseAndVerifyRequestObject_Valid(t *testing.T) {
	priv := generateTestRSAKey(t)
	kid := "test-key-1"
	srv := startJWKSServer(t, kid, &priv.PublicKey)
	defer srv.Close()

	uri := srv.URL
	client := &model.OAuthClient{JWKSUri: &uri}
	cache := middleware.NewJWKSCache()

	claims := jwt.MapClaims{
		"iss":           "client-1",
		"redirect_uri":  "https://app.example/cb",
		"response_type": "code",
		"scope":         "openid profile",
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(2 * time.Minute).Unix(),
	}
	jwtStr := signRequestObject(t, kid, priv, claims)

	got, err := ParseAndVerifyRequestObject(jwtStr, client, cache)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["redirect_uri"] != "https://app.example/cb" {
		t.Errorf("redirect_uri = %q", got["redirect_uri"])
	}
	if got["scope"] != "openid profile" {
		t.Errorf("scope = %q", got["scope"])
	}
}

func TestParseAndVerifyRequestObject_RejectsUnsignedAlgNone(t *testing.T) {
	uri := "https://example/jwks"
	client := &model.OAuthClient{JWKSUri: &uri}
	cache := middleware.NewJWKSCache()

	// Forge an alg=none JWT by hand.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"redirect_uri":"https://evil/cb"}`))
	unsigned := header + "." + payload + "."

	if _, err := ParseAndVerifyRequestObject(unsigned, client, cache); err == nil {
		t.Errorf("expected rejection for alg=none, got nil")
	} else if !strings.Contains(err.Error(), "signed") && !strings.Contains(err.Error(), "alg") {
		t.Errorf("error should mention signing requirement, got %v", err)
	}
}

func TestParseAndVerifyRequestObject_RejectsBadSignature(t *testing.T) {
	priv := generateTestRSAKey(t)
	otherKey := generateTestRSAKey(t)
	kid := "test-key-1"
	srv := startJWKSServer(t, kid, &priv.PublicKey)
	defer srv.Close()

	uri := srv.URL
	client := &model.OAuthClient{JWKSUri: &uri}
	cache := middleware.NewJWKSCache()

	claims := jwt.MapClaims{
		"iss": "c",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	// Sign with a different key — verifier should refuse.
	jwtStr := signRequestObject(t, kid, otherKey, claims)
	if _, err := ParseAndVerifyRequestObject(jwtStr, client, cache); err == nil {
		t.Errorf("expected signature verification failure")
	}
}

func TestParseAndVerifyRequestObject_RejectsClientWithoutJWKSUri(t *testing.T) {
	client := &model.OAuthClient{}
	cache := middleware.NewJWKSCache()
	if _, err := ParseAndVerifyRequestObject("a.b.c", client, cache); err == nil {
		t.Errorf("expected error when client has no jwks_uri")
	}
}

func TestFetchRequestURI_Succeeds(t *testing.T) {
	body := "header.payload.sig"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/oauth-authz-req+jwt" {
			t.Errorf("Accept header = %q", got)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := FetchRequestURI(srv.URL)
	if err != nil {
		t.Fatalf("FetchRequestURI: %v", err)
	}
	if got != body {
		t.Errorf("body = %q", got)
	}
}

func TestFetchRequestURI_RejectsLargeBody(t *testing.T) {
	huge := strings.Repeat("a", requestObjectMaxBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	if _, err := FetchRequestURI(srv.URL); err == nil {
		t.Errorf("expected error for body exceeding cap")
	}
}

func TestFetchRequestURI_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	if _, err := FetchRequestURI(srv.URL); err == nil {
		t.Errorf("expected error on non-200 response")
	}
}
