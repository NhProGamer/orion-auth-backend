package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	appCrypto "orion-auth-backend/crypto"
	"orion-auth-backend/model"
)

// setActiveKeyWithPub generates a key pair and wires both private + public
// PEMs into a Service so that GenerateAccessTokenJWT and
// ValidateAccessTokenJWT round-trip correctly.
func setActiveKeyWithPub(t *testing.T) *Service {
	t.Helper()
	privPEM, pubPEM, err := appCrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := appCrypto.ParseRSAPrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.New()
	return &Service{
		issuer:     "https://auth.example.com",
		activeKey:  &model.SigningKey{ID: keyID, Algorithm: "RS256"},
		privateKey: priv,
		allKeys: []model.SigningKey{
			{ID: keyID, Algorithm: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM},
		},
	}
}

func TestGenerateAccessTokenJWT_UserBoundWithRoles(t *testing.T) {
	s := setActiveKeyWithPub(t)
	uid := uuid.New()
	cid := uuid.New()

	jwtStr, jti, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		UserID:   &uid,
		ClientID: cid,
		Scopes:   []string{"read", "write"},
		Audience: "urn:my:api",
		TTL:      time.Hour,
	}, "RS256")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if jti == "" {
		t.Errorf("jti is empty")
	}

	claims, err := s.ValidateAccessTokenJWT(jwtStr)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims["sub"] != uid.String() {
		t.Errorf("sub = %v, want %s", claims["sub"], uid)
	}
	if claims["aud"] != "urn:my:api" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["client_id"] != cid.String() {
		t.Errorf("client_id = %v", claims["client_id"])
	}
	if claims["scope"] != "read write" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if claims["jti"] != jti {
		t.Errorf("jti claim mismatch")
	}
	// roles claim should NOT be present without scope "roles"
	if _, ok := claims["roles"]; ok {
		t.Errorf("roles claim should be absent without scope=roles")
	}
}

func TestGenerateAccessTokenJWT_ClientCredentialsUsesClientAsSub(t *testing.T) {
	s := setActiveKeyWithPub(t)
	cid := uuid.New()
	jwtStr, _, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		ClientID: cid,
		Scopes:   []string{"machine:do"},
		Audience: "urn:my:api",
		TTL:      time.Hour,
	}, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ValidateAccessTokenJWT(jwtStr)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != cid.String() {
		t.Errorf("sub should equal client_id for client_credentials, got %v", claims["sub"])
	}
}

func TestGenerateAccessTokenJWT_HeaderTypAtJWT(t *testing.T) {
	s := setActiveKeyWithPub(t)
	cid := uuid.New()
	jwtStr, _, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		ClientID: cid, Scopes: []string{"x"}, Audience: "u", TTL: time.Minute,
	}, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 parts, got %d", len(parts))
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if typ, _ := tok.Header["typ"].(string); typ != "at+jwt" {
		t.Errorf("typ header = %q, want at+jwt", typ)
	}
	if kid, _ := tok.Header["kid"].(string); kid == "" {
		t.Errorf("kid header is empty")
	}
}

func TestGenerateAccessTokenJWT_RejectsUnsupportedAlg(t *testing.T) {
	s := setActiveKeyWithPub(t)
	if _, _, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		ClientID: uuid.New(), Scopes: []string{"x"}, Audience: "u", TTL: time.Minute,
	}, "HS256"); err == nil {
		t.Errorf("expected error on HS256 (server has RSA key only)")
	}
}

func TestGenerateAccessTokenJWT_ExtraClaimsCannotOverrideReserved(t *testing.T) {
	s := setActiveKeyWithPub(t)
	cid := uuid.New()
	jwtStr, _, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		ClientID: cid, Scopes: []string{"x"}, Audience: "u", TTL: time.Minute,
		ExtraClaims: map[string]any{
			"sub":   "evil",
			"aud":   "malicious",
			"scope": "admin",
			"foo":   "bar",
		},
	}, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ValidateAccessTokenJWT(jwtStr)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] == "evil" || claims["aud"] == "malicious" || claims["scope"] == "admin" {
		t.Errorf("reserved claims were overridden by ExtraClaims: %v", claims)
	}
	if claims["foo"] != "bar" {
		t.Errorf("non-reserved extra claim not merged: %v", claims["foo"])
	}
}

func TestValidateAccessTokenJWT_RejectsWrongIssuer(t *testing.T) {
	s := setActiveKeyWithPub(t)
	jwtStr, _, err := s.GenerateAccessTokenJWT(AccessTokenClaims{
		ClientID: uuid.New(), Scopes: []string{"x"}, Audience: "u", TTL: time.Minute,
	}, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	other := setActiveKeyWithPub(t)
	other.issuer = "https://different.example.com"
	if _, err := other.ValidateAccessTokenJWT(jwtStr); err == nil {
		t.Errorf("expected issuer mismatch failure")
	}
}
