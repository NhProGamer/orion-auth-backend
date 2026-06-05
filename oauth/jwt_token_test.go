package oauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// stubJWTSigner is a tiny in-memory AccessTokenJWTSigner used by introspect /
// revoke tests so we exercise the dispatch logic without importing oidc and
// pulling in its key management.
type stubJWTSigner struct {
	tokens map[string]map[string]any // jwt → claims
}

func newStubJWTSigner() *stubJWTSigner {
	return &stubJWTSigner{tokens: map[string]map[string]any{}}
}

func (s *stubJWTSigner) GenerateAccessTokenJWT(claims AccessTokenJWTClaims, _ string) (string, string, error) {
	jti := uuid.NewString()
	// Build a synthetic 3-segment string so looksLikeJWT() picks it up.
	tok := "header." + jti + ".sig"
	s.tokens[tok] = map[string]any{
		"iss":       "https://auth.example.com",
		"sub":       claims.ClientID.String(),
		"aud":       claims.Audience,
		"client_id": claims.ClientID.String(),
		"scope":     strings.Join(claims.Scopes, " "),
		"jti":       jti,
		"exp":       float64(time.Now().Add(claims.TTL).Unix()),
		"iat":       float64(time.Now().Unix()),
	}
	return tok, jti, nil
}

func (s *stubJWTSigner) ValidateAccessTokenJWT(token string) (map[string]any, error) {
	if claims, ok := s.tokens[token]; ok {
		return claims, nil
	}
	return nil, errors.New("unknown token")
}

func TestIntrospect_JWTAccessToken_HappyPath(t *testing.T) {
	repo := &mockOAuthRepo{}
	signer := newStubJWTSigner()
	svc := newTestService(repo, &mockUserRepo{}, &mockSessionRepo{}, withAccessTokenJWTSigner(signer))

	clientID := uuid.New()
	tok, _, err := signer.GenerateAccessTokenJWT(AccessTokenJWTClaims{
		ClientID: clientID,
		Scopes:   []string{"read", "write"},
		Audience: "urn:my:api",
		TTL:      time.Hour,
	}, "RS256")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Introspect(tok, "", "https://auth.example.com", clientID)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Errorf("expected Active=true, got %+v", resp)
	}
	if resp.Scope != "read write" {
		t.Errorf("scope = %q", resp.Scope)
	}
	if resp.ClientID != clientID.String() {
		t.Errorf("client_id = %s, want %s", resp.ClientID, clientID)
	}
	if resp.Aud != "urn:my:api" {
		t.Errorf("aud = %s", resp.Aud)
	}
}

func TestIntrospect_JWTAccessToken_DenylistFlipsActive(t *testing.T) {
	revoked := map[string]bool{}
	repo := &mockOAuthRepo{
		isJTIRevokedFn: func(jti string) (bool, error) { return revoked[jti], nil },
	}
	signer := newStubJWTSigner()
	svc := newTestService(repo, &mockUserRepo{}, &mockSessionRepo{}, withAccessTokenJWTSigner(signer))

	clientID := uuid.New()
	tok, jti, _ := signer.GenerateAccessTokenJWT(AccessTokenJWTClaims{
		ClientID: clientID, Scopes: []string{"x"}, Audience: "u", TTL: time.Hour,
	}, "RS256")

	resp, _ := svc.Introspect(tok, "", "iss", clientID)
	if !resp.Active {
		t.Fatalf("token should be active before revoke")
	}
	revoked[jti] = true
	resp, _ = svc.Introspect(tok, "", "iss", clientID)
	if resp.Active {
		t.Errorf("token should be inactive after JTI is denylisted")
	}
}

func TestRevoke_JWTAccessToken_AddsToDenylist(t *testing.T) {
	var revokedJTI string
	repo := &mockOAuthRepo{
		revokeJTIFn: func(jti string, _ time.Time) error {
			revokedJTI = jti
			return nil
		},
	}
	signer := newStubJWTSigner()
	svc := newTestService(repo, &mockUserRepo{}, &mockSessionRepo{}, withAccessTokenJWTSigner(signer))

	clientID := uuid.New()
	tok, jti, _ := signer.GenerateAccessTokenJWT(AccessTokenJWTClaims{
		ClientID: clientID, Scopes: []string{"x"}, Audience: "u", TTL: time.Hour,
	}, "RS256")
	client := newTestClient()
	client.ID = clientID
	if err := svc.Revoke(tok, "", client); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revokedJTI != jti {
		t.Errorf("denylisted JTI = %q, want %q", revokedJTI, jti)
	}
}

func TestRevoke_JWTAccessToken_CrossClientIsSilentSuccess(t *testing.T) {
	var revokedJTI string
	repo := &mockOAuthRepo{
		revokeJTIFn: func(jti string, _ time.Time) error {
			revokedJTI = jti
			return nil
		},
	}
	signer := newStubJWTSigner()
	svc := newTestService(repo, &mockUserRepo{}, &mockSessionRepo{}, withAccessTokenJWTSigner(signer))

	tokenOwner := uuid.New()
	tok, _, _ := signer.GenerateAccessTokenJWT(AccessTokenJWTClaims{
		ClientID: tokenOwner, Scopes: []string{"x"}, Audience: "u", TTL: time.Hour,
	}, "RS256")
	other := newTestClient()
	other.ID = uuid.New() // different from tokenOwner
	if err := svc.Revoke(tok, "", other); err != nil {
		t.Fatalf("Revoke should silently succeed (RFC 7009): %v", err)
	}
	if revokedJTI != "" {
		t.Errorf("denylist should NOT contain JTI revoked by wrong client")
	}
}
