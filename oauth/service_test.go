package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/session"
	"orion-auth-backend/testutil"
	"orion-auth-backend/user"
)

// ---------------------------------------------------------------------------
// Mock: oauth.RepositoryInterface
// ---------------------------------------------------------------------------

type mockOAuthRepo struct {
	findClientFn                   func(clientIDStr string) (*model.OAuthClient, error)
	createAuthRequestFn            func(req *model.AuthorizationRequest) error
	findAuthRequestFn              func(id uuid.UUID) (*model.AuthorizationRequest, error)
	updateAuthRequestFn            func(req *model.AuthorizationRequest) error
	deleteAuthRequestFn            func(id uuid.UUID) error
	createAuthCodeFn               func(code *model.AuthorizationCode) error
	findAuthCodeFn                 func(codeHash string) (*model.AuthorizationCode, error)
	markAuthCodeUsedFn             func(codeHash string) error
	createAccessTokenFn            func(token *model.AccessToken) error
	findAccessTokenFn              func(id string) (*model.AccessToken, error)
	revokeAccessTokenFn            func(id string) error
	revokeAccessTokensByRefreshFn  func(refreshTokenID string) error
	revokeAccessTokensBySessionFn  func(sessionID uuid.UUID) error
	createRefreshTokenFn           func(token *model.RefreshToken) error
	findRefreshTokenFn             func(id string) (*model.RefreshToken, error)
	rotateRefreshTokenFn           func(id string) error
	revokeRefreshTokenFamilyFn     func(familyID uuid.UUID) error
	revokeRefreshTokensBySessionFn func(sessionID uuid.UUID) error
	findActiveConsentFn            func(userID, clientID uuid.UUID) (*model.Consent, error)
	createConsentFn                func(consent *model.Consent) error
	updateConsentFn                func(consent *model.Consent) error
	createDeviceCodeFn             func(dc *model.DeviceCode) error
	findDeviceCodeFn               func(codeHash string) (*model.DeviceCode, error)
	findDeviceCodeByUserCodeFn     func(userCode string) (*model.DeviceCode, error)
	updateDeviceCodeFn             func(dc *model.DeviceCode) error
	createPARFn                    func(par *model.PushedAuthorizationRequest) error
	findPARFn                      func(requestURI string) (*model.PushedAuthorizationRequest, error)
	deletePARFn                    func(requestURI string) error
	isJTIRevokedFn                 func(jti string) (bool, error)
	revokeJTIFn                    func(jti string, expiresAt time.Time) error
	purgeExpiredRevokedJTIsFn      func() (int64, error)
}

func (m *mockOAuthRepo) findClient(clientIDStr string) (*model.OAuthClient, error) {
	if m.findClientFn != nil {
		return m.findClientFn(clientIDStr)
	}
	return nil, errors.New("not implemented")
}
func (m *mockOAuthRepo) CreateAuthRequest(req *model.AuthorizationRequest) error {
	if m.createAuthRequestFn != nil {
		return m.createAuthRequestFn(req)
	}
	id, _ := uuid.NewV7()
	req.ID = id
	return nil
}
func (m *mockOAuthRepo) FindAuthRequest(id uuid.UUID) (*model.AuthorizationRequest, error) {
	if m.findAuthRequestFn != nil {
		return m.findAuthRequestFn(id)
	}
	return nil, nil
}
func (m *mockOAuthRepo) UpdateAuthRequest(req *model.AuthorizationRequest) error {
	if m.updateAuthRequestFn != nil {
		return m.updateAuthRequestFn(req)
	}
	return nil
}
func (m *mockOAuthRepo) DeleteAuthRequest(id uuid.UUID) error {
	if m.deleteAuthRequestFn != nil {
		return m.deleteAuthRequestFn(id)
	}
	return nil
}
func (m *mockOAuthRepo) CreateAuthCode(code *model.AuthorizationCode) error {
	if m.createAuthCodeFn != nil {
		return m.createAuthCodeFn(code)
	}
	return nil
}
func (m *mockOAuthRepo) FindAuthCode(codeHash string) (*model.AuthorizationCode, error) {
	if m.findAuthCodeFn != nil {
		return m.findAuthCodeFn(codeHash)
	}
	return nil, nil
}
func (m *mockOAuthRepo) MarkAuthCodeUsed(codeHash string) error {
	if m.markAuthCodeUsedFn != nil {
		return m.markAuthCodeUsedFn(codeHash)
	}
	return nil
}
func (m *mockOAuthRepo) CreateAccessToken(token *model.AccessToken) error {
	if m.createAccessTokenFn != nil {
		return m.createAccessTokenFn(token)
	}
	return nil
}
func (m *mockOAuthRepo) FindAccessToken(id string) (*model.AccessToken, error) {
	if m.findAccessTokenFn != nil {
		return m.findAccessTokenFn(id)
	}
	return nil, nil
}
func (m *mockOAuthRepo) RevokeAccessToken(id string) error {
	if m.revokeAccessTokenFn != nil {
		return m.revokeAccessTokenFn(id)
	}
	return nil
}
func (m *mockOAuthRepo) RevokeAccessTokensByRefreshToken(refreshTokenID string) error {
	if m.revokeAccessTokensByRefreshFn != nil {
		return m.revokeAccessTokensByRefreshFn(refreshTokenID)
	}
	return nil
}
func (m *mockOAuthRepo) RevokeAccessTokensBySession(sessionID uuid.UUID) error {
	if m.revokeAccessTokensBySessionFn != nil {
		return m.revokeAccessTokensBySessionFn(sessionID)
	}
	return nil
}
func (m *mockOAuthRepo) CreateRefreshToken(token *model.RefreshToken) error {
	if m.createRefreshTokenFn != nil {
		return m.createRefreshTokenFn(token)
	}
	return nil
}
func (m *mockOAuthRepo) FindRefreshToken(id string) (*model.RefreshToken, error) {
	if m.findRefreshTokenFn != nil {
		return m.findRefreshTokenFn(id)
	}
	return nil, nil
}
func (m *mockOAuthRepo) RotateRefreshToken(id string) error {
	if m.rotateRefreshTokenFn != nil {
		return m.rotateRefreshTokenFn(id)
	}
	return nil
}
func (m *mockOAuthRepo) RevokeRefreshTokenFamily(familyID uuid.UUID) error {
	if m.revokeRefreshTokenFamilyFn != nil {
		return m.revokeRefreshTokenFamilyFn(familyID)
	}
	return nil
}
func (m *mockOAuthRepo) RevokeRefreshTokensBySession(sessionID uuid.UUID) error {
	if m.revokeRefreshTokensBySessionFn != nil {
		return m.revokeRefreshTokensBySessionFn(sessionID)
	}
	return nil
}
func (m *mockOAuthRepo) FindActiveConsent(userID, clientID uuid.UUID) (*model.Consent, error) {
	if m.findActiveConsentFn != nil {
		return m.findActiveConsentFn(userID, clientID)
	}
	return nil, nil
}
func (m *mockOAuthRepo) CreateConsent(consent *model.Consent) error {
	if m.createConsentFn != nil {
		return m.createConsentFn(consent)
	}
	return nil
}
func (m *mockOAuthRepo) UpdateConsent(consent *model.Consent) error {
	if m.updateConsentFn != nil {
		return m.updateConsentFn(consent)
	}
	return nil
}
func (m *mockOAuthRepo) CreateDeviceCode(dc *model.DeviceCode) error {
	if m.createDeviceCodeFn != nil {
		return m.createDeviceCodeFn(dc)
	}
	return nil
}
func (m *mockOAuthRepo) FindDeviceCode(codeHash string) (*model.DeviceCode, error) {
	if m.findDeviceCodeFn != nil {
		return m.findDeviceCodeFn(codeHash)
	}
	return nil, nil
}
func (m *mockOAuthRepo) FindDeviceCodeByUserCode(userCode string) (*model.DeviceCode, error) {
	if m.findDeviceCodeByUserCodeFn != nil {
		return m.findDeviceCodeByUserCodeFn(userCode)
	}
	return nil, nil
}
func (m *mockOAuthRepo) UpdateDeviceCode(dc *model.DeviceCode) error {
	if m.updateDeviceCodeFn != nil {
		return m.updateDeviceCodeFn(dc)
	}
	return nil
}
func (m *mockOAuthRepo) CreatePAR(par *model.PushedAuthorizationRequest) error {
	if m.createPARFn != nil {
		return m.createPARFn(par)
	}
	return nil
}
func (m *mockOAuthRepo) FindPAR(requestURI string) (*model.PushedAuthorizationRequest, error) {
	if m.findPARFn != nil {
		return m.findPARFn(requestURI)
	}
	return nil, nil
}
func (m *mockOAuthRepo) DeletePAR(requestURI string) error {
	if m.deletePARFn != nil {
		return m.deletePARFn(requestURI)
	}
	return nil
}
func (m *mockOAuthRepo) IsJTIRevoked(jti string) (bool, error) {
	if m.isJTIRevokedFn != nil {
		return m.isJTIRevokedFn(jti)
	}
	return false, nil
}
func (m *mockOAuthRepo) RevokeJTI(jti string, expiresAt time.Time) error {
	if m.revokeJTIFn != nil {
		return m.revokeJTIFn(jti, expiresAt)
	}
	return nil
}
func (m *mockOAuthRepo) PurgeExpiredRevokedJTIs() (int64, error) {
	if m.purgeExpiredRevokedJTIsFn != nil {
		return m.purgeExpiredRevokedJTIsFn()
	}
	return 0, nil
}
func (m *mockOAuthRepo) Transaction(fn func(tx RepositoryInterface) error) error {
	return fn(m)
}

// ---------------------------------------------------------------------------
// Mock: user.RepositoryInterface
// ---------------------------------------------------------------------------

type mockUserRepo struct {
	findByEmailFn  func(email string) (*model.User, error)
	findByIDFn     func(id uuid.UUID) (*model.User, error)
	updateFieldsFn func(id uuid.UUID, fields map[string]any) error
}

func (m *mockUserRepo) Create(_ *model.User) error { return nil }
func (m *mockUserRepo) FindByID(id uuid.UUID) (*model.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(id)
	}
	return nil, nil
}
func (m *mockUserRepo) FindByEmail(email string) (*model.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(email)
	}
	return nil, nil
}
func (m *mockUserRepo) Update(_ *model.User) error { return nil }
func (m *mockUserRepo) UpdateFields(id uuid.UUID, fields map[string]any) error {
	if m.updateFieldsFn != nil {
		return m.updateFieldsFn(id, fields)
	}
	return nil
}
func (m *mockUserRepo) List(_, _ int) ([]model.User, int64, error)      { return nil, 0, nil }
func (m *mockUserRepo) Delete(_ uuid.UUID) error                        { return nil }
func (m *mockUserRepo) FindByResetToken(_ string) (*model.User, error)       { return nil, nil }
func (m *mockUserRepo) FindByVerifyToken(_ string) (*model.User, error)      { return nil, nil }
func (m *mockUserRepo) FindByEmailChangeToken(_ string) (*model.User, error) { return nil, nil }
func (m *mockUserRepo) FindByDeletionToken(_ string) (*model.User, error)    { return nil, nil }

// ---------------------------------------------------------------------------
// Mock: session.RepositoryInterface
// ---------------------------------------------------------------------------

type mockSessionRepo struct {
	createFn func(s *model.Session) error
}

func (m *mockSessionRepo) Create(s *model.Session) error {
	if m.createFn != nil {
		return m.createFn(s)
	}
	id, _ := uuid.NewV7()
	s.ID = id
	return nil
}
func (m *mockSessionRepo) FindByID(_ uuid.UUID) (*model.Session, error)              { return nil, nil }
func (m *mockSessionRepo) FindActiveByUser(_ uuid.UUID) ([]model.Session, error)     { return nil, nil }
func (m *mockSessionRepo) Revoke(_ uuid.UUID) error                                  { return nil }
func (m *mockSessionRepo) RevokeAllForUser(_ uuid.UUID, _ *uuid.UUID) (int64, error) { return 0, nil }
func (m *mockSessionRepo) UpdateLastActive(_ uuid.UUID) error                        { return nil }

// ---------------------------------------------------------------------------
// Mock: IDTokenGenerator
// ---------------------------------------------------------------------------

type mockIDTokenGen struct {
	generateFn func(claims IDTokenClaims) (string, error)
}

func (m *mockIDTokenGen) GenerateIDToken(claims IDTokenClaims) (string, error) {
	if m.generateFn != nil {
		return m.generateFn(claims)
	}
	return "mock-id-token", nil
}

// ---------------------------------------------------------------------------
// Mock: MFAValidator
// ---------------------------------------------------------------------------

type mockMFAValidator struct {
	hasMFAFn       func(userID uuid.UUID) (bool, error)
	validateCodeFn func(userID uuid.UUID, code string) (bool, error)
}

func (m *mockMFAValidator) HasMFA(userID uuid.UUID) (bool, error) {
	if m.hasMFAFn != nil {
		return m.hasMFAFn(userID)
	}
	return false, nil
}
func (m *mockMFAValidator) ValidateCode(userID uuid.UUID, code string) (bool, error) {
	if m.validateCodeFn != nil {
		return m.validateCodeFn(userID, code)
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Mock: PolicyEvaluator
// ---------------------------------------------------------------------------

type mockPolicyEvaluator struct {
	evaluateFn func(policyType string, input map[string]any) (*PolicyResult, error)
}

func (m *mockPolicyEvaluator) Evaluate(_ context.Context, policyType string, input map[string]any) (*PolicyResult, error) {
	if m.evaluateFn != nil {
		return m.evaluateFn(policyType, input)
	}
	return &PolicyResult{Allow: true}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const testPassword = "TestP@ss123!"

func newTestService(oauthRepo *mockOAuthRepo, userRepo *mockUserRepo, sessionRepo *mockSessionRepo) *Service {
	hasher := testutil.FastHasher()
	cfg := testutil.TestAuthConfig()

	userSvc := user.NewService(userRepo, hasher, cfg)
	sessionSvc := session.NewService(sessionRepo, cfg)

	return NewService(oauthRepo, userSvc, sessionSvc, hasher, cfg)
}

func newTestClient() *model.OAuthClient {
	return testutil.TestClient()
}

func newFirstPartyClient() *model.OAuthClient {
	c := testutil.TestClient()
	c.IsFirstParty = true
	return c
}

func newPublicClient() *model.OAuthClient {
	c := testutil.TestClient()
	c.IsPublic = true
	c.IsFirstParty = false
	c.SecretHash = nil
	c.TokenAuthMethod = "none"
	return c
}

func newTestUser(hasher *crypto.Argon2Hasher) *model.User {
	return testutil.TestUser(hasher, testPassword)
}

// computeS256Challenge generates a PKCE S256 challenge from a verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func assertOAuthErrorCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", expectedCode)
	}
	var oauthErr *pkg.OAuthError
	if errors.As(err, &oauthErr) {
		if oauthErr.Code != expectedCode {
			t.Fatalf("expected OAuth error code %q, got %q (%s)", expectedCode, oauthErr.Code, oauthErr.Description)
		}
		return
	}
	t.Fatalf("expected *pkg.OAuthError with code %q, got %T: %v", expectedCode, err, err)
}

// ===========================================================================
// InitAuthorize Tests
// ===========================================================================

func TestInitAuthorize_Success(t *testing.T) {
	oauthRepo := &mockOAuthRepo{}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid profile", State: "state123", Nonce: "nonce123", CodeChallenge: "test-challenge", CodeChallengeMethod: "S256"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID == uuid.Nil {
		t.Fatal("expected non-nil request ID")
	}
	if resp.ClientName != client.Name {
		t.Errorf("expected client name %q, got %q", client.Name, resp.ClientName)
	}
	if !resp.RequiresLogin {
		t.Error("expected RequiresLogin=true")
	}
	// Non-first-party requires consent
	if !resp.RequiresConsent {
		t.Error("expected RequiresConsent=true for non-first-party client")
	}
}

func TestInitAuthorize_FirstPartyNoConsent(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newFirstPartyClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid", CodeChallenge: "test-challenge", CodeChallengeMethod: "S256"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequiresConsent {
		t.Error("expected RequiresConsent=false for first-party client")
	}
}

func TestInitAuthorize_UnsupportedResponseType(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "id_token", Scope: "openid"})
	assertOAuthErrorCode(t, err, "unsupported_response_type")
}

func TestInitAuthorize_InvalidRedirectURI(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://evil.com/callback", ResponseType: "code", Scope: "openid"})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_GrantTypeNotAllowed(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()
	client.GrantTypes = pq.StringArray{"client_credentials"} // no authorization_code

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid"})
	assertOAuthErrorCode(t, err, "unauthorized_client")
}

func TestInitAuthorize_RequiresPKCE(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid"})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_ConfidentialClientPKCEOptional(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()
	client.RequirePKCE = false

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID == uuid.Nil {
		t.Fatal("expected non-nil request ID")
	}
}

func TestInitAuthorize_PublicClientPKCEAlwaysRequired(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newPublicClient()
	client.RequirePKCE = false

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid"})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_OnlyS256Accepted(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid", CodeChallenge: "challenge123", CodeChallengeMethod: "plain"})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_S256DefaultMethod(t *testing.T) {
	oauthRepo := &mockOAuthRepo{}
	var savedReq *model.AuthorizationRequest
	oauthRepo.createAuthRequestFn = func(req *model.AuthorizationRequest) error {
		id, _ := uuid.NewV7()
		req.ID = id
		savedReq = req
		return nil
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid", CodeChallenge: "challenge123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if savedReq == nil || savedReq.CodeChallengeMethod == nil || *savedReq.CodeChallengeMethod != "S256" {
		t.Error("expected code_challenge_method to default to S256")
	}
}

func TestInitAuthorize_InvalidScopes(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "unknown_scope", CodeChallenge: "test-challenge", CodeChallengeMethod: "S256"})
	assertOAuthErrorCode(t, err, "invalid_scope")
}

func TestInitAuthorize_PublicClientWithPKCE(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newPublicClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid", CodeChallenge: "challenge123", CodeChallengeMethod: "S256"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID == uuid.Nil {
		t.Fatal("expected non-nil request ID")
	}
}

// ===========================================================================
// OIDC Parameters Tests
// ===========================================================================

func TestInitAuthorize_PromptLogin(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newFirstPartyClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Prompt:        "login",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.RequiresLogin {
		t.Error("expected RequiresLogin=true with prompt=login")
	}
	if resp.Prompt != "login" {
		t.Errorf("expected prompt=login in response, got %q", resp.Prompt)
	}
}

func TestInitAuthorize_PromptConsent(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newFirstPartyClient() // first-party normally skips consent

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Prompt:        "consent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.RequiresConsent {
		t.Error("expected RequiresConsent=true with prompt=consent, even for first-party")
	}
}

func TestInitAuthorize_PromptSelectAccount(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Prompt:        "select_account",
	})
	assertOAuthErrorCode(t, err, "account_selection_required")
}

func TestInitAuthorize_PromptNone_NoHint(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Prompt:        "none",
	})
	assertOAuthErrorCode(t, err, "login_required")
}

func TestInitAuthorize_InvalidPromptValue(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Prompt:        "invalid_value",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_InvalidDisplayValue(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Display:       "invalid",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_ValidDisplayValue(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Display:       "popup",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Display != "popup" {
		t.Errorf("expected display=popup in response, got %q", resp.Display)
	}
}

func TestInitAuthorize_LoginHintPassthrough(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	resp, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		LoginHint:     "user@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.LoginHint != "user@example.com" {
		t.Errorf("expected login_hint=user@example.com, got %q", resp.LoginHint)
	}
}

func TestInitAuthorize_UILocalesAccepted(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		UILocales:     "fr-FR en",
	})
	if err != nil {
		t.Fatalf("ui_locales should be accepted without error: %v", err)
	}
}

func TestInitAuthorize_ACRValuesAccepted(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		ACRValues:     "urn:mace:incommon:iap:silver",
	})
	if err != nil {
		t.Fatalf("acr_values should be accepted without error: %v", err)
	}
}

func TestInitAuthorize_InvalidMaxAge(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		MaxAge:        "not_a_number",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_InvalidClaimsJSON(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Claims:        "not valid json",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestInitAuthorize_ValidClaimsJSON(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.InitAuthorize(client, InitAuthorizeParams{
		RedirectURI:   "https://example.com/callback",
		ResponseType:  "code",
		Scope:         "openid",
		CodeChallenge: "test-challenge",
		Claims:        `{"id_token":{"auth_time":{"essential":true}}}`,
	})
	if err != nil {
		t.Fatalf("valid claims JSON should be accepted: %v", err)
	}
}

// ===========================================================================
// AuthorizeLogin Tests
// ===========================================================================

func TestAuthorizeLogin_SuccessFirstParty(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := newTestUser(hasher)
	client := newFirstPartyClient()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:   model.BaseModel{ID: id},
				ClientID:    client.ID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid", "profile"},
				ExpiresAt:   time.Now().Add(10 * time.Minute),
			}, nil
		},
		findClientFn: func(clientIDStr string) (*model.OAuthClient, error) {
			return client, nil
		},
	}
	userRepo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) {
			return testUser, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})

	reqID, _ := uuid.NewV7()
	resp, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     testUser.Email,
		Password:  testPassword,
	}, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Authenticated {
		t.Error("expected Authenticated=true")
	}
	if resp.RequiresConsent {
		t.Error("expected RequiresConsent=false for first-party client")
	}
	if resp.RequiresMFA {
		t.Error("expected RequiresMFA=false")
	}
}

func TestAuthorizeLogin_ExpiredRequest(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel: model.BaseModel{ID: id},
				ExpiresAt: time.Now().Add(-1 * time.Minute), // expired
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	reqID, _ := uuid.NewV7()
	_, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     "test@example.com",
		Password:  "whatever",
	}, "", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestAuthorizeLogin_AlreadyAuthenticated(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: id},
				Authenticated: true,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	reqID, _ := uuid.NewV7()
	_, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     "test@example.com",
		Password:  "whatever",
	}, "", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestAuthorizeLogin_PolicyDeniesLogin(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := newTestUser(hasher)
	client := newFirstPartyClient()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:   model.BaseModel{ID: id},
				ClientID:    client.ID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				ExpiresAt:   time.Now().Add(10 * time.Minute),
			}, nil
		},
		findClientFn: func(clientIDStr string) (*model.OAuthClient, error) {
			return client, nil
		},
	}
	userRepo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) {
			return testUser, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})
	svc.SetPolicyEvaluator(&mockPolicyEvaluator{
		evaluateFn: func(policyType string, input map[string]any) (*PolicyResult, error) {
			if policyType == "login" {
				return &PolicyResult{Deny: true, DenyReason: "blocked by policy"}, nil
			}
			return &PolicyResult{Allow: true}, nil
		},
	})

	reqID, _ := uuid.NewV7()
	_, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     testUser.Email,
		Password:  testPassword,
	}, "127.0.0.1", "test-agent")
	assertOAuthErrorCode(t, err, "access_denied")
}

func TestAuthorizeLogin_RequiresMFA(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := newTestUser(hasher)
	client := newFirstPartyClient()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:   model.BaseModel{ID: id},
				ClientID:    client.ID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				ExpiresAt:   time.Now().Add(10 * time.Minute),
			}, nil
		},
		findClientFn: func(clientIDStr string) (*model.OAuthClient, error) {
			return client, nil
		},
	}
	userRepo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) {
			return testUser, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})
	svc.SetMFAValidator(&mockMFAValidator{
		hasMFAFn: func(userID uuid.UUID) (bool, error) {
			return true, nil
		},
	})

	reqID, _ := uuid.NewV7()
	resp, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     testUser.Email,
		Password:  testPassword,
	}, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.RequiresMFA {
		t.Error("expected RequiresMFA=true")
	}
	if resp.Authenticated {
		t.Error("expected Authenticated=false when MFA is required")
	}
}

func TestAuthorizeLogin_InvalidRequest(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return nil, nil // not found
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	reqID, _ := uuid.NewV7()
	_, err := svc.AuthorizeLogin(AuthorizeLoginInput{
		RequestID: reqID,
		Email:     "test@example.com",
		Password:  "whatever",
	}, "", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

// ===========================================================================
// ExchangeAuthorizationCode Tests
// ===========================================================================

func TestExchangeAuthorizationCode_Success(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()

	rawCode, codeHash, _ := crypto.GenerateOpaqueToken()

	challenge := computeS256Challenge("my-verifier")
	method := "S256"

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			if hash != codeHash {
				return nil, nil
			}
			return &model.AuthorizationCode{
				CodeHash:            codeHash,
				ClientID:            client.ID,
				UserID:              userID,
				RedirectURI:         "https://example.com/callback",
				Scopes:              pq.StringArray{"openid", "profile"},
				CodeChallenge:       &challenge,
				CodeChallengeMethod: &method,
				SessionID:           &sessionID,
				ExpiresAt:           time.Now().Add(5 * time.Minute),
				Used:                false,
				CreatedAt:           time.Now(),
			}, nil
		},
	}

	userRepo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) {
			return &model.User{
				BaseModel: model.BaseModel{ID: userID},
				Email:     "test@example.com",
				Active:    true,
			}, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})
	svc.SetIDTokenGenerator(&mockIDTokenGen{})

	resp, err := svc.ExchangeAuthorizationCode(client, rawCode, "https://example.com/callback", "my-verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %q", resp.TokenType)
	}
	if resp.IDToken == "" {
		t.Error("expected non-empty ID token when openid scope present")
	}
	if resp.ExpiresIn != client.AccessTokenTTL {
		t.Errorf("expected expires_in=%d, got %d", client.AccessTokenTTL, resp.ExpiresIn)
	}
}

func TestExchangeAuthorizationCode_InvalidCode(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			return nil, nil // not found
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.ExchangeAuthorizationCode(client, "invalid-code", "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_ExpiredCode(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			return &model.AuthorizationCode{
				CodeHash:    hash,
				ClientID:    client.ID,
				UserID:      userID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				ExpiresAt:   time.Now().Add(-1 * time.Minute), // expired
				Used:        false,
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, "some-code", "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_CodeAlreadyUsed(t *testing.T) {
	// When Used=true, IsValid() returns false so the service returns
	// "authorization code expired or already used" before reaching replay detection.
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			return &model.AuthorizationCode{
				CodeHash:    hash,
				ClientID:    client.ID,
				UserID:      userID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				SessionID:   &sessionID,
				ExpiresAt:   time.Now().Add(5 * time.Minute),
				Used:        true, // already used
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, "some-code", "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_ClientMismatch(t *testing.T) {
	client := newTestClient()
	otherClientID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			return &model.AuthorizationCode{
				CodeHash:    hash,
				ClientID:    otherClientID, // different client
				UserID:      userID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				ExpiresAt:   time.Now().Add(5 * time.Minute),
				Used:        false,
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, "some-code", "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_RedirectURIMismatch(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			return &model.AuthorizationCode{
				CodeHash:    hash,
				ClientID:    client.ID,
				UserID:      userID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				ExpiresAt:   time.Now().Add(5 * time.Minute),
				Used:        false,
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, "some-code", "https://different.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_PKCEVerificationSuccess(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)
	method := "S256"

	rawCode, codeHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			if hash != codeHash {
				return nil, nil
			}
			return &model.AuthorizationCode{
				CodeHash:            codeHash,
				ClientID:            client.ID,
				UserID:              userID,
				RedirectURI:         "https://example.com/callback",
				Scopes:              pq.StringArray{"openid"},
				CodeChallenge:       &challenge,
				CodeChallengeMethod: &method,
				SessionID:           &sessionID,
				ExpiresAt:           time.Now().Add(5 * time.Minute),
				Used:                false,
				CreatedAt:           time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.ExchangeAuthorizationCode(client, rawCode, "https://example.com/callback", verifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
}

func TestExchangeAuthorizationCode_PKCEVerificationFailure(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	challenge := computeS256Challenge("correct-verifier")
	method := "S256"

	rawCode, codeHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			if hash != codeHash {
				return nil, nil
			}
			return &model.AuthorizationCode{
				CodeHash:            codeHash,
				ClientID:            client.ID,
				UserID:              userID,
				RedirectURI:         "https://example.com/callback",
				Scopes:              pq.StringArray{"openid"},
				CodeChallenge:       &challenge,
				CodeChallengeMethod: &method,
				SessionID:           &sessionID,
				ExpiresAt:           time.Now().Add(5 * time.Minute),
				Used:                false,
				CreatedAt:           time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, rawCode, "https://example.com/callback", "wrong-verifier")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_PKCEMissingVerifier(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	challenge := computeS256Challenge("some-verifier")
	method := "S256"

	rawCode, codeHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			if hash != codeHash {
				return nil, nil
			}
			return &model.AuthorizationCode{
				CodeHash:            codeHash,
				ClientID:            client.ID,
				UserID:              userID,
				RedirectURI:         "https://example.com/callback",
				Scopes:              pq.StringArray{"openid"},
				CodeChallenge:       &challenge,
				CodeChallengeMethod: &method,
				SessionID:           &sessionID,
				ExpiresAt:           time.Now().Add(5 * time.Minute),
				Used:                false,
				CreatedAt:           time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, rawCode, "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCode_PublicClientNoPKCE(t *testing.T) {
	client := newPublicClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()

	rawCode, codeHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAuthCodeFn: func(hash string) (*model.AuthorizationCode, error) {
			if hash != codeHash {
				return nil, nil
			}
			return &model.AuthorizationCode{
				CodeHash:    codeHash,
				ClientID:    client.ID,
				UserID:      userID,
				RedirectURI: "https://example.com/callback",
				Scopes:      pq.StringArray{"openid"},
				SessionID:   &sessionID,
				ExpiresAt:   time.Now().Add(5 * time.Minute),
				Used:        false,
				CreatedAt:   time.Now(),
				// No PKCE challenge stored
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeAuthorizationCode(client, rawCode, "https://example.com/callback", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

// ===========================================================================
// ExchangeClientCredentials Tests
// ===========================================================================

func TestExchangeClientCredentials_Success(t *testing.T) {
	oauthRepo := &mockOAuthRepo{}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	resp, err := svc.ExchangeClientCredentials(client, "openid profile", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken != "" {
		t.Error("expected no refresh token for client_credentials")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %q", resp.TokenType)
	}
	if resp.ExpiresIn != client.AccessTokenTTL {
		t.Errorf("expected expires_in=%d, got %d", client.AccessTokenTTL, resp.ExpiresIn)
	}
}

func TestExchangeClientCredentials_PublicClientRejected(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newPublicClient()

	_, err := svc.ExchangeClientCredentials(client, "openid", "")
	assertOAuthErrorCode(t, err, "unauthorized_client")
}

func TestExchangeClientCredentials_GrantTypeNotAllowed(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()
	client.GrantTypes = pq.StringArray{"authorization_code"} // no client_credentials

	_, err := svc.ExchangeClientCredentials(client, "openid", "")
	assertOAuthErrorCode(t, err, "unauthorized_client")
}

// ===========================================================================
// ExchangeRefreshToken Tests
// ===========================================================================

func TestExchangeRefreshToken_Success(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid", "profile"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				Revoked:   false,
			}, nil
		},
	}

	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.ExchangeRefreshToken(client, rawRT, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token (rotation)")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %q", resp.TokenType)
	}
}

func TestExchangeRefreshToken_InvalidToken(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			return nil, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	_, err := svc.ExchangeRefreshToken(client, "invalid-token", "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeRefreshToken_ExpiredToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, rawRT, "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeRefreshToken_RevokedToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				Revoked:   true,
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, rawRT, "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeRefreshToken_ClientMismatch(t *testing.T) {
	client := newTestClient()
	otherClientID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  otherClientID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, rawRT, "")
	assertOAuthErrorCode(t, err, "invalid_grant")
}

func TestExchangeRefreshToken_ReuseDetection(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	rotatedAt := time.Now().Add(-5 * time.Minute)
	familyRevoked := false

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				RotatedAt: &rotatedAt, // already rotated
			}, nil
		},
		revokeRefreshTokenFamilyFn: func(fid uuid.UUID) error {
			if fid == familyID {
				familyRevoked = true
			}
			return nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, rawRT, "")
	assertOAuthErrorCode(t, err, "invalid_grant")
	if !familyRevoked {
		t.Error("expected entire refresh token family to be revoked on reuse detection")
	}
}

func TestExchangeRefreshToken_GrantTypeNotAllowed(t *testing.T) {
	client := newTestClient()
	client.GrantTypes = pq.StringArray{"authorization_code"} // no refresh_token

	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, "some-token", "")
	assertOAuthErrorCode(t, err, "unauthorized_client")
}

func TestExchangeRefreshToken_ScopeDownscoping(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid", "profile", "email"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.ExchangeRefreshToken(client, rawRT, "openid profile")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Scope != "openid profile" {
		t.Errorf("expected scope 'openid profile', got %q", resp.Scope)
	}
}

func TestExchangeRefreshToken_ScopeExceedsOriginalGrant(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawRT, rtHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != rtHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        rtHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.ExchangeRefreshToken(client, rawRT, "admin_scope_not_granted")
	assertOAuthErrorCode(t, err, "invalid_scope")
}

// ===========================================================================
// Introspect Tests
// ===========================================================================

func TestIntrospect_ActiveAccessToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	testUser := &model.User{
		BaseModel: model.BaseModel{ID: userID},
		Email:     "test@example.com",
		Active:    true,
	}

	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.AccessToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    &userID,
				Scopes:    pq.StringArray{"openid", "profile"},
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			}, nil
		},
	}
	userRepo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) {
			if id == userID {
				return testUser, nil
			}
			return nil, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})

	resp, err := svc.Introspect(rawToken, "access_token", "https://issuer.example.com", client.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Error("expected active=true")
	}
	if resp.ClientID != client.ID.String() {
		t.Errorf("expected client_id=%s, got %s", client.ID, resp.ClientID)
	}
	if resp.Sub != userID.String() {
		t.Errorf("expected sub=%s, got %s", userID, resp.Sub)
	}
	if resp.Username != testUser.Email {
		t.Errorf("expected username=%s, got %s", testUser.Email, resp.Username)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %s", resp.TokenType)
	}
	if resp.Iss != "https://issuer.example.com" {
		t.Errorf("expected iss=%s, got %s", "https://issuer.example.com", resp.Iss)
	}
}

func TestIntrospect_ExpiredAccessToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.AccessToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    &userID,
				Scopes:    pq.StringArray{"openid"},
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
				CreatedAt: time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.Introspect(rawToken, "access_token", "https://issuer.example.com", client.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for expired token")
	}
}

func TestIntrospect_RevokedAccessToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.AccessToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    &userID,
				Scopes:    pq.StringArray{"openid"},
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Revoked:   true,
				CreatedAt: time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.Introspect(rawToken, "access_token", "https://issuer.example.com", client.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for revoked token")
	}
}

func TestIntrospect_UnknownToken(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			return nil, nil
		},
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			return nil, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.Introspect("unknown-token", "", "https://issuer.example.com", uuid.Nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for unknown token")
	}
}

func TestIntrospect_EmptyToken(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.Introspect("", "", "https://issuer.example.com", uuid.Nil)
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestIntrospect_RefreshToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			return nil, nil // not found as access token
		},
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				Scopes:    pq.StringArray{"openid", "offline_access"},
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.Introspect(rawToken, "", "https://issuer.example.com", client.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Error("expected active=true for valid refresh token")
	}
	if resp.TokenType != "refresh_token" {
		t.Errorf("expected token_type=refresh_token, got %s", resp.TokenType)
	}
	if resp.Sub != userID.String() {
		t.Errorf("expected sub=%s, got %s", userID, resp.Sub)
	}
}

func TestIntrospect_UsernameOnlyForOwningClient(t *testing.T) {
	client := newTestClient()
	otherClientID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	oauthRepo := &mockOAuthRepo{
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.AccessToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    &userID,
				Scopes:    pq.StringArray{"openid"},
				ExpiresAt: time.Now().Add(1 * time.Hour),
				CreatedAt: time.Now(),
			}, nil
		},
	}
	userRepo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) {
			return &model.User{
				BaseModel: model.BaseModel{ID: userID},
				Email:     "test@example.com",
			}, nil
		},
	}

	svc := newTestService(oauthRepo, userRepo, &mockSessionRepo{})

	// Requesting with a DIFFERENT client ID
	resp, err := svc.Introspect(rawToken, "access_token", "https://issuer.example.com", otherClientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Error("expected active=true")
	}
	if resp.Username != "" {
		t.Error("expected empty username when requesting client is not the token owner")
	}
}

// ===========================================================================
// Revoke Tests
// ===========================================================================

func TestRevoke_RefreshToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	familyRevoked := false
	sessionTokensRevoked := false

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    userID,
				SessionID: sessionID,
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
		revokeRefreshTokenFamilyFn: func(fid uuid.UUID) error {
			if fid == familyID {
				familyRevoked = true
			}
			return nil
		},
		revokeAccessTokensBySessionFn: func(sid uuid.UUID) error {
			if sid == sessionID {
				sessionTokensRevoked = true
			}
			return nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	err := svc.Revoke(rawToken, "refresh_token", client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !familyRevoked {
		t.Error("expected refresh token family to be revoked")
	}
	if !sessionTokensRevoked {
		t.Error("expected access tokens for session to be revoked (cascade)")
	}
}

func TestRevoke_AccessToken(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	revoked := false

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			return nil, nil // not a refresh token
		},
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.AccessToken{
				ID:        tokenHash,
				ClientID:  client.ID,
				UserID:    &userID,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		},
		revokeAccessTokenFn: func(id string) error {
			if id == tokenHash {
				revoked = true
			}
			return nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	err := svc.Revoke(rawToken, "", client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Error("expected access token to be revoked")
	}
}

func TestRevoke_EmptyToken(t *testing.T) {
	svc := newTestService(&mockOAuthRepo{}, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	err := svc.Revoke("", "", client)
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestRevoke_UnknownTokenReturnsSuccess(t *testing.T) {
	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			return nil, nil
		},
		findAccessTokenFn: func(id string) (*model.AccessToken, error) {
			return nil, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	client := newTestClient()

	// RFC 7009: revocation of unknown token returns success
	err := svc.Revoke("unknown-token", "", client)
	if err != nil {
		t.Fatalf("expected nil error for unknown token per RFC 7009, got: %v", err)
	}
}

func TestRevoke_DifferentClientReturnsSuccess(t *testing.T) {
	client := newTestClient()
	otherClient := newTestClient()
	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	familyID, _ := uuid.NewV7()

	rawToken, tokenHash, _ := crypto.GenerateOpaqueToken()

	familyRevoked := false

	oauthRepo := &mockOAuthRepo{
		findRefreshTokenFn: func(id string) (*model.RefreshToken, error) {
			if id != tokenHash {
				return nil, nil
			}
			return &model.RefreshToken{
				ID:        tokenHash,
				ClientID:  client.ID, // owned by 'client'
				UserID:    userID,
				SessionID: sessionID,
				FamilyID:  familyID,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}, nil
		},
		revokeRefreshTokenFamilyFn: func(fid uuid.UUID) error {
			familyRevoked = true
			return nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	// Attempt revoke with a different client
	err := svc.Revoke(rawToken, "refresh_token", otherClient)
	if err != nil {
		t.Fatalf("expected nil error per RFC 7009, got: %v", err)
	}
	if familyRevoked {
		t.Error("should not revoke tokens owned by another client")
	}
}

// ===========================================================================
// AuthorizeMFA Tests
// ===========================================================================

func TestAuthorizeMFA_Success(t *testing.T) {
	client := newFirstPartyClient()
	userID, _ := uuid.NewV7()
	reqID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				ClientID:      client.ID,
				Scopes:        pq.StringArray{"openid"},
				UserID:        &userID,
				Authenticated: false, // not yet authenticated because MFA pending
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
		findClientFn: func(clientIDStr string) (*model.OAuthClient, error) {
			return client, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	svc.SetMFAValidator(&mockMFAValidator{
		validateCodeFn: func(uid uuid.UUID, code string) (bool, error) {
			return code == "123456", nil
		},
	})

	resp, err := svc.AuthorizeMFA(AuthorizeMFAInput{
		RequestID: reqID,
		Code:      "123456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Authenticated {
		t.Error("expected Authenticated=true after MFA")
	}
	if resp.RequiresMFA {
		t.Error("expected RequiresMFA=false after successful MFA")
	}
}

func TestAuthorizeMFA_InvalidCode(t *testing.T) {
	userID, _ := uuid.NewV7()
	reqID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        &userID,
				Authenticated: false,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})
	svc.SetMFAValidator(&mockMFAValidator{
		validateCodeFn: func(uid uuid.UUID, code string) (bool, error) {
			return false, nil
		},
	})

	_, err := svc.AuthorizeMFA(AuthorizeMFAInput{
		RequestID: reqID,
		Code:      "wrong",
	})
	assertOAuthErrorCode(t, err, "access_denied")
}

func TestAuthorizeMFA_MustAuthenticateFirst(t *testing.T) {
	reqID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        nil, // no user yet
				Authenticated: false,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.AuthorizeMFA(AuthorizeMFAInput{
		RequestID: reqID,
		Code:      "123456",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestAuthorizeMFA_AlreadyCompleted(t *testing.T) {
	userID, _ := uuid.NewV7()
	reqID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        &userID,
				Authenticated: true, // already done
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.AuthorizeMFA(AuthorizeMFAInput{
		RequestID: reqID,
		Code:      "123456",
	})
	assertOAuthErrorCode(t, err, "invalid_request")
}

// ===========================================================================
// AuthorizeConsent Tests
// ===========================================================================

func TestAuthorizeConsent_Success(t *testing.T) {
	client := newTestClient()
	userID, _ := uuid.NewV7()
	reqID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				ClientID:      client.ID,
				RedirectURI:   "https://example.com/callback",
				ResponseType:  "code",
				Scopes:        pq.StringArray{"openid", "profile"},
				UserID:        &userID,
				Authenticated: true,
				ConsentGiven:  false,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
		findClientFn: func(clientIDStr string) (*model.OAuthClient, error) {
			return client, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.AuthorizeConsent(AuthorizeConsentInput{
		RequestID:     reqID,
		ScopesGranted: []string{"openid", "profile"},
	}, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RedirectURI != "https://example.com/callback" {
		t.Errorf("expected redirect_uri=https://example.com/callback, got %s", resp.RedirectURI)
	}
	if resp.Code == "" {
		t.Error("expected non-empty authorization code")
	}
}

func TestAuthorizeConsent_NotAuthenticated(t *testing.T) {
	reqID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        &userID,
				Authenticated: false,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.AuthorizeConsent(AuthorizeConsentInput{
		RequestID:     reqID,
		ScopesGranted: []string{"openid"},
	}, "", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

func TestAuthorizeConsent_InvalidScopes(t *testing.T) {
	reqID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        &userID,
				Authenticated: true,
				Scopes:        pq.StringArray{"openid"},
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.AuthorizeConsent(AuthorizeConsentInput{
		RequestID:     reqID,
		ScopesGranted: []string{"admin_not_requested"},
	}, "", "")
	assertOAuthErrorCode(t, err, "invalid_scope")
}

// ===========================================================================
// CompleteAuthorizeFirstParty Tests
// ===========================================================================

func TestCompleteAuthorizeFirstParty_Success(t *testing.T) {
	client := newFirstPartyClient()
	userID, _ := uuid.NewV7()
	reqID, _ := uuid.NewV7()
	state := "mystate"

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				ClientID:      client.ID,
				RedirectURI:   "https://example.com/callback",
				ResponseType:  "code",
				Scopes:        pq.StringArray{"openid"},
				State:         &state,
				UserID:        &userID,
				Authenticated: true,
				ConsentGiven:  true,
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	resp, err := svc.CompleteAuthorizeFirstParty(reqID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Code == "" {
		t.Error("expected non-empty authorization code")
	}
	if resp.State != state {
		t.Errorf("expected state=%s, got %s", state, resp.State)
	}
}

func TestCompleteAuthorizeFirstParty_NotReady(t *testing.T) {
	reqID, _ := uuid.NewV7()
	userID, _ := uuid.NewV7()

	oauthRepo := &mockOAuthRepo{
		findAuthRequestFn: func(id uuid.UUID) (*model.AuthorizationRequest, error) {
			return &model.AuthorizationRequest{
				BaseModel:     model.BaseModel{ID: reqID},
				UserID:        &userID,
				Authenticated: true,
				ConsentGiven:  false, // not ready
				ExpiresAt:     time.Now().Add(10 * time.Minute),
			}, nil
		},
	}
	svc := newTestService(oauthRepo, &mockUserRepo{}, &mockSessionRepo{})

	_, err := svc.CompleteAuthorizeFirstParty(reqID, "", "")
	assertOAuthErrorCode(t, err, "invalid_request")
}

// ===========================================================================
// Helper function tests
// ===========================================================================

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	if !verifyPKCE(verifier, challenge) {
		t.Error("expected PKCE verification to succeed")
	}
	if verifyPKCE("wrong-verifier", challenge) {
		t.Error("expected PKCE verification to fail with wrong verifier")
	}
}

func TestParseSpaceDelimited(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"openid profile email", []string{"openid", "profile", "email"}},
		{"openid", []string{"openid"}},
		{"", nil},
		{"  openid   profile  ", []string{"openid", "profile"}},
	}
	for _, tt := range tests {
		result := parseSpaceDelimited(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseSpaceDelimited(%q): expected %v, got %v", tt.input, tt.expected, result)
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("parseSpaceDelimited(%q)[%d]: expected %q, got %q", tt.input, i, tt.expected[i], v)
			}
		}
	}
}

func TestJoinScopes(t *testing.T) {
	if got := joinScopes([]string{"openid", "profile"}); got != "openid profile" {
		t.Errorf("expected 'openid profile', got %q", got)
	}
	if got := joinScopes([]string{}); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestFilterScopes(t *testing.T) {
	result := filterScopes([]string{"openid", "admin", "profile"}, []string{"openid", "profile", "email"})
	if len(result) != 2 || result[0] != "openid" || result[1] != "profile" {
		t.Errorf("expected [openid profile], got %v", result)
	}
}

func TestContainsScope(t *testing.T) {
	if !containsScope([]string{"openid", "profile"}, "openid") {
		t.Error("expected true")
	}
	if containsScope([]string{"openid", "profile"}, "admin") {
		t.Error("expected false")
	}
}
