package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

// --- Mock OIDC provider (end-to-end) ---

type fakeProvider struct {
	server         *httptest.Server
	priv           *rsa.PrivateKey
	kid            string
	expectedCode   string
	expectedVerify string
	clientID       string
	clientSecret   string
	subject        string
	email          string
	emailVerified  bool
	nonce          string
}

func startFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fp := &fakeProvider{
		priv: priv,
		kid:  "test-key-1",
	}
	mux := http.NewServeMux()
	fp.server = httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fp.server.URL,
			"authorization_endpoint":                fp.server.URL + "/authorize",
			"token_endpoint":                        fp.server.URL + "/token",
			"userinfo_endpoint":                     fp.server.URL + "/userinfo",
			"jwks_uri":                              fp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": fp.kid, "n": n, "e": e},
			},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if fp.expectedCode != "" && r.PostForm.Get("code") != fp.expectedCode {
			http.Error(w, "bad code", 400)
			return
		}
		if fp.expectedVerify != "" && r.PostForm.Get("code_verifier") != fp.expectedVerify {
			http.Error(w, "bad verifier", 400)
			return
		}

		idTokenClaims := jwt.MapClaims{
			"iss":            fp.server.URL,
			"sub":            fp.subject,
			"aud":            fp.clientID,
			"exp":            time.Now().Add(5 * time.Minute).Unix(),
			"iat":            time.Now().Unix(),
			"email":          fp.email,
			"email_verified": fp.emailVerified,
			"nonce":          fp.nonce,
			"name":           "Alice Federated",
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
		tok.Header["kid"] = fp.kid
		signed, err := tok.SignedString(fp.priv)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"id_token":     signed,
			"expires_in":   300,
		})
	})

	return fp
}

func (fp *fakeProvider) close() { fp.server.Close() }

// --- E2E tests ---

func TestE2E_NewUserAutoProvisioned(t *testing.T) {
	fp := startFakeProvider(t)
	defer fp.close()
	fp.subject = "google-sub-001"
	fp.email = "alice@example.com"
	fp.emailVerified = true

	users := newMockUsers()
	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, fakeReg{enabled: true}, &fakeInvitations{})

	in := basicCreateInput()
	iss := fp.server.URL
	in.IssuerURL = &iss
	in.ClientID = "test-client"
	in.ClientSecret = "test-secret"
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)

	fp.clientID = provider.ClientID
	fp.clientSecret = "test-secret"

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{})
	require.NoError(t, err)
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	q := parsed.Query()
	fp.nonce = q.Get("nonce")
	fp.expectedCode = "the-code"
	fp.expectedVerify = mustVerifierFor(t, q.Get("code_challenge"), state.authRequests[q.Get("state")])

	cb, err := svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, q.Get("state"))
	require.NoError(t, err)
	assert.Equal(t, fp.subject, cb.Claims.ExternalID)
	assert.Equal(t, fp.email, cb.Claims.Email)
	assert.True(t, cb.Claims.EmailVerified)

	out, err := svc.FindOrProvisionUser(cb)
	require.NoError(t, err)
	assert.Equal(t, ProvisionPendingSignup, out.Kind)
	assert.NotEmpty(t, out.PendingSignupToken, "signup must be staged, not committed, until password is set")
	assert.Nil(t, out.User, "user is only created during CompleteSignup")

	// CompleteSignup finalises the account with the chosen password.
	res, err := svc.CompleteSignup(CompleteSignupInput{Token: out.PendingSignupToken, Password: "ChosenPasswd1!"})
	require.NoError(t, err)
	require.NotNil(t, res.User)
	assert.False(t, res.User.MustSetPassword)
	assert.Equal(t, fp.email, res.User.Email)
}

func TestE2E_ExistingLinkLogsIn(t *testing.T) {
	fp := startFakeProvider(t)
	defer fp.close()
	fp.subject = "google-sub-existing"
	fp.email = "bob@example.com"
	fp.emailVerified = true

	users := newMockUsers()
	hash := "h"
	uid, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: uid}, Email: fp.email, PasswordHash: &hash, Active: true})

	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, fakeReg{enabled: true}, &fakeInvitations{})

	in := basicCreateInput()
	iss := fp.server.URL
	in.IssuerURL = &iss
	in.ClientID = "test-client"
	in.ClientSecret = "test-secret"
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)
	fp.clientID = provider.ClientID

	// Pre-existing link.
	require.NoError(t, repo.CreateLink(&model.FederationLink{
		UserID: uid, ProviderID: provider.ID, ExternalID: fp.subject,
	}))

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{})
	require.NoError(t, err)
	parsed, _ := url.Parse(authURL)
	q := parsed.Query()
	fp.nonce = q.Get("nonce")
	fp.expectedCode = "the-code-2"
	fp.expectedVerify = mustVerifierFor(t, q.Get("code_challenge"), state.authRequests[q.Get("state")])

	cb, err := svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, q.Get("state"))
	require.NoError(t, err)

	out, err := svc.FindOrProvisionUser(cb)
	require.NoError(t, err)
	assert.Equal(t, ProvisionLoginExisting, out.Kind)
	require.NotNil(t, out.User)
	assert.Equal(t, uid, out.User.ID)
}

func TestE2E_EmailMatchStagesPendingLink(t *testing.T) {
	fp := startFakeProvider(t)
	defer fp.close()
	fp.subject = "google-sub-match"
	fp.email = "carol@example.com"

	users := newMockUsers()
	hash := "h"
	uid, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: uid}, Email: fp.email, PasswordHash: &hash, Active: true})

	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, fakeReg{enabled: true}, &fakeInvitations{})

	in := basicCreateInput()
	iss := fp.server.URL
	in.IssuerURL = &iss
	in.ClientID = "test-client"
	in.ClientSecret = "test-secret"
	confirm := true
	in.AllowLinkConfirmation = &confirm
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)
	fp.clientID = provider.ClientID

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{})
	require.NoError(t, err)
	parsed, _ := url.Parse(authURL)
	q := parsed.Query()
	fp.nonce = q.Get("nonce")
	fp.expectedCode = "the-code-3"
	fp.expectedVerify = mustVerifierFor(t, q.Get("code_challenge"), state.authRequests[q.Get("state")])

	cb, err := svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, q.Get("state"))
	require.NoError(t, err)

	out, err := svc.FindOrProvisionUser(cb)
	require.NoError(t, err)
	assert.Equal(t, ProvisionPendingLinkConfirmation, out.Kind)
	assert.NotEmpty(t, out.PendingLinkToken)
}

func TestE2E_NonceMismatchRejected(t *testing.T) {
	fp := startFakeProvider(t)
	defer fp.close()
	fp.subject = "google-sub-bad-nonce"
	fp.email = "dan@example.com"
	fp.emailVerified = true

	users := newMockUsers()
	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, fakeReg{enabled: true}, &fakeInvitations{})

	in := basicCreateInput()
	iss := fp.server.URL
	in.IssuerURL = &iss
	in.ClientID = "test-client"
	in.ClientSecret = "test-secret"
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)
	fp.clientID = provider.ClientID

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{})
	require.NoError(t, err)
	parsed, _ := url.Parse(authURL)
	q := parsed.Query()
	// Provider signs an id_token with a DIFFERENT nonce than what the
	// backend persisted — must be rejected.
	fp.nonce = "intruder-nonce"
	fp.expectedCode = "the-code-4"
	fp.expectedVerify = mustVerifierFor(t, q.Get("code_challenge"), state.authRequests[q.Get("state")])

	_, err = svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, q.Get("state"))
	require.Error(t, err)
}

func TestE2E_ReusedStateRejected(t *testing.T) {
	fp := startFakeProvider(t)
	defer fp.close()
	fp.subject = "google-sub-replay"
	fp.email = "eve@example.com"
	fp.emailVerified = true

	users := newMockUsers()
	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, fakeReg{enabled: true}, &fakeInvitations{})

	in := basicCreateInput()
	iss := fp.server.URL
	in.IssuerURL = &iss
	in.ClientID = "test-client"
	in.ClientSecret = "test-secret"
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)
	fp.clientID = provider.ClientID

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{})
	require.NoError(t, err)
	parsed, _ := url.Parse(authURL)
	q := parsed.Query()
	stateParam := q.Get("state")
	fp.nonce = q.Get("nonce")
	fp.expectedCode = "the-code-5"
	fp.expectedVerify = mustVerifierFor(t, q.Get("code_challenge"), state.authRequests[stateParam])

	_, err = svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, stateParam)
	require.NoError(t, err)

	// Same state, second call — must fail (delete-on-read).
	_, err = svc.ProcessCallback(context.Background(), provider.Name, fp.expectedCode, stateParam)
	require.Error(t, err)
}

// mustVerifierFor looks up the verifier stored against the auth request
// and asserts its S256 challenge matches the URL parameter (so the test
// stays honest about PKCE).
func mustVerifierFor(t *testing.T, expectedChallenge string, req *model.FederationAuthRequest) string {
	t.Helper()
	require.NotNil(t, req)
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	actual := base64.RawURLEncoding.EncodeToString(sum[:])
	require.Equal(t, expectedChallenge, actual, "PKCE challenge derived from stored verifier must match URL")
	return req.CodeVerifier
}
