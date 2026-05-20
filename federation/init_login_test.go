package federation

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

// mockStateRepo implements StateRepositoryInterface in-memory.
type mockStateRepo struct {
	authRequests   map[string]*model.FederationAuthRequest
	pending        map[string]*model.FederationPendingLink
	pendingSignups map[string]*model.FederationPendingSignup
}

func newMockStateRepo() *mockStateRepo {
	return &mockStateRepo{
		authRequests:   map[string]*model.FederationAuthRequest{},
		pending:        map[string]*model.FederationPendingLink{},
		pendingSignups: map[string]*model.FederationPendingSignup{},
	}
}
func (m *mockStateRepo) InsertAuthRequest(req *model.FederationAuthRequest) error {
	m.authRequests[req.State] = req
	return nil
}
func (m *mockStateRepo) ConsumeAuthRequest(state string) (*model.FederationAuthRequest, error) {
	req := m.authRequests[state]
	delete(m.authRequests, state)
	return req, nil
}
func (m *mockStateRepo) DeleteExpiredAuthRequests() (int64, error) { return 0, nil }
func (m *mockStateRepo) InsertPendingLink(p *model.FederationPendingLink) error {
	m.pending[p.TokenHash] = p
	return nil
}
func (m *mockStateRepo) ConsumePendingLink(tokenHash string) (*model.FederationPendingLink, error) {
	p := m.pending[tokenHash]
	delete(m.pending, tokenHash)
	return p, nil
}
func (m *mockStateRepo) DeleteExpiredPendingLinks() (int64, error) { return 0, nil }
func (m *mockStateRepo) InsertPendingSignup(p *model.FederationPendingSignup) error {
	m.pendingSignups[p.TokenHash] = p
	return nil
}
func (m *mockStateRepo) ConsumePendingSignup(tokenHash string) (*model.FederationPendingSignup, error) {
	p := m.pendingSignups[tokenHash]
	delete(m.pendingSignups, tokenHash)
	return p, nil
}
func (m *mockStateRepo) GetPendingSignup(tokenHash string) (*model.FederationPendingSignup, error) {
	return m.pendingSignups[tokenHash], nil
}
func (m *mockStateRepo) DeleteExpiredPendingSignups() (int64, error) { return 0, nil }

func TestInitSocialLogin_GeneratesStatePKCEAndNonce(t *testing.T) {
	srv := mockOIDCServer(t)
	defer srv.Close()

	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)

	in := basicCreateInput()
	iss := srv.URL
	in.IssuerURL = &iss
	provider, err := svc.CreateProvider(in)
	require.NoError(t, err)

	authURL, err := svc.InitSocialLogin(context.Background(), provider.Name, InitOptions{
		ReturnTo:  "https://auth.example.com/ui/home",
		IPAddress: "127.0.0.1",
		UserAgent: "go-test",
	})
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	assert.NotEmpty(t, q.Get("state"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("nonce"))
	assert.Equal(t, provider.ClientID, q.Get("client_id"))
	assert.Equal(t, "code", q.Get("response_type"))

	// State must be persisted with the matching verifier/nonce.
	saved := state.authRequests[q.Get("state")]
	require.NotNil(t, saved, "auth request must be persisted")
	assert.Equal(t, provider.ID, saved.ProviderID)
	assert.Equal(t, q.Get("nonce"), saved.Nonce)
	assert.NotEmpty(t, saved.CodeVerifier)
	assert.Equal(t, pkceS256Challenge(saved.CodeVerifier), q.Get("code_challenge"))
	assert.False(t, saved.ExpiresAt.IsZero())
	require.NotNil(t, saved.ReturnTo)
	assert.Equal(t, "https://auth.example.com/ui/home", *saved.ReturnTo)
}

func TestInitSocialLogin_RequiresStateRepo(t *testing.T) {
	srv := mockOIDCServer(t)
	defer srv.Close()

	repo := newMockRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	// Intentionally do not call SetStateRepository.

	in := basicCreateInput()
	iss := srv.URL
	in.IssuerURL = &iss
	_, err := svc.CreateProvider(in)
	require.NoError(t, err)

	_, err = svc.InitSocialLogin(context.Background(), "test-provider", InitOptions{})
	require.Error(t, err)
}

func TestInitSocialLogin_UnknownProviderRejected(t *testing.T) {
	svc := NewService(newMockRepo(), "https://auth.example.com", newKey(t))
	svc.SetStateRepository(newMockStateRepo())
	_, err := svc.InitSocialLogin(context.Background(), "does-not-exist", InitOptions{})
	require.Error(t, err)
}

func TestInitSocialLogin_PersistsContinuationContext(t *testing.T) {
	srv := mockOIDCServer(t)
	defer srv.Close()

	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)

	in := basicCreateInput()
	iss := srv.URL
	in.IssuerURL = &iss
	_, err := svc.CreateProvider(in)
	require.NoError(t, err)

	rid, _ := uuid.NewV7()
	_, err = svc.InitSocialLogin(context.Background(), "test-provider", InitOptions{
		ReturnTo:        "https://app.example.com/back",
		OAuthRequestID:  &rid,
		InvitationToken: "inv-abc-123",
	})
	require.NoError(t, err)

	require.Len(t, state.authRequests, 1)
	for _, saved := range state.authRequests {
		require.NotNil(t, saved.OAuthRequestID)
		assert.Equal(t, rid, *saved.OAuthRequestID)
		require.NotNil(t, saved.InvitationToken)
		assert.Equal(t, "inv-abc-123", *saved.InvitationToken)
		require.NotNil(t, saved.ReturnTo)
		assert.Equal(t, "https://app.example.com/back", *saved.ReturnTo)
	}
}
