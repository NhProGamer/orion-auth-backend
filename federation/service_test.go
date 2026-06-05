package federation

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
)

// --- Mock repository ---

type mockRepo struct {
	providers       map[uuid.UUID]*model.FederationProvider
	providersByName map[string]*model.FederationProvider
	links           map[uuid.UUID]*model.FederationLink
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		providers:       map[uuid.UUID]*model.FederationProvider{},
		providersByName: map[string]*model.FederationProvider{},
		links:           map[uuid.UUID]*model.FederationLink{},
	}
}

func (m *mockRepo) CreateProvider(p *model.FederationProvider) error {
	if p.ID == uuid.Nil {
		id, _ := uuid.NewV7()
		p.ID = id
	}
	m.providers[p.ID] = p
	m.providersByName[p.Name] = p
	return nil
}
func (m *mockRepo) FindProviderByID(id uuid.UUID) (*model.FederationProvider, error) {
	return m.providers[id], nil
}
func (m *mockRepo) FindProviderByName(name string) (*model.FederationProvider, error) {
	return m.providersByName[name], nil
}
func (m *mockRepo) ListProviders() ([]model.FederationProvider, error) {
	out := make([]model.FederationProvider, 0, len(m.providers))
	for _, p := range m.providers {
		out = append(out, *p)
	}
	return out, nil
}
func (m *mockRepo) UpdateProvider(p *model.FederationProvider) error {
	m.providers[p.ID] = p
	m.providersByName[p.Name] = p
	return nil
}
func (m *mockRepo) DeleteProvider(id uuid.UUID) error {
	if p, ok := m.providers[id]; ok {
		delete(m.providersByName, p.Name)
	}
	delete(m.providers, id)
	return nil
}
func (m *mockRepo) CreateLink(l *model.FederationLink) error {
	if l.ID == uuid.Nil {
		id, _ := uuid.NewV7()
		l.ID = id
	}
	m.links[l.ID] = l
	return nil
}
func (m *mockRepo) FindLink(providerID uuid.UUID, externalID string) (*model.FederationLink, error) {
	for _, l := range m.links {
		if l.ProviderID == providerID && l.ExternalID == externalID {
			return l, nil
		}
	}
	return nil, nil
}
func (m *mockRepo) FindLinksByUser(userID uuid.UUID) ([]model.FederationLink, error) {
	var out []model.FederationLink
	for _, l := range m.links {
		if l.UserID == userID {
			out = append(out, *l)
		}
	}
	return out, nil
}
func (m *mockRepo) DeleteLink(id uuid.UUID) error { delete(m.links, id); return nil }
func (m *mockRepo) FindLinkByID(id uuid.UUID) (*model.FederationLink, error) {
	return m.links[id], nil
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

// optModifier and the withX helpers below let tests construct a
// federation.Service in one call without re-declaring the full
// Options literal. Mirrors the pattern in user/invitation tests.
type optModifier func(*Options)

func withState(s StateRepositoryInterface) optModifier {
	return func(o *Options) { o.StateRepository = s }
}

func withProvisioning(u UserProvisioner, r RegistrationGate, i InvitationValidator) optModifier {
	return func(o *Options) {
		o.Users = u
		o.Registration = r
		o.Invitations = i
	}
}

func newTestService(t *testing.T, repo RepositoryInterface, mods ...optModifier) *Service {
	t.Helper()
	opts := Options{
		Repo:              repo,
		Issuer:            "https://auth.example.com",
		HMACEncryptionKey: newKey(t),
	}
	for _, m := range mods {
		m(&opts)
	}
	return NewService(opts)
}

func basicCreateInput() CreateProviderInput {
	iss := "https://accounts.example.com"
	return CreateProviderInput{
		Name:         "test-provider",
		Type:         "oidc",
		ClientID:     "client-abc",
		ClientSecret: "super-secret-value",
		IssuerURL:    &iss,
		Scopes:       []string{"openid", "email"},
	}
}

func TestCreateProvider_EncryptsSecret(t *testing.T) {
	key := newKey(t)
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: key})

	p, err := svc.CreateProvider(basicCreateInput())
	require.NoError(t, err)

	assert.NotEmpty(t, p.ClientSecretEncrypted, "encrypted secret must be persisted")
	assert.Nil(t, p.ClientSecret, "plaintext secret must not be set")
	assert.False(t, bytes.Contains(p.ClientSecretEncrypted, []byte("super-secret-value")), "plaintext must not appear in ciphertext")

	got, err := crypto.DecryptHMACSecret(p.ClientSecretEncrypted, key)
	require.NoError(t, err)
	assert.Equal(t, "super-secret-value", string(got))
}

func TestCreateProvider_DefaultMapperApplied(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: newKey(t)})

	p, err := svc.CreateProvider(basicCreateInput())
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(p.AttributeMapper, &m))
	assert.Equal(t, "sub", m["external_id"])
	assert.Equal(t, "email", m["email"])
	assert.Equal(t, "email_verified", m["email_verified"])
	assert.Equal(t, "name", m["name"])
	assert.Equal(t, "picture", m["picture"])
}

func TestCreateProvider_CustomMapperOverrides(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: newKey(t)})

	in := basicCreateInput()
	in.AttributeMapper = json.RawMessage(`{"email":"email_address","name":"full_name"}`)

	p, err := svc.CreateProvider(in)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(p.AttributeMapper, &m))
	assert.Equal(t, "email_address", m["email"])
	assert.Equal(t, "full_name", m["name"])
}

func TestCreateProvider_RejectsUnknownMapperKey(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: newKey(t)})

	in := basicCreateInput()
	in.AttributeMapper = json.RawMessage(`{"username":"preferred_username"}`)

	_, err := svc.CreateProvider(in)
	require.Error(t, err)
}

func TestCreateProvider_RequiresEncryptionKey(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com"})

	_, err := svc.CreateProvider(basicCreateInput())
	require.Error(t, err, "must reject creation when no AES key is configured")
}

func TestUpdateProvider_ReSealsSecretAndClearsPlaintext(t *testing.T) {
	key := newKey(t)
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: key})

	p, err := svc.CreateProvider(basicCreateInput())
	require.NoError(t, err)

	// Simulate a legacy plaintext row alongside the encrypted blob.
	legacy := "legacy-plaintext"
	p.ClientSecret = &legacy
	require.NoError(t, repo.UpdateProvider(p))

	newSecret := "rotated-secret-v2"
	updated, err := svc.UpdateProvider(p.ID, UpdateProviderInput{ClientSecret: &newSecret})
	require.NoError(t, err)

	assert.Nil(t, updated.ClientSecret, "plaintext must be cleared after rotation")
	got, err := crypto.DecryptHMACSecret(updated.ClientSecretEncrypted, key)
	require.NoError(t, err)
	assert.Equal(t, newSecret, string(got))
}

func TestUpdateProvider_PreservesSecretWhenOmitted(t *testing.T) {
	key := newKey(t)
	repo := newMockRepo()
	svc := NewService(Options{Repo: repo, Issuer: "https://auth.example.com", HMACEncryptionKey: key})

	p, err := svc.CreateProvider(basicCreateInput())
	require.NoError(t, err)
	before := append([]byte(nil), p.ClientSecretEncrypted...)

	syncOn := true
	_, err = svc.UpdateProvider(p.ID, UpdateProviderInput{SyncOnLogin: &syncOn})
	require.NoError(t, err)

	got, _ := repo.FindProviderByID(p.ID)
	assert.Equal(t, before, got.ClientSecretEncrypted, "secret bytes must not change when ClientSecret is omitted")
	assert.True(t, got.SyncOnLogin)
}

func TestRevealSecret_PrefersEncryptedFallsBackToPlaintext(t *testing.T) {
	key := newKey(t)
	svc := NewService(Options{Repo: newMockRepo(), Issuer: "https://auth.example.com", HMACEncryptionKey: key})

	// Encrypted only.
	sealed, err := crypto.EncryptHMACSecret([]byte("from-encrypted"), key)
	require.NoError(t, err)
	enc, err := svc.RevealSecret(&model.FederationProvider{ClientSecretEncrypted: sealed})
	require.NoError(t, err)
	assert.Equal(t, "from-encrypted", enc)

	// Plaintext fallback (legacy row).
	plain := "from-plaintext"
	pl, err := svc.RevealSecret(&model.FederationProvider{ClientSecret: &plain})
	require.NoError(t, err)
	assert.Equal(t, "from-plaintext", pl)

	// Neither set → error.
	_, err = svc.RevealSecret(&model.FederationProvider{})
	require.Error(t, err)
}
