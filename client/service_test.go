package client

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
	"orion-auth-backend/testutil"
)

// --- Mock Repository ---

type mockClientRepo struct {
	createFn       func(c *model.OAuthClient) error
	findByIDFn     func(id uuid.UUID) (*model.OAuthClient, error)
	findActiveByFn func(id uuid.UUID) (*model.OAuthClient, error)
	updateFn       func(c *model.OAuthClient) error
	listFn         func(page, perPage int) ([]model.OAuthClient, int64, error)
	deleteFn       func(id uuid.UUID) error
}

func (m *mockClientRepo) Create(c *model.OAuthClient) error {
	if m.createFn != nil {
		return m.createFn(c)
	}
	return nil
}

func (m *mockClientRepo) FindByID(id uuid.UUID) (*model.OAuthClient, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(id)
	}
	return nil, nil
}

func (m *mockClientRepo) FindActiveByID(id uuid.UUID) (*model.OAuthClient, error) {
	if m.findActiveByFn != nil {
		return m.findActiveByFn(id)
	}
	return nil, nil
}

func (m *mockClientRepo) Update(c *model.OAuthClient) error {
	if m.updateFn != nil {
		return m.updateFn(c)
	}
	return nil
}

func (m *mockClientRepo) List(page, perPage int) ([]model.OAuthClient, int64, error) {
	if m.listFn != nil {
		return m.listFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockClientRepo) Delete(id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(id)
	}
	return nil
}

// --- Helpers ---

func newTestService(repo *mockClientRepo) *Service {
	return NewService(repo, testutil.FastHasher(), nil)
}

func newTestServiceWithHMAC(repo *mockClientRepo, hmacKey []byte) *Service {
	return NewService(repo, testutil.FastHasher(), hmacKey)
}

func makeClient(isPublic bool) *model.OAuthClient {
	id, _ := uuid.NewV7()
	c := &model.OAuthClient{
		BaseModel:       model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Name:            "test-client",
		RedirectURIs:    pq.StringArray{"https://example.com/cb"},
		GrantTypes:      pq.StringArray{"authorization_code"},
		ResponseTypes:   pq.StringArray{"code"},
		Scopes:          pq.StringArray{"openid"},
		TokenAuthMethod: "client_secret_basic",
		IsPublic:        isPublic,
		Active:          true,
	}
	if !isPublic {
		h := "somehash"
		c.SecretHash = &h
	}
	return c
}

// --- Create Tests ---

func TestCreate_ConfidentialClient(t *testing.T) {
	var created *model.OAuthClient
	repo := &mockClientRepo{
		createFn: func(c *model.OAuthClient) error {
			created = c
			return nil
		},
	}
	svc := newTestService(repo)

	resp, err := svc.Create(CreateInput{
		Name:         "my-app",
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.ClientSecret, "confidential client should have a secret")
	assert.NotNil(t, created.SecretHash, "secret hash should be stored")
	assert.False(t, created.IsPublic)
	assert.Equal(t, "client_secret_basic", created.TokenAuthMethod)
}

func TestCreate_PublicClient(t *testing.T) {
	var created *model.OAuthClient
	repo := &mockClientRepo{
		createFn: func(c *model.OAuthClient) error {
			created = c
			return nil
		},
	}
	svc := newTestService(repo)

	resp, err := svc.Create(CreateInput{
		Name:         "spa-app",
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		IsPublic:     true,
	})

	require.NoError(t, err)
	assert.Empty(t, resp.ClientSecret, "public client should have no secret")
	assert.Nil(t, created.SecretHash)
	assert.True(t, created.IsPublic)
	assert.Equal(t, "none", created.TokenAuthMethod)
}

func TestCreate_DefaultResponseTypes(t *testing.T) {
	var created *model.OAuthClient
	repo := &mockClientRepo{
		createFn: func(c *model.OAuthClient) error {
			created = c
			return nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.Create(CreateInput{
		Name:         "my-app",
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		// ResponseTypes intentionally omitted
	})

	require.NoError(t, err)
	assert.Equal(t, pq.StringArray{"code"}, created.ResponseTypes)
}

// --- GetByID Tests ---

func TestGetByID_Success(t *testing.T) {
	expected := makeClient(false)
	repo := &mockClientRepo{
		findByIDFn: func(id uuid.UUID) (*model.OAuthClient, error) {
			return expected, nil
		},
	}
	svc := newTestService(repo)

	got, err := svc.GetByID(expected.ID)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, got.ID)
}

func TestGetByID_NotFound(t *testing.T) {
	repo := &mockClientRepo{} // returns nil by default
	svc := newTestService(repo)

	id, _ := uuid.NewV7()
	_, err := svc.GetByID(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Update Tests ---

func TestUpdate_PartialFields(t *testing.T) {
	existing := makeClient(false)
	repo := &mockClientRepo{
		findByIDFn: func(_ uuid.UUID) (*model.OAuthClient, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo)

	newName := "updated-name"
	got, err := svc.Update(existing.ID, UpdateInput{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "updated-name", got.Name)
	// Unchanged fields should remain
	assert.Equal(t, existing.RedirectURIs, got.RedirectURIs)
}

func TestUpdate_NotFound(t *testing.T) {
	repo := &mockClientRepo{}
	svc := newTestService(repo)

	id, _ := uuid.NewV7()
	newName := "x"
	_, err := svc.Update(id, UpdateInput{Name: &newName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Delete Tests ---

func TestDelete_Success(t *testing.T) {
	existing := makeClient(false)
	deleted := false
	repo := &mockClientRepo{
		findByIDFn: func(_ uuid.UUID) (*model.OAuthClient, error) {
			return existing, nil
		},
		deleteFn: func(_ uuid.UUID) error {
			deleted = true
			return nil
		},
	}
	svc := newTestService(repo)

	err := svc.Delete(existing.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDelete_NotFound(t *testing.T) {
	repo := &mockClientRepo{}
	svc := newTestService(repo)

	id, _ := uuid.NewV7()
	err := svc.Delete(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- RotateSecret Tests ---

func TestRotateSecret_Success(t *testing.T) {
	existing := makeClient(false)
	repo := &mockClientRepo{
		findByIDFn: func(_ uuid.UUID) (*model.OAuthClient, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo)

	secret, err := svc.RotateSecret(existing.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.NotNil(t, existing.SecretHash)
}

func TestRotateSecret_PublicClientRejected(t *testing.T) {
	existing := makeClient(true)
	repo := &mockClientRepo{
		findByIDFn: func(_ uuid.UUID) (*model.OAuthClient, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.RotateSecret(existing.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public client")
}

// --- List Test ---

func TestList(t *testing.T) {
	c1 := makeClient(false)
	c2 := makeClient(true)
	repo := &mockClientRepo{
		listFn: func(page, perPage int) ([]model.OAuthClient, int64, error) {
			return []model.OAuthClient{*c1, *c2}, 2, nil
		},
	}
	svc := newTestService(repo)

	clients, total, err := svc.List(1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, clients, 2)
}
