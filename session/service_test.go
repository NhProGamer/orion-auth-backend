package session

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg/clock"
	"orion-auth-backend/testutil"
)

// --- Mock Repository ---

type mockSessionRepo struct {
	createFn           func(s *model.Session) error
	findByIDFn         func(id uuid.UUID) (*model.Session, error)
	findActiveByUserFn func(userID uuid.UUID) ([]model.Session, error)
	revokeFn           func(id uuid.UUID) error
	revokeAllForUserFn func(userID uuid.UUID, exceptID *uuid.UUID) (int64, error)
	updateLastActiveFn func(id uuid.UUID) error
}

func (m *mockSessionRepo) Create(s *model.Session) error {
	if m.createFn != nil {
		return m.createFn(s)
	}
	return nil
}

func (m *mockSessionRepo) FindByID(id uuid.UUID) (*model.Session, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(id)
	}
	return nil, nil
}

func (m *mockSessionRepo) FindActiveByUser(userID uuid.UUID) ([]model.Session, error) {
	if m.findActiveByUserFn != nil {
		return m.findActiveByUserFn(userID)
	}
	return nil, nil
}

func (m *mockSessionRepo) Revoke(id uuid.UUID) error {
	if m.revokeFn != nil {
		return m.revokeFn(id)
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllForUser(userID uuid.UUID, exceptID *uuid.UUID) (int64, error) {
	if m.revokeAllForUserFn != nil {
		return m.revokeAllForUserFn(userID, exceptID)
	}
	return 0, nil
}

func (m *mockSessionRepo) UpdateLastActive(id uuid.UUID) error {
	if m.updateLastActiveFn != nil {
		return m.updateLastActiveFn(id)
	}
	return nil
}

// --- Helpers ---

func newTestService(repo *mockSessionRepo) *Service {
	return NewService(repo, testutil.TestAuthConfig())
}

func makeSession(userID uuid.UUID) *model.Session {
	id, _ := uuid.NewV7()
	ip := "127.0.0.1"
	ua := "TestBrowser/1.0"
	return &model.Session{
		ID:              id,
		UserID:          userID,
		IPAddress:       &ip,
		UserAgent:       &ua,
		LastActiveAt:    time.Now(),
		AuthenticatedAt: time.Now(),
		ExpiresAt:       time.Now().Add(24 * time.Hour),
	}
}

// --- Create Tests ---

func TestCreate_Success(t *testing.T) {
	var created *model.Session
	repo := &mockSessionRepo{
		createFn: func(s *model.Session) error {
			created = s
			return nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	sess, err := svc.Create(CreateInput{
		UserID:    userID,
		IPAddress: "10.0.0.1",
		UserAgent: "TestAgent/1.0",
	})

	require.NoError(t, err)
	assert.NotNil(t, sess)
	assert.Equal(t, userID, created.UserID)
	assert.NotEqual(t, uuid.Nil, created.ID)
	assert.NotNil(t, created.IPAddress)
	assert.Equal(t, "10.0.0.1", *created.IPAddress)
	assert.False(t, created.ExpiresAt.IsZero())
}

func TestCreate_DefaultTTL(t *testing.T) {
	var created *model.Session
	repo := &mockSessionRepo{
		createFn: func(s *model.Session) error {
			created = s
			return nil
		},
	}
	svc := newTestService(repo)

	before := time.Now()
	userID, _ := uuid.NewV7()
	_, err := svc.Create(CreateInput{UserID: userID})
	require.NoError(t, err)

	cfg := testutil.TestAuthConfig()
	delta := created.ExpiresAt.Sub(before)
	assert.GreaterOrEqual(t, delta, cfg.SessionTTL-time.Second)
	assert.LessOrEqual(t, delta, cfg.SessionTTL+time.Second)
}

// TestCreate_UsesInjectedClock pins the contract that session creation's
// ExpiresAt is computed from the injected clock. Replaces the previous
// "before / after" wall-clock window with an exact equality assertion.
func TestCreate_UsesInjectedClock(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fake := clock.NewFake(t0)

	var created *model.Session
	repo := &mockSessionRepo{
		createFn: func(s *model.Session) error {
			created = s
			return nil
		},
	}
	svc := newTestService(repo)
	svc.SetClock(fake)

	userID, _ := uuid.NewV7()
	_, err := svc.Create(CreateInput{UserID: userID})
	require.NoError(t, err)

	cfg := testutil.TestAuthConfig()
	wantExpiry := t0.Add(cfg.SessionTTL)
	assert.True(t, created.ExpiresAt.Equal(wantExpiry),
		"ExpiresAt = %v, want exactly %v", created.ExpiresAt, wantExpiry)
}

// TestIsActive_UsesInjectedClock verifies the active-session predicate
// trips on the injected clock — relevant for middleware.BearerAuth which
// gates user-bound tokens behind this exact check.
func TestIsActive_UsesInjectedClock(t *testing.T) {
	expiry := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sess := &model.Session{ExpiresAt: expiry}
	repo := &mockSessionRepo{findByIDFn: func(id uuid.UUID) (*model.Session, error) {
		return sess, nil
	}}
	svc := newTestService(repo)
	fake := clock.NewFake(expiry.Add(-time.Second))
	svc.SetClock(fake)

	id, _ := uuid.NewV7()
	active, err := svc.IsActive(id)
	require.NoError(t, err)
	assert.True(t, active, "session should be active 1s before expiry")

	fake.Set(expiry.Add(time.Nanosecond))
	active, err = svc.IsActive(id)
	require.NoError(t, err)
	assert.False(t, active, "session should be inactive 1ns after expiry")
}

func TestCreate_ExtendedTTL(t *testing.T) {
	var created *model.Session
	repo := &mockSessionRepo{
		createFn: func(s *model.Session) error {
			created = s
			return nil
		},
	}
	svc := newTestService(repo)

	before := time.Now()
	userID, _ := uuid.NewV7()
	_, err := svc.Create(CreateInput{UserID: userID, Extended: true})
	require.NoError(t, err)

	cfg := testutil.TestAuthConfig()
	delta := created.ExpiresAt.Sub(before)
	assert.GreaterOrEqual(t, delta, cfg.SessionExtendedTTL-time.Second)
	assert.LessOrEqual(t, delta, cfg.SessionExtendedTTL+time.Second)
}

// --- ListActive Tests ---

func TestListActive_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	s1 := makeSession(userID)
	s2 := makeSession(userID)
	repo := &mockSessionRepo{
		findActiveByUserFn: func(_ uuid.UUID) ([]model.Session, error) {
			return []model.Session{*s1, *s2}, nil
		},
	}
	svc := newTestService(repo)

	sessions, err := svc.ListActive(userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

// --- Revoke Tests ---

func TestRevoke_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	sess := makeSession(userID)
	revoked := false
	repo := &mockSessionRepo{
		findByIDFn: func(_ uuid.UUID) (*model.Session, error) {
			return sess, nil
		},
		revokeFn: func(_ uuid.UUID) error {
			revoked = true
			return nil
		},
	}
	svc := newTestService(repo)

	err := svc.Revoke(sess.ID, userID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevoke_NotFound(t *testing.T) {
	repo := &mockSessionRepo{} // returns nil by default
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	sessionID, _ := uuid.NewV7()
	err := svc.Revoke(sessionID, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRevoke_WrongUser(t *testing.T) {
	ownerID, _ := uuid.NewV7()
	otherID, _ := uuid.NewV7()
	sess := makeSession(ownerID)
	repo := &mockSessionRepo{
		findByIDFn: func(_ uuid.UUID) (*model.Session, error) {
			return sess, nil
		},
	}
	svc := newTestService(repo)

	err := svc.Revoke(sess.ID, otherID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

// --- RevokeAll Tests ---

func TestRevokeAll_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockSessionRepo{
		revokeAllForUserFn: func(_ uuid.UUID, exceptID *uuid.UUID) (int64, error) {
			assert.Nil(t, exceptID)
			return 3, nil
		},
	}
	svc := newTestService(repo)

	count, err := svc.RevokeAll(userID, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestRevokeAll_ExceptCurrent(t *testing.T) {
	userID, _ := uuid.NewV7()
	currentID, _ := uuid.NewV7()
	repo := &mockSessionRepo{
		revokeAllForUserFn: func(_ uuid.UUID, exceptID *uuid.UUID) (int64, error) {
			require.NotNil(t, exceptID)
			assert.Equal(t, currentID, *exceptID)
			return 2, nil
		},
	}
	svc := newTestService(repo)

	count, err := svc.RevokeAll(userID, &currentID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}
