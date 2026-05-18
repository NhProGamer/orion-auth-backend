package reauth

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
)

// --- mocks ---

type mockRepo struct {
	tokens   map[string]*model.ReauthToken
	createFn func(*model.ReauthToken) error
}

func newMockRepo() *mockRepo { return &mockRepo{tokens: map[string]*model.ReauthToken{}} }

func (m *mockRepo) Create(t *model.ReauthToken) error {
	if m.createFn != nil {
		return m.createFn(t)
	}
	m.tokens[t.ID] = t
	return nil
}
func (m *mockRepo) FindByHash(hash string) (*model.ReauthToken, error) {
	if t, ok := m.tokens[hash]; ok {
		return t, nil
	}
	return nil, nil
}
func (m *mockRepo) MarkUsed(hash, consumedBy string) error {
	t, ok := m.tokens[hash]
	if !ok {
		return nil
	}
	now := time.Now()
	t.Used = true
	t.UsedAt = &now
	t.ConsumedBy = &consumedBy
	return nil
}
func (m *mockRepo) DeleteExpired() (int64, error) {
	n := int64(0)
	now := time.Now()
	for k, t := range m.tokens {
		if t.ExpiresAt.Before(now) {
			delete(m.tokens, k)
			n++
		}
	}
	return n, nil
}
func (m *mockRepo) DeleteForSession(sessionID uuid.UUID) error {
	for k, t := range m.tokens {
		if t.SessionID == sessionID {
			delete(m.tokens, k)
		}
	}
	return nil
}

type mockPasswordVerifier struct {
	password string
}

func (m *mockPasswordVerifier) VerifyPassword(_ uuid.UUID, password string) (bool, error) {
	return password == m.password, nil
}

type mockMFA struct {
	hasMFA bool
	valid  string
}

func (m *mockMFA) ValidateCode(_ uuid.UUID, code string) (bool, error) {
	return code == m.valid, nil
}
func (m *mockMFA) HasMFA(_ uuid.UUID) (bool, error) { return m.hasMFA, nil }

// --- tests ---

func TestIssue_PasswordHappyPath(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "hunter2"}, 10*time.Minute)

	uid := uuid.New()
	sid := uuid.New()

	resp, err := svc.Issue(uid, sid, IssueRequest{Method: MethodPassword, Password: "hunter2"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, MethodPassword, resp.Method)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), resp.ExpiresAt, 5*time.Second)

	hash := crypto.HashToken(resp.Token)
	stored := repo.tokens[hash]
	require.NotNil(t, stored)
	assert.Equal(t, uid, stored.UserID)
	assert.Equal(t, sid, stored.SessionID)
	assert.False(t, stored.Used)
}

func TestIssue_PasswordWrong(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "good"}, 10*time.Minute)

	_, err := svc.Issue(uuid.New(), uuid.New(), IssueRequest{Method: MethodPassword, Password: "bad"})
	assert.Error(t, err)
	assert.Empty(t, repo.tokens, "no token should be persisted on failed verification")
}

func TestIssue_TOTPHappyPath(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{}, 10*time.Minute)
	svc.SetMFAValidator(&mockMFA{hasMFA: true, valid: "123456"})

	_, err := svc.Issue(uuid.New(), uuid.New(), IssueRequest{Method: MethodTOTP, Code: "123456"})
	require.NoError(t, err)
}

func TestIssue_TOTPNotEnrolled(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{}, 10*time.Minute)
	svc.SetMFAValidator(&mockMFA{hasMFA: false})

	_, err := svc.Issue(uuid.New(), uuid.New(), IssueRequest{Method: MethodTOTP, Code: "123456"})
	assert.Error(t, err)
}

func TestIssue_UnsupportedMethod(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "x"}, 10*time.Minute)

	_, err := svc.Issue(uuid.New(), uuid.New(), IssueRequest{Method: "carrier_pigeon"})
	assert.Error(t, err)
}

func TestVerify_HappyPath(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 10*time.Minute)

	uid := uuid.New()
	sid := uuid.New()
	resp, _ := svc.Issue(uid, sid, IssueRequest{Method: MethodPassword, Password: "p"})

	got, err := svc.Verify(resp.Token, uid, sid)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, got.Used)
}

func TestVerify_WrongSession(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 10*time.Minute)

	uid := uuid.New()
	sid := uuid.New()
	resp, _ := svc.Issue(uid, sid, IssueRequest{Method: MethodPassword, Password: "p"})

	got, err := svc.Verify(resp.Token, uid, uuid.New())
	require.NoError(t, err)
	assert.Nil(t, got, "token must be rejected when session differs")
}

func TestVerify_Expired(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 1*time.Nanosecond)

	uid := uuid.New()
	sid := uuid.New()
	resp, _ := svc.Issue(uid, sid, IssueRequest{Method: MethodPassword, Password: "p"})
	time.Sleep(5 * time.Millisecond)

	got, err := svc.Verify(resp.Token, uid, sid)
	require.NoError(t, err)
	assert.Nil(t, got, "expired token must not verify")
}

func TestVerify_AfterConsume_SingleUse(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 10*time.Minute)

	uid := uuid.New()
	sid := uuid.New()
	resp, _ := svc.Issue(uid, sid, IssueRequest{Method: MethodPassword, Password: "p"})

	first, err := svc.Verify(resp.Token, uid, sid)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NoError(t, svc.Consume(first.ID, "test.action"))

	second, err := svc.Verify(resp.Token, uid, sid)
	require.NoError(t, err)
	assert.Nil(t, second, "consumed token must not verify a second time")
}

func TestRevokeForSession_DeletesAllSessionTokens(t *testing.T) {
	repo := newMockRepo()
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 10*time.Minute)

	uid := uuid.New()
	sid1 := uuid.New()
	sid2 := uuid.New()
	_, _ = svc.Issue(uid, sid1, IssueRequest{Method: MethodPassword, Password: "p"})
	_, _ = svc.Issue(uid, sid1, IssueRequest{Method: MethodPassword, Password: "p"})
	_, _ = svc.Issue(uid, sid2, IssueRequest{Method: MethodPassword, Password: "p"})
	require.Len(t, repo.tokens, 3)

	require.NoError(t, svc.RevokeForSession(sid1))
	assert.Len(t, repo.tokens, 1)
}

func TestIssue_RepoError(t *testing.T) {
	repo := newMockRepo()
	repo.createFn = func(*model.ReauthToken) error { return errors.New("db down") }
	svc := NewService(repo, &mockPasswordVerifier{password: "p"}, 10*time.Minute)

	_, err := svc.Issue(uuid.New(), uuid.New(), IssueRequest{Method: MethodPassword, Password: "p"})
	assert.Error(t, err)
}
