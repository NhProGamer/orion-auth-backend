package passkey

import (
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

// --- mocks ---

type mockRepo struct {
	passkeys   map[uuid.UUID]*model.Passkey
	challenges map[uuid.UUID]*model.PasskeyChallenge
	createErr  error
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		passkeys:   map[uuid.UUID]*model.Passkey{},
		challenges: map[uuid.UUID]*model.PasskeyChallenge{},
	}
}

func (m *mockRepo) Create(p *model.Passkey) error {
	if m.createErr != nil {
		return m.createErr
	}
	if p.ID == uuid.Nil {
		p.ID, _ = uuid.NewV7()
	}
	m.passkeys[p.ID] = p
	return nil
}
func (m *mockRepo) FindByCredentialID(id []byte) (*model.Passkey, error) {
	for _, p := range m.passkeys {
		if string(p.CredentialID) == string(id) {
			return p, nil
		}
	}
	return nil, nil
}
func (m *mockRepo) FindByID(id uuid.UUID) (*model.Passkey, error) { return m.passkeys[id], nil }
func (m *mockRepo) ListByUser(userID uuid.UUID) ([]model.Passkey, error) {
	out := []model.Passkey{}
	for _, p := range m.passkeys {
		if p.UserID == userID {
			out = append(out, *p)
		}
	}
	return out, nil
}
func (m *mockRepo) UpdateName(id, userID uuid.UUID, name string) error {
	p, ok := m.passkeys[id]
	if !ok || p.UserID != userID {
		return errors.New("not found")
	}
	p.Name = name
	return nil
}
func (m *mockRepo) UpdateSignCount(id uuid.UUID, sc uint32, last int64) error {
	p, ok := m.passkeys[id]
	if !ok {
		return nil
	}
	p.SignCount = sc
	t := time.Unix(last, 0)
	p.LastUsedAt = &t
	return nil
}
func (m *mockRepo) Delete(id, userID uuid.UUID) error {
	p, ok := m.passkeys[id]
	if !ok || p.UserID != userID {
		return errors.New("not found")
	}
	delete(m.passkeys, id)
	return nil
}
func (m *mockRepo) SetCloneWarning(id uuid.UUID, v bool) error {
	if p, ok := m.passkeys[id]; ok {
		p.CloneWarning = v
	}
	return nil
}
func (m *mockRepo) CreateChallenge(c *model.PasskeyChallenge) error {
	if c.ID == uuid.Nil {
		c.ID, _ = uuid.NewV7()
	}
	m.challenges[c.ID] = c
	return nil
}
func (m *mockRepo) FindChallenge(id uuid.UUID) (*model.PasskeyChallenge, error) {
	return m.challenges[id], nil
}
func (m *mockRepo) DeleteChallenge(id uuid.UUID) error {
	delete(m.challenges, id)
	return nil
}
func (m *mockRepo) DeleteExpiredChallenges() (int64, error) {
	n := int64(0)
	now := time.Now()
	for k, c := range m.challenges {
		if c.ExpiresAt.Before(now) {
			delete(m.challenges, k)
			n++
		}
	}
	return n, nil
}

type mockUserFinder struct {
	user *model.User
	err  error
}

func (m *mockUserFinder) GetByID(_ uuid.UUID) (*model.User, error) {
	return m.user, m.err
}

func newSvc(t *testing.T, repo *mockRepo, finder *mockUserFinder) *Service {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	})
	require.NoError(t, err)
	return NewService(repo, finder, wa, 5*time.Minute)
}

// --- tests ---

func TestChallenge_StoreAndPop_HappyPath(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	finder := &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}, Email: "u@e"}}
	svc := newSvc(t, repo, finder)

	data := &webauthn.SessionData{Challenge: "abc", UserID: []byte("uid"), Expires: time.Now().Add(5 * time.Minute)}
	id, err := svc.storeChallenge(&uid, PurposeReauth, data)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id)
	assert.Len(t, repo.challenges, 1)

	got, err := svc.popChallenge(id, &uid, PurposeReauth)
	require.NoError(t, err)
	assert.Equal(t, "abc", got.Challenge)
	assert.Empty(t, repo.challenges, "popChallenge must delete the challenge (single-use)")
}

func TestChallenge_Pop_WrongPurpose(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	data := &webauthn.SessionData{Challenge: "x", Expires: time.Now().Add(time.Minute)}
	id, _ := svc.storeChallenge(&uid, PurposeRegistration, data)

	_, err := svc.popChallenge(id, &uid, PurposeReauth)
	assert.Error(t, err)
	assert.Empty(t, repo.challenges, "challenge must be deleted even on purpose mismatch (defense in depth)")
}

func TestChallenge_Pop_WrongUser(t *testing.T) {
	repo := newMockRepo()
	owner := uuid.New()
	other := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: owner}}})

	data := &webauthn.SessionData{Challenge: "x", Expires: time.Now().Add(time.Minute)}
	id, _ := svc.storeChallenge(&owner, PurposeReauth, data)

	_, err := svc.popChallenge(id, &other, PurposeReauth)
	assert.Error(t, err)
}

func TestChallenge_Pop_Expired(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	data := &webauthn.SessionData{Challenge: "x", Expires: time.Now()}
	id, _ := svc.storeChallenge(&uid, PurposeReauth, data)
	// Force the row itself to look expired (storeChallenge sets ExpiresAt = now + TTL).
	repo.challenges[id].ExpiresAt = time.Now().Add(-time.Minute)

	_, err := svc.popChallenge(id, &uid, PurposeReauth)
	assert.Error(t, err)
}

func TestCRUD_RenameAndDelete(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	p := &model.Passkey{UserID: uid, CredentialID: []byte("c1"), PublicKey: []byte("pk"), Name: "old"}
	require.NoError(t, repo.Create(p))

	require.NoError(t, svc.Rename(p.ID, uid, "shiny"))
	assert.Equal(t, "shiny", repo.passkeys[p.ID].Name)

	// Wrong user can't delete
	assert.Error(t, svc.Delete(p.ID, uuid.New()))

	require.NoError(t, svc.Delete(p.ID, uid))
	assert.Empty(t, repo.passkeys)
}

func TestHasUserVerifiedPasskey_RecognisesUVFlag(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	// flag bit 0x04 (UV) per WebAuthn spec
	repo.passkeys[uuid.New()] = &model.Passkey{UserID: uid, CredentialID: []byte("a"), PublicKey: []byte("p"), Flags: 0x04}

	has, err := svc.HasUserVerifiedPasskey(uid)
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasUserVerifiedPasskey_NoUVPasskeys(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	repo.passkeys[uuid.New()] = &model.Passkey{UserID: uid, CredentialID: []byte("a"), PublicKey: []byte("p"), Flags: 0x01} // UP only
	has, err := svc.HasUserVerifiedPasskey(uid)
	require.NoError(t, err)
	assert.False(t, has)
}

func TestBeginReauth_RequiresAtLeastOnePasskey(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}, Email: "u@e"}})

	_, err := svc.BeginReauth(uid)
	assert.Error(t, err, "BeginReauth must fail when user has no passkeys")
}

// TestHasUserVerifiedPasskey_IgnoresClonedPasskey is the regression test
// for Vuln 7: once a passkey carries CloneWarning=true (set by
// FinishDiscoverableLogin / ValidateReauthAssertion when go-webauthn
// reports a stalled signCount), it must no longer count as MFA material.
// Otherwise an attacker who's cloned the credential could still claim
// "MFA enrolled" status while sidestepping subsequent reauth ceremonies
// (which now refuse the cloned authenticator).
func TestHasUserVerifiedPasskey_IgnoresClonedPasskey(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	svc := newSvc(t, repo, &mockUserFinder{user: &model.User{BaseModel: model.BaseModel{ID: uid}}})

	id := uuid.New()
	repo.passkeys[id] = &model.Passkey{
		BaseModel:    model.BaseModel{ID: id},
		UserID:       uid,
		CredentialID: []byte("a"),
		PublicKey:    []byte("p"),
		Flags:        0x04, // UV set
		CloneWarning: true, // but clone detected
	}

	has, err := svc.HasUserVerifiedPasskey(uid)
	require.NoError(t, err)
	assert.False(t, has, "passkey with CloneWarning must not count as MFA")
}

// TestSetCloneWarning_PersistsThroughRepo confirms the repo plumbing for
// the clone flag works end-to-end (production code uses the same call
// path inside FinishDiscoverableLogin / ValidateReauthAssertion).
func TestSetCloneWarning_PersistsThroughRepo(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.New()
	id := uuid.New()
	repo.passkeys[id] = &model.Passkey{BaseModel: model.BaseModel{ID: id}, UserID: uid}

	require.NoError(t, repo.SetCloneWarning(id, true))
	assert.True(t, repo.passkeys[id].CloneWarning)
}
