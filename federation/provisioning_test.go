package federation

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

// --- Mock UserProvisioner ---

type mockUsers struct {
	byEmail        map[string]*model.User
	byID           map[uuid.UUID]*model.User
	createdInputs  []user.FederationProvisionInput
	passwordOK     bool
	passwordErr    error
	verifyPwdCalls int
}

func newMockUsers() *mockUsers {
	return &mockUsers{
		byEmail: map[string]*model.User{},
		byID:    map[uuid.UUID]*model.User{},
	}
}
func (m *mockUsers) addUser(u *model.User) {
	m.byEmail[u.Email] = u
	m.byID[u.ID] = u
}
func (m *mockUsers) FindByEmail(email string) (*model.User, error) {
	return m.byEmail[email], nil
}
func (m *mockUsers) GetByID(id uuid.UUID) (*model.User, error) {
	return m.byID[id], nil
}
func (m *mockUsers) CreateFromFederation(in user.FederationProvisionInput, roleIDs []uuid.UUID) (*model.User, error) {
	id, _ := uuid.NewV7()
	hash := "fed-hash:" + in.Password
	u := &model.User{
		BaseModel:       model.BaseModel{ID: id},
		Email:           in.Email,
		EmailVerified:   in.EmailVerified,
		PasswordHash:    &hash,
		MustSetPassword: false,
		Active:          true,
	}
	m.addUser(u)
	m.createdInputs = append(m.createdInputs, in)
	return u, nil
}
func (m *mockUsers) VerifyPassword(id uuid.UUID, password string) (bool, error) {
	m.verifyPwdCalls++
	return m.passwordOK, m.passwordErr
}

// --- Mock registration / invitations ---

type fakeReg struct{ enabled bool }

func (f fakeReg) IsRegistrationEnabled() bool { return f.enabled }

type fakeInvitations struct {
	byToken  map[string]*model.Invitation
	consumed []*model.Invitation
}

func (f *fakeInvitations) ValidateToken(token string) (*model.Invitation, error) {
	return f.byToken[token], nil
}
func (f *fakeInvitations) ConsumeToken(inv *model.Invitation) error {
	f.consumed = append(f.consumed, inv)
	return nil
}

// --- Helpers ---

func makeProvider(t *testing.T, allowConfirm bool) *model.FederationProvider {
	t.Helper()
	id, _ := uuid.NewV7()
	iss := "https://accounts.example.com"
	return &model.FederationProvider{
		BaseModel:             model.BaseModel{ID: id},
		Name:                  "test",
		Type:                  ProviderTypeOIDC,
		ClientID:              "client",
		IssuerURL:             &iss,
		AllowLinkConfirmation: allowConfirm,
	}
}

func makeAuthRequest(provider *model.FederationProvider, invToken string) *model.FederationAuthRequest {
	req := &model.FederationAuthRequest{
		State:      "stateX",
		ProviderID: provider.ID,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	if invToken != "" {
		t := invToken
		req.InvitationToken = &t
	}
	return req
}

func newService(t *testing.T, users UserProvisioner, reg RegistrationGate, inv InvitationValidator) (*Service, *mockRepo, *mockStateRepo) {
	t.Helper()
	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)
	svc.SetProvisioningDependencies(users, reg, inv)
	return svc, repo, state
}

// --- Tests ---

func TestFindOrProvisionUser_ExistingLinkLogsInDirectly(t *testing.T) {
	users := newMockUsers()
	existingID, _ := uuid.NewV7()
	hash := "h"
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: existingID}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	provider := makeProvider(t, false)

	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))
	require.NoError(t, repo.CreateLink(&model.FederationLink{
		UserID: existingID, ProviderID: provider.ID, ExternalID: "ext-1",
	}))

	out, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, ProvisionLoginExisting, out.Kind)
	require.NotNil(t, out.User)
	assert.Equal(t, existingID, out.User.ID)
}

func TestFindOrProvisionUser_EmailMatchWithoutAutoLinkRejected(t *testing.T) {
	users := newMockUsers()
	hash := "h"
	id, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: id}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	provider := makeProvider(t, false) // AllowLinkConfirmation off

	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	_, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com", EmailVerified: true},
	})
	require.Error(t, err)
}

func TestFindOrProvisionUser_EmailMatchWithoutLocalPasswordRejected(t *testing.T) {
	users := newMockUsers()
	id, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: id}, Email: "alice@example.com", PasswordHash: nil, MustSetPassword: true, Active: true})
	provider := makeProvider(t, true) // AllowLinkConfirmation on

	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	_, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})
	require.Error(t, err, "user without local password cannot complete a confirmation challenge")
}

func TestFindOrProvisionUser_EmailMatchStagesPendingLink(t *testing.T) {
	users := newMockUsers()
	hash := "h"
	id, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: id}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	provider := makeProvider(t, true)

	svc, repo, state := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	out, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, ProvisionPendingLinkConfirmation, out.Kind)
	assert.NotEmpty(t, out.PendingLinkToken)
	assert.Len(t, state.pending, 1, "pending link must be persisted")
}

func TestFindOrProvisionUser_UnknownEmailWithRegistrationStagesPendingSignup(t *testing.T) {
	users := newMockUsers()
	provider := makeProvider(t, false)

	svc, repo, state := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	out, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "bob@example.com", EmailVerified: true, Name: "Bob"},
	})
	require.NoError(t, err)
	assert.Equal(t, ProvisionPendingSignup, out.Kind)
	assert.NotEmpty(t, out.PendingSignupToken)
	assert.Nil(t, out.User, "user is only materialised on CompleteSignup")
	assert.Len(t, state.pendingSignups, 1, "pending signup must be persisted")
}

func TestFindOrProvisionUser_UnknownEmailWithoutRegistrationOrInviteRejected(t *testing.T) {
	users := newMockUsers()
	provider := makeProvider(t, false)

	svc, repo, _ := newService(t, users, fakeReg{enabled: false}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	_, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "carol@example.com"},
	})
	require.Error(t, err)
}

func TestFindOrProvisionUser_InvitationOverridesRegistrationGate(t *testing.T) {
	users := newMockUsers()
	provider := makeProvider(t, false)
	inv := &model.Invitation{Email: "carol@example.com", RoleIDs: []string{}}
	invs := &fakeInvitations{byToken: map[string]*model.Invitation{"valid-token": inv}}

	svc, repo, _ := newService(t, users, fakeReg{enabled: false}, invs)
	require.NoError(t, repo.CreateProvider(provider))

	out, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, "valid-token"),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "carol@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, ProvisionPendingSignup, out.Kind)
	assert.Len(t, invs.consumed, 0, "invitation must NOT be consumed until CompleteSignup completes")
	require.NotEmpty(t, out.PendingSignupToken)

	// Now complete: invitation is consumed exactly once.
	_, err = svc.CompleteSignup(CompleteSignupInput{Token: out.PendingSignupToken, Password: "passw0rd-strong"})
	require.NoError(t, err)
	assert.Len(t, invs.consumed, 1)
}

func TestConfirmLink_HappyPathCreatesLink(t *testing.T) {
	users := newMockUsers()
	hash := "h"
	uid, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: uid}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	users.passwordOK = true

	provider := makeProvider(t, true)
	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	out, err := svc.FindOrProvisionUser(&CallbackContext{
		Provider:    provider,
		AuthRequest: makeAuthRequest(provider, ""),
		Claims:      ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})
	require.NoError(t, err)
	require.Equal(t, ProvisionPendingLinkConfirmation, out.Kind)

	res, err := svc.ConfirmLink(out.PendingLinkToken, "correct-password")
	require.NoError(t, err)
	require.NotNil(t, res.User)
	assert.Equal(t, uid, res.User.ID)
	// A FederationLink must now exist for that provider+external_id.
	link, _ := repo.FindLink(provider.ID, "ext-1")
	require.NotNil(t, link)
	assert.Equal(t, uid, link.UserID)
}

func TestConfirmLink_WrongPasswordReturnsInvalidPasswordSentinel(t *testing.T) {
	users := newMockUsers()
	hash := "h"
	uid, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: uid}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	users.passwordOK = false

	provider := makeProvider(t, true)
	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	out, _ := svc.FindOrProvisionUser(&CallbackContext{
		Provider: provider, AuthRequest: makeAuthRequest(provider, ""),
		Claims: ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})

	_, err := svc.ConfirmLink(out.PendingLinkToken, "wrong-password")
	require.Error(t, err)
	assert.True(t, IsInvalidConfirmPassword(err))
}

func TestConfirmLink_TokenCannotBeReused(t *testing.T) {
	users := newMockUsers()
	hash := "h"
	uid, _ := uuid.NewV7()
	users.addUser(&model.User{BaseModel: model.BaseModel{ID: uid}, Email: "alice@example.com", PasswordHash: &hash, Active: true})
	users.passwordOK = true

	provider := makeProvider(t, true)
	svc, repo, _ := newService(t, users, fakeReg{enabled: true}, &fakeInvitations{})
	require.NoError(t, repo.CreateProvider(provider))

	out, _ := svc.FindOrProvisionUser(&CallbackContext{
		Provider: provider, AuthRequest: makeAuthRequest(provider, ""),
		Claims: ProviderClaims{ExternalID: "ext-1", Email: "alice@example.com"},
	})

	_, err := svc.ConfirmLink(out.PendingLinkToken, "correct")
	require.NoError(t, err)

	_, err = svc.ConfirmLink(out.PendingLinkToken, "correct")
	require.Error(t, err)
}
