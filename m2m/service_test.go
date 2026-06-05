package m2m

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

// --- mocks ---

type mockUsers struct {
	users         map[uuid.UUID]*model.User
	registerArgs  *user.RegisterInput
	registerRoles []uuid.UUID
	registerErr   error
	updateErr     error
	setPwdCalls   []setPwdCall
	deleteErr     error
	unlocked      []uuid.UUID
}

type setPwdCall struct {
	id  uuid.UUID
	pwd string
}

func ptrStr(s string) *string { return &s }

func newMockUsers() *mockUsers {
	return &mockUsers{users: map[uuid.UUID]*model.User{}}
}

func (m *mockUsers) GetByID(id uuid.UUID) (*model.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, pkg.ErrNotFound("user not found")
	}
	return u, nil
}
func (m *mockUsers) FindByEmail(email string) (*model.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}
func (m *mockUsers) List(_, _ int) ([]model.User, int64, error) {
	out := make([]model.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, *u)
	}
	return out, int64(len(out)), nil
}
func (m *mockUsers) Delete(id uuid.UUID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.users, id)
	return nil
}
func (m *mockUsers) RegisterAdmin(input user.RegisterInput, roleIDs []uuid.UUID) (*model.User, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	m.registerArgs = &input
	m.registerRoles = roleIDs
	id, _ := uuid.NewV7()
	u := &model.User{
		BaseModel:    model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Email:        input.Email,
		PasswordHash: ptrStr("hash"),
		Active:       true,
	}
	if input.DisplayName != nil {
		u.DisplayName = input.DisplayName
	}
	m.users[id] = u
	return u, nil
}
func (m *mockUsers) M2MUpdate(id uuid.UUID, input user.M2MUpdateInput) (*model.User, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	u, ok := m.users[id]
	if !ok {
		return nil, pkg.ErrNotFound("user not found")
	}
	if input.Email != nil {
		u.Email = *input.Email
	}
	if input.EmailVerified != nil {
		u.EmailVerified = *input.EmailVerified
	}
	if input.DisplayName != nil {
		u.DisplayName = input.DisplayName
	}
	if input.Active != nil {
		u.Active = *input.Active
	}
	return u, nil
}
func (m *mockUsers) SetPassword(id uuid.UUID, pwd string) error {
	m.setPwdCalls = append(m.setPwdCalls, setPwdCall{id: id, pwd: pwd})
	return nil
}
func (m *mockUsers) Unlock(id uuid.UUID) error {
	m.unlocked = append(m.unlocked, id)
	return nil
}

type mockRoles struct {
	assigned []roleAssignment
	removed  []roleAssignment
	roles    map[uuid.UUID][]model.Role
}

type roleAssignment struct{ userID, roleID uuid.UUID }

func (m *mockRoles) AssignRole(uid, rid uuid.UUID) error {
	m.assigned = append(m.assigned, roleAssignment{uid, rid})
	return nil
}
func (m *mockRoles) RemoveRole(uid, rid uuid.UUID) error {
	m.removed = append(m.removed, roleAssignment{uid, rid})
	return nil
}
func (m *mockRoles) GetUserRoles(uid uuid.UUID) ([]model.Role, error) {
	return m.roles[uid], nil
}

type mockSessions struct {
	revokeAllCalls []uuid.UUID
	revokeCalls    []roleAssignment
}

func (m *mockSessions) ListActive(_ uuid.UUID) ([]model.Session, error) { return nil, nil }
func (m *mockSessions) Revoke(sid, uid uuid.UUID) error {
	m.revokeCalls = append(m.revokeCalls, roleAssignment{uid, sid})
	return nil
}
func (m *mockSessions) RevokeAll(uid uuid.UUID, _ *uuid.UUID) (int64, error) {
	m.revokeAllCalls = append(m.revokeAllCalls, uid)
	return 3, nil
}

type mockMFA struct {
	resetCalls []uuid.UUID
	err        error
}

func (m *mockMFA) ForceDisable(uid uuid.UUID) error {
	m.resetCalls = append(m.resetCalls, uid)
	return m.err
}

type mockPasskeys struct {
	deleteCalls []roleAssignment
}

func (m *mockPasskeys) List(_ uuid.UUID) ([]model.Passkey, error) { return nil, nil }
func (m *mockPasskeys) Delete(pid, uid uuid.UUID) error {
	m.deleteCalls = append(m.deleteCalls, roleAssignment{uid, pid})
	return nil
}

type mockFed struct {
	unlinkCalls []roleAssignment
}

func (m *mockFed) GetLinkedAccounts(_ uuid.UUID) ([]model.FederationLink, error) {
	return nil, nil
}
func (m *mockFed) UnlinkAccount(linkID, uid uuid.UUID) error {
	m.unlinkCalls = append(m.unlinkCalls, roleAssignment{uid, linkID})
	return nil
}

func newSvc() (*UserService, *mockUsers, *mockRoles, *mockSessions, *mockMFA, *mockPasskeys, *mockFed) {
	u := newMockUsers()
	r := &mockRoles{roles: map[uuid.UUID][]model.Role{}}
	s := &mockSessions{}
	m := &mockMFA{}
	p := &mockPasskeys{}
	f := &mockFed{}
	return NewUserService(u, r, s, m, p, f), u, r, s, m, p, f
}

// --- tests ---

func TestCreate_GeneratesPasswordWhenOmitted(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	out, generated, err := svc.Create(CreateUserInput{Email: "a@b.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected user")
	}
	if generated == "" || len(generated) < 16 {
		t.Errorf("expected a non-empty generated password, got %q", generated)
	}
	if users.registerArgs == nil || users.registerArgs.Email != "a@b.com" {
		t.Error("registerArgs not captured properly")
	}
	if users.registerArgs.Password != generated {
		t.Error("the generated password should have been forwarded to RegisterAdmin")
	}
}

func TestCreate_UsesProvidedPassword(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	_, generated, err := svc.Create(CreateUserInput{Email: "x@y", Password: "Hunter12345!"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if generated != "" {
		t.Errorf("when caller supplies password, GeneratedPassword must be empty, got %q", generated)
	}
	if users.registerArgs.Password != "Hunter12345!" {
		t.Error("RegisterAdmin should receive the provided password verbatim")
	}
}

func TestCreate_AppliesPostCreateFields(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	verified := true
	active := false
	phone := "+33"
	out, _, err := svc.Create(CreateUserInput{
		Email:         "post@create",
		Password:      "longenough12",
		EmailVerified: &verified,
		Active:        &active,
		Phone:         &phone,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored := users.users[out.ID]
	if !stored.EmailVerified || stored.Active {
		t.Errorf("post-create update should have set email_verified=true, active=false; got %+v", stored)
	}
}

func TestCreate_PropagatesRoles(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	rid1 := uuid.New()
	rid2 := uuid.New()
	_, _, err := svc.Create(CreateUserInput{
		Email:    "r@r",
		Password: "longenough12",
		RoleIDs:  []uuid.UUID{rid1, rid2},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users.registerRoles) != 2 || users.registerRoles[0] != rid1 || users.registerRoles[1] != rid2 {
		t.Errorf("RegisterAdmin should receive roleIDs verbatim, got %v", users.registerRoles)
	}
}

func TestUpdate_ForwardsAllFields(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}, Email: "old@x"}

	newEmail := "new@x"
	out, err := svc.Update(uid, UpdateUserInput{Email: &newEmail})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Email != "new@x" {
		t.Errorf("email not updated, got %q", out.Email)
	}
}

func TestUpdate_PropagatesUpstreamError(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	users.updateErr = pkg.ErrConflict("email taken")
	_, err := svc.Update(uid, UpdateUserInput{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDelete_ChecksExistenceFirst(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvc()
	err := svc.Delete(uuid.New())
	if err == nil {
		t.Fatal("expected 404 for non-existent user")
	}
}

func TestDelete_HappyPath(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	if err := svc.Delete(uid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := users.users[uid]; ok {
		t.Error("user should be deleted from store")
	}
}

func TestSetPassword_RevokesAllSessions(t *testing.T) {
	svc, users, _, sessions, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	if err := svc.SetPassword(uid, "NewPassword12!"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users.setPwdCalls) != 1 || users.setPwdCalls[0].pwd != "NewPassword12!" {
		t.Errorf("SetPassword should be called with new password, got %+v", users.setPwdCalls)
	}
	if len(sessions.revokeAllCalls) != 1 || sessions.revokeAllCalls[0] != uid {
		t.Errorf("all sessions should be revoked after password set, got %+v", sessions.revokeAllCalls)
	}
}

func TestSetPassword_NotFound(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvc()
	if err := svc.SetPassword(uuid.New(), "x"); err == nil {
		t.Fatal("expected error for non-existent user")
	}
}

func TestUnlock(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	if err := svc.Unlock(uid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users.unlocked) != 1 || users.unlocked[0] != uid {
		t.Errorf("Unlock should be called, got %v", users.unlocked)
	}
}

func TestResetMFA(t *testing.T) {
	svc, users, _, _, mfa, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	if err := svc.ResetMFA(uid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mfa.resetCalls) != 1 {
		t.Error("ForceDisable should be called")
	}
}

func TestResetMFA_NotFound(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvc()
	if err := svc.ResetMFA(uuid.New()); err == nil {
		t.Fatal("expected 404 for non-existent user")
	}
}

func TestResetMFA_PropagatesError(t *testing.T) {
	svc, users, _, _, mfa, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	mfa.err = errors.New("boom")
	if err := svc.ResetMFA(uid); err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestRoles(t *testing.T) {
	svc, users, roles, _, _, _, _ := newSvc()
	uid := uuid.New()
	rid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}

	if err := svc.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := svc.RemoveRole(uid, rid); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if len(roles.assigned) != 1 || roles.assigned[0].userID != uid || roles.assigned[0].roleID != rid {
		t.Errorf("Assign not recorded, got %+v", roles.assigned)
	}
	if len(roles.removed) != 1 {
		t.Errorf("Remove not recorded, got %+v", roles.removed)
	}
}

func TestSessions(t *testing.T) {
	svc, users, _, sessions, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	sid := uuid.New()

	if err := svc.RevokeSession(sid, uid); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	count, err := svc.RevokeAllSessions(uid)
	if err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if count != 3 {
		t.Errorf("expected revoked_count 3, got %d", count)
	}
	if len(sessions.revokeCalls) != 1 || len(sessions.revokeAllCalls) != 1 {
		t.Errorf("expected one of each session call, got %+v / %+v", sessions.revokeCalls, sessions.revokeAllCalls)
	}
}

func TestPasskeys(t *testing.T) {
	svc, users, _, _, _, passkeys, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	pid := uuid.New()
	if err := svc.DeletePasskey(pid, uid); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	if len(passkeys.deleteCalls) != 1 || passkeys.deleteCalls[0].userID != uid || passkeys.deleteCalls[0].roleID != pid {
		t.Errorf("DeletePasskey not recorded, got %+v", passkeys.deleteCalls)
	}
}

func TestLinkedAccounts(t *testing.T) {
	svc, users, _, _, _, _, fed := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}
	linkID := uuid.New()
	if err := svc.UnlinkAccount(linkID, uid); err != nil {
		t.Fatalf("UnlinkAccount: %v", err)
	}
	if len(fed.unlinkCalls) != 1 {
		t.Error("UnlinkAccount not recorded")
	}
}

// TestAssignRole_RefusesProtectedRole locks in Vuln 14's fix: even with
// the m2m:users:manage_roles scope, the M2M API must refuse to assign
// a role that the operator has marked protected (default: admin).
func TestAssignRole_RefusesProtectedRole(t *testing.T) {
	svc, users, _, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}

	adminRole := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	svc.SetProtectedRoles([]string{adminRole.String()})

	err := svc.AssignRole(uid, adminRole)
	if err == nil {
		t.Fatal("expected protected-role refusal")
	}
}

// TestAssignRole_AllowsNonProtectedRole verifies the protection only
// affects the listed UUIDs — assigning any other role still goes
// through normally.
func TestAssignRole_AllowsNonProtectedRole(t *testing.T) {
	svc, users, roles, _, _, _, _ := newSvc()
	uid := uuid.New()
	users.users[uid] = &model.User{BaseModel: model.BaseModel{ID: uid}}

	adminRole := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	svc.SetProtectedRoles([]string{adminRole.String()})

	customerRole := uuid.New()
	if err := svc.AssignRole(uid, customerRole); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if len(roles.assigned) != 1 {
		t.Fatalf("expected role to be assigned, got %d", len(roles.assigned))
	}
}
