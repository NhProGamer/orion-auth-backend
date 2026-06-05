package invitation

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
	"orion-auth-backend/rbac"
	"orion-auth-backend/testutil"
	"orion-auth-backend/user"
)

// --- Mock Invitation Repository ---

type mockInvitationRepo struct {
	createFn         func(inv *model.Invitation) error
	findByTokenFn    func(tokenHash string) (*model.Invitation, error)
	findByIDFn       func(id uuid.UUID) (*model.Invitation, error)
	listFn           func(page, perPage int) ([]model.Invitation, int64, error)
	markUsedFn       func(inv *model.Invitation) error
	deleteFn         func(id uuid.UUID) error
	getSettingFn     func(key string) (string, error)
	setSettingFn     func(key, value string) error
	getAllSettingsFn func() ([]model.Setting, error)
}

func (m *mockInvitationRepo) Create(inv *model.Invitation) error {
	if m.createFn != nil {
		return m.createFn(inv)
	}
	return nil
}

func (m *mockInvitationRepo) FindByToken(tokenHash string) (*model.Invitation, error) {
	if m.findByTokenFn != nil {
		return m.findByTokenFn(tokenHash)
	}
	return nil, nil
}

func (m *mockInvitationRepo) FindByID(id uuid.UUID) (*model.Invitation, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(id)
	}
	return nil, nil
}

func (m *mockInvitationRepo) List(page, perPage int) ([]model.Invitation, int64, error) {
	if m.listFn != nil {
		return m.listFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockInvitationRepo) MarkUsed(inv *model.Invitation) error {
	if m.markUsedFn != nil {
		return m.markUsedFn(inv)
	}
	return nil
}

func (m *mockInvitationRepo) Delete(id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(id)
	}
	return nil
}

func (m *mockInvitationRepo) GetSetting(key string) (string, error) {
	if m.getSettingFn != nil {
		return m.getSettingFn(key)
	}
	return "", nil
}

func (m *mockInvitationRepo) SetSetting(key, value string) error {
	if m.setSettingFn != nil {
		return m.setSettingFn(key, value)
	}
	return nil
}

func (m *mockInvitationRepo) GetAllSettings() ([]model.Setting, error) {
	if m.getAllSettingsFn != nil {
		return m.getAllSettingsFn()
	}
	return nil, nil
}

// --- Mock User Repository ---

type mockUserRepo struct {
	createFn            func(u *model.User) error
	findByIDFn          func(id uuid.UUID) (*model.User, error)
	findByEmailFn       func(email string) (*model.User, error)
	updateFn            func(u *model.User) error
	updateFieldsFn      func(id uuid.UUID, fields map[string]any) error
	listFn              func(page, perPage int) ([]model.User, int64, error)
	deleteFn            func(id uuid.UUID) error
	findByResetTokenFn  func(tokenHash string) (*model.User, error)
	findByVerifyTokenFn func(tokenHash string) (*model.User, error)
}

func (m *mockUserRepo) Create(u *model.User) error {
	if m.createFn != nil {
		return m.createFn(u)
	}
	return nil
}

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

func (m *mockUserRepo) Update(u *model.User) error {
	if m.updateFn != nil {
		return m.updateFn(u)
	}
	return nil
}

func (m *mockUserRepo) UpdateFields(id uuid.UUID, fields map[string]any) error {
	if m.updateFieldsFn != nil {
		return m.updateFieldsFn(id, fields)
	}
	return nil
}

func (m *mockUserRepo) List(page, perPage int) ([]model.User, int64, error) {
	if m.listFn != nil {
		return m.listFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockUserRepo) Search(_ string, page, perPage int) ([]model.User, int64, error) {
	if m.listFn != nil {
		return m.listFn(page, perPage)
	}
	return nil, 0, nil
}

func (m *mockUserRepo) Delete(id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(id)
	}
	return nil
}

func (m *mockUserRepo) FindByResetToken(tokenHash string) (*model.User, error) {
	if m.findByResetTokenFn != nil {
		return m.findByResetTokenFn(tokenHash)
	}
	return nil, nil
}

func (m *mockUserRepo) FindByVerifyToken(tokenHash string) (*model.User, error) {
	if m.findByVerifyTokenFn != nil {
		return m.findByVerifyTokenFn(tokenHash)
	}
	return nil, nil
}

func (m *mockUserRepo) FindByEmailChangeToken(_ string) (*model.User, error) {
	return nil, nil
}

func (m *mockUserRepo) FindByDeletionToken(_ string) (*model.User, error) {
	return nil, nil
}

// --- Mock RBAC Repository ---

type mockRbacRepo struct {
	createRoleFn         func(role *model.Role) error
	findRoleByIDFn       func(id uuid.UUID) (*model.Role, error)
	findRoleByNameFn     func(name string) (*model.Role, error)
	listRolesFn          func() ([]model.Role, error)
	updateRoleFn         func(role *model.Role) error
	deleteRoleFn         func(id uuid.UUID) error
	listPermissionsFn    func() ([]model.Permission, error)
	findPermsByIDsFn     func(ids []uuid.UUID) ([]model.Permission, error)
	setRolePermsFn       func(roleID uuid.UUID, permIDs []uuid.UUID) error
	getUserRolesFn       func(userID uuid.UUID) ([]model.Role, error)
	assignRoleFn         func(userID, roleID uuid.UUID) error
	removeRoleFn         func(userID, roleID uuid.UUID) error
	getUserPermissionsFn func(userID uuid.UUID) ([]string, error)
}

func (m *mockRbacRepo) CreateRole(role *model.Role) error {
	if m.createRoleFn != nil {
		return m.createRoleFn(role)
	}
	return nil
}
func (m *mockRbacRepo) FindRoleByID(id uuid.UUID) (*model.Role, error) {
	if m.findRoleByIDFn != nil {
		return m.findRoleByIDFn(id)
	}
	return nil, nil
}
func (m *mockRbacRepo) FindRoleByName(name string) (*model.Role, error) {
	if m.findRoleByNameFn != nil {
		return m.findRoleByNameFn(name)
	}
	return nil, nil
}
func (m *mockRbacRepo) ListRoles() ([]model.Role, error) {
	if m.listRolesFn != nil {
		return m.listRolesFn()
	}
	return nil, nil
}
func (m *mockRbacRepo) UpdateRole(role *model.Role) error {
	if m.updateRoleFn != nil {
		return m.updateRoleFn(role)
	}
	return nil
}
func (m *mockRbacRepo) DeleteRole(id uuid.UUID) error {
	if m.deleteRoleFn != nil {
		return m.deleteRoleFn(id)
	}
	return nil
}
func (m *mockRbacRepo) ListPermissions() ([]model.Permission, error) {
	if m.listPermissionsFn != nil {
		return m.listPermissionsFn()
	}
	return nil, nil
}
func (m *mockRbacRepo) FindPermissionsByIDs(ids []uuid.UUID) ([]model.Permission, error) {
	if m.findPermsByIDsFn != nil {
		return m.findPermsByIDsFn(ids)
	}
	return nil, nil
}
func (m *mockRbacRepo) SetRolePermissions(roleID uuid.UUID, permIDs []uuid.UUID) error {
	if m.setRolePermsFn != nil {
		return m.setRolePermsFn(roleID, permIDs)
	}
	return nil
}
func (m *mockRbacRepo) GetUserRoles(userID uuid.UUID) ([]model.Role, error) {
	if m.getUserRolesFn != nil {
		return m.getUserRolesFn(userID)
	}
	return nil, nil
}
func (m *mockRbacRepo) AssignRole(userID, roleID uuid.UUID) error {
	if m.assignRoleFn != nil {
		return m.assignRoleFn(userID, roleID)
	}
	return nil
}
func (m *mockRbacRepo) RemoveRole(userID, roleID uuid.UUID) error {
	if m.removeRoleFn != nil {
		return m.removeRoleFn(userID, roleID)
	}
	return nil
}
func (m *mockRbacRepo) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	if m.getUserPermissionsFn != nil {
		return m.getUserPermissionsFn(userID)
	}
	return nil, nil
}

// --- Mock Email Sender ---

type mockEmailSender struct {
	sendInvitationFn func(to, token string) error
}

func (m *mockEmailSender) SendVerificationEmail(_, _ string) error  { return nil }
func (m *mockEmailSender) SendPasswordResetEmail(_, _ string) error { return nil }
func (m *mockEmailSender) SendInvitationEmail(to, token string) error {
	if m.sendInvitationFn != nil {
		return m.sendInvitationFn(to, token)
	}
	return nil
}

func (m *mockEmailSender) SendEmailChangeConfirmation(_, _ string) error { return nil }
func (m *mockEmailSender) SendEmailChangedNotice(_, _ string) error      { return nil }
func (m *mockEmailSender) SendPasswordChangedNotice(_ string) error      { return nil }
func (m *mockEmailSender) SendAccountDeletionEmail(_, _ string) error    { return nil }

// --- Helpers ---

func newTestService(invRepo *mockInvitationRepo, userRepo *mockUserRepo, rbacRepo *mockRbacRepo, emailSender *mockEmailSender) *Service {
	userSvc := user.NewService(user.Options{Repo: userRepo, Hasher: testutil.FastHasher(), Cfg: testutil.TestAuthConfig()})
	rbacSvc := rbac.NewService(rbacRepo)
	var sender *mockEmailSender
	if emailSender != nil {
		sender = emailSender
	}
	if sender != nil {
		return NewService(invRepo, userSvc, rbacSvc, sender, "https://auth.example.com")
	}
	return NewService(invRepo, userSvc, rbacSvc, nil, "https://auth.example.com")
}

func makeInvitation() *model.Invitation {
	id, _ := uuid.NewV7()
	invitedBy, _ := uuid.NewV7()
	return &model.Invitation{
		BaseModel: model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Email:     "invite@example.com",
		Token:     "hashed-token",
		InvitedBy: invitedBy,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
}

// --- Create Tests ---

func TestCreate_Success(t *testing.T) {
	var created *model.Invitation
	emailSent := false
	invRepo := &mockInvitationRepo{
		createFn: func(inv *model.Invitation) error {
			created = inv
			return nil
		},
	}
	emailMock := &mockEmailSender{
		sendInvitationFn: func(to, token string) error {
			emailSent = true
			assert.Equal(t, "new@example.com", to)
			assert.NotEmpty(t, token)
			return nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, emailMock)

	invitedBy, _ := uuid.NewV7()
	inv, err := svc.Create(CreateInput{Email: "new@example.com"}, invitedBy)

	require.NoError(t, err)
	assert.NotNil(t, inv)
	assert.Equal(t, "new@example.com", created.Email)
	assert.NotEmpty(t, created.Token, "token hash should be stored")
	assert.True(t, emailSent, "invitation email should be sent")
}

func TestCreate_NoEmailSender(t *testing.T) {
	invRepo := &mockInvitationRepo{
		createFn: func(_ *model.Invitation) error { return nil },
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	invitedBy, _ := uuid.NewV7()
	inv, err := svc.Create(CreateInput{Email: "no-email@example.com"}, invitedBy)

	require.NoError(t, err)
	assert.NotNil(t, inv)
}

// --- Delete Tests ---

func TestDelete_Success(t *testing.T) {
	existing := makeInvitation()
	deleted := false
	invRepo := &mockInvitationRepo{
		findByIDFn: func(_ uuid.UUID) (*model.Invitation, error) {
			return existing, nil
		},
		deleteFn: func(_ uuid.UUID) error {
			deleted = true
			return nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	err := svc.Delete(existing.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDelete_NotFound(t *testing.T) {
	invRepo := &mockInvitationRepo{} // returns nil by default

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	id, _ := uuid.NewV7()
	err := svc.Delete(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- ValidateToken Tests ---

func TestValidateToken_HappyPath(t *testing.T) {
	existing := makeInvitation()
	invRepo := &mockInvitationRepo{
		findByTokenFn: func(_ string) (*model.Invitation, error) {
			return existing, nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	inv, err := svc.ValidateToken("any-raw-token")
	require.NoError(t, err)
	require.NotNil(t, inv)
	assert.Equal(t, existing.Email, inv.Email)
}

func TestValidateToken_Empty(t *testing.T) {
	svc := newTestService(&mockInvitationRepo{}, &mockUserRepo{}, &mockRbacRepo{}, nil)

	inv, err := svc.ValidateToken("")
	require.NoError(t, err)
	assert.Nil(t, inv)
}

func TestValidateToken_NotFound(t *testing.T) {
	invRepo := &mockInvitationRepo{
		findByTokenFn: func(_ string) (*model.Invitation, error) { return nil, nil },
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	inv, err := svc.ValidateToken("missing")
	require.NoError(t, err)
	assert.Nil(t, inv)
}

func TestValidateToken_Expired(t *testing.T) {
	expired := makeInvitation()
	expired.ExpiresAt = time.Now().Add(-1 * time.Hour)
	invRepo := &mockInvitationRepo{
		findByTokenFn: func(_ string) (*model.Invitation, error) { return expired, nil },
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	inv, err := svc.ValidateToken("expired")
	require.NoError(t, err)
	assert.Nil(t, inv)
}

func TestValidateToken_Used(t *testing.T) {
	used := makeInvitation()
	used.Used = true
	invRepo := &mockInvitationRepo{
		findByTokenFn: func(_ string) (*model.Invitation, error) { return used, nil },
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	inv, err := svc.ValidateToken("used")
	require.NoError(t, err)
	assert.Nil(t, inv)
}

// --- Session TTL Resolver ---

func TestSessionTTL_FallbackToDefaults(t *testing.T) {
	svc := newTestService(&mockInvitationRepo{}, &mockUserRepo{}, &mockRbacRepo{}, nil)
	svc.SetSessionTTLDefaults(24*time.Hour, 720*time.Hour)

	assert.Equal(t, 24*time.Hour, svc.SessionTTL(false))
	assert.Equal(t, 720*time.Hour, svc.SessionTTL(true))
}

func TestSessionTTL_AdminOverride(t *testing.T) {
	invRepo := &mockInvitationRepo{
		getSettingFn: func(key string) (string, error) {
			switch key {
			case "default_session_ttl":
				return "3600", nil
			case "default_session_extended_ttl":
				return "604800", nil
			}
			return "", nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)
	svc.SetSessionTTLDefaults(24*time.Hour, 720*time.Hour)

	assert.Equal(t, time.Hour, svc.SessionTTL(false))
	assert.Equal(t, 7*24*time.Hour, svc.SessionTTL(true))
}

func TestSessionTTL_InvalidOverrideFallsBack(t *testing.T) {
	invRepo := &mockInvitationRepo{
		getSettingFn: func(key string) (string, error) {
			if key == "default_session_ttl" {
				return "not-a-number", nil
			}
			return "", nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)
	svc.SetSessionTTLDefaults(24*time.Hour, 720*time.Hour)

	assert.Equal(t, 24*time.Hour, svc.SessionTTL(false))
}

// --- Post-Register Redirect URL ---

func TestGetPostRegisterRedirectURL_FromSetting(t *testing.T) {
	invRepo := &mockInvitationRepo{
		getSettingFn: func(key string) (string, error) {
			if key == "default_post_register_redirect_url" {
				return "https://dev.clown.school/", nil
			}
			return "", nil
		},
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	assert.Equal(t, "https://dev.clown.school/", svc.GetPostRegisterRedirectURL())
}

func TestGetPostRegisterRedirectURL_Default(t *testing.T) {
	svc := newTestService(&mockInvitationRepo{}, &mockUserRepo{}, &mockRbacRepo{}, nil)

	assert.Equal(t, "", svc.GetPostRegisterRedirectURL())
}

func TestSetAllowedOrigins(t *testing.T) {
	svc := newTestService(&mockInvitationRepo{}, &mockUserRepo{}, &mockRbacRepo{}, nil)
	svc.SetAllowedOrigins([]string{"https://dev.clown.school"})

	assert.Equal(t, []string{"https://dev.clown.school"}, svc.AllowedOrigins())
}

// --- IsEmailVerificationRequired ---

func TestIsEmailVerificationRequired_DefaultTrue(t *testing.T) {
	svc := newTestService(&mockInvitationRepo{}, &mockUserRepo{}, &mockRbacRepo{}, nil)
	assert.True(t, svc.IsEmailVerificationRequired())
}

func TestIsEmailVerificationRequired_DisabledExplicitly(t *testing.T) {
	invRepo := &mockInvitationRepo{
		getSettingFn: func(key string) (string, error) {
			if key == "registration_email_verification_required" {
				return "false", nil
			}
			return "", nil
		},
	}
	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)
	assert.False(t, svc.IsEmailVerificationRequired())
}

// --- IsRegistrationEnabled Tests ---

func TestIsRegistrationEnabled_Default(t *testing.T) {
	invRepo := &mockInvitationRepo{
		// getSettingFn not set => returns "", nil => default true
	}

	svc := newTestService(invRepo, &mockUserRepo{}, &mockRbacRepo{}, nil)

	assert.True(t, svc.IsRegistrationEnabled())
}
