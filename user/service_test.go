package user

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
	"orion-auth-backend/testutil"
)

// ---------------------------------------------------------------------------
// Mock: UserRepo
// ---------------------------------------------------------------------------

type mockUserRepo struct {
	createFn            func(user *model.User) error
	findByIDFn          func(id uuid.UUID) (*model.User, error)
	findByEmailFn       func(email string) (*model.User, error)
	updateFn            func(user *model.User) error
	updateFieldsFn      func(id uuid.UUID, fields map[string]any) error
	listFn              func(page, perPage int) ([]model.User, int64, error)
	deleteFn            func(id uuid.UUID) error
	findByResetTokenFn  func(tokenHash string) (*model.User, error)
	findByVerifyTokenFn func(tokenHash string) (*model.User, error)
}

func (m *mockUserRepo) Create(user *model.User) error {
	if m.createFn != nil {
		return m.createFn(user)
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

func (m *mockUserRepo) Update(user *model.User) error {
	if m.updateFn != nil {
		return m.updateFn(user)
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

func (m *mockUserRepo) FindByEmailChangeToken(tokenHash string) (*model.User, error) {
	return nil, nil
}

func (m *mockUserRepo) FindByDeletionToken(tokenHash string) (*model.User, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Mock: EmailSender
// ---------------------------------------------------------------------------

type mockEmailSender struct {
	sendVerificationEmailFn  func(to, token string) error
	sendPasswordResetEmailFn func(to, token string) error
	sendInvitationEmailFn    func(to, token string) error
}

func (m *mockEmailSender) SendVerificationEmail(to, token string) error {
	if m.sendVerificationEmailFn != nil {
		return m.sendVerificationEmailFn(to, token)
	}
	return nil
}

func (m *mockEmailSender) SendPasswordResetEmail(to, token string) error {
	if m.sendPasswordResetEmailFn != nil {
		return m.sendPasswordResetEmailFn(to, token)
	}
	return nil
}

func (m *mockEmailSender) SendInvitationEmail(to, token string) error {
	if m.sendInvitationEmailFn != nil {
		return m.sendInvitationEmailFn(to, token)
	}
	return nil
}

func (m *mockEmailSender) SendEmailChangeConfirmation(_, _ string) error { return nil }
func (m *mockEmailSender) SendEmailChangedNotice(_, _ string) error      { return nil }
func (m *mockEmailSender) SendPasswordChangedNotice(_ string) error      { return nil }
func (m *mockEmailSender) SendAccountDeletionEmail(_, _ string) error    { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService(repo *mockUserRepo) *Service {
	hasher := testutil.FastHasher()
	cfg := testutil.TestAuthConfig()
	return NewService(repo, hasher, cfg)
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegister_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return nil, nil },
		createFn:      func(user *model.User) error { return nil },
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	user, err := svc.Register(RegisterInput{
		Email:    "Alice@Example.COM",
		Password: "strongpassword",
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.True(t, user.Active)
	require.NotNil(t, user.PasswordHash)
	assert.NotEmpty(t, *user.PasswordHash)
	// Verify the hash is valid
	match, err := hasher.Verify("strongpassword", *user.PasswordHash)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestRegister_PasswordTooShort(t *testing.T) {
	svc := newTestService(&mockUserRepo{})

	_, err := svc.Register(RegisterInput{
		Email:    "test@example.com",
		Password: "short",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "password must be at least")
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	existing := testutil.TestUser(testutil.FastHasher(), "password123")
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return existing, nil },
	}
	svc := newTestService(repo)

	_, err := svc.Register(RegisterInput{
		Email:    "test@example.com",
		Password: "strongpassword",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "email already registered")
}

func TestRegister_EmailNormalization(t *testing.T) {
	var capturedEmail string
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) {
			capturedEmail = email
			return nil, nil
		},
		createFn: func(user *model.User) error { return nil },
	}
	svc := newTestService(repo)

	user, err := svc.Register(RegisterInput{
		Email:    "  Alice@EXAMPLE.COM  ",
		Password: "strongpassword",
	})

	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", capturedEmail)
	assert.Equal(t, "alice@example.com", user.Email)
}

// ---------------------------------------------------------------------------
// Authenticate
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.FailedLoginAttempts = 2

	var updatedFields map[string]any
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			updatedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	user, err := svc.Authenticate(LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, testUser.ID, user.ID)
	// Should reset failed attempts
	require.NotNil(t, updatedFields)
	assert.Equal(t, 0, updatedFields["failed_login_attempts"])
}

func TestAuthenticate_UserNotFound(t *testing.T) {
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return nil, nil },
	}
	svc := newTestService(repo)

	_, err := svc.Authenticate(LoginInput{
		Email:    "nonexistent@example.com",
		Password: "password123",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email or password")
}

func TestAuthenticate_AccountDeactivated(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.Active = false

	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	_, err := svc.Authenticate(LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account is deactivated")
}

func TestAuthenticate_AccountLocked(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	lockedUntil := time.Now().Add(15 * time.Minute)
	testUser.LockedUntil = &lockedUntil

	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	_, err := svc.Authenticate(LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account is temporarily locked")
}

func TestAuthenticate_WrongPassword_IncrementsFailedAttempts(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.FailedLoginAttempts = 0

	var capturedFields map[string]any
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			capturedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	_, err := svc.Authenticate(LoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email or password")
	require.NotNil(t, capturedFields)
	assert.Equal(t, 1, capturedFields["failed_login_attempts"])
	// Should NOT set locked_until (only 1 attempt)
	_, hasLock := capturedFields["locked_until"]
	assert.False(t, hasLock)
}

func TestAuthenticate_WrongPassword_LocksAfterMaxAttempts(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.FailedLoginAttempts = 4 // Next failure will be attempt #5

	var capturedFields map[string]any
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			capturedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	_, err := svc.Authenticate(LoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})

	require.Error(t, err)
	require.NotNil(t, capturedFields)
	assert.Equal(t, 5, capturedFields["failed_login_attempts"])
	// Should set locked_until
	lockedUntil, hasLock := capturedFields["locked_until"]
	assert.True(t, hasLock)
	lockTime, ok := lockedUntil.(time.Time)
	assert.True(t, ok)
	assert.True(t, lockTime.After(time.Now()))
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func TestChangePassword_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "oldpassword")

	var capturedFields map[string]any
	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			capturedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	err := svc.ChangePassword(testUser.ID, ChangePasswordInput{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword123",
	})

	require.NoError(t, err)
	require.NotNil(t, capturedFields)
	newHash, ok := capturedFields["password_hash"].(string)
	require.True(t, ok)
	// Verify the new hash matches the new password
	match, err := hasher.Verify("newpassword123", newHash)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "correctpassword")

	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	err := svc.ChangePassword(testUser.ID, ChangePasswordInput{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "current password is incorrect")
}

func TestChangePassword_NewPasswordTooShort(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "oldpassword")

	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	err := svc.ChangePassword(testUser.ID, ChangePasswordInput{
		CurrentPassword: "oldpassword",
		NewPassword:     "short",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "password must be at least")
}

// ---------------------------------------------------------------------------
// SendVerificationEmail
// ---------------------------------------------------------------------------

func TestSendVerificationEmail_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.EmailVerified = false

	var emailSent bool
	var sentTo string
	emailMock := &mockEmailSender{
		sendVerificationEmailFn: func(to, token string) error {
			emailSent = true
			sentTo = to
			assert.NotEmpty(t, token)
			return nil
		},
	}

	var storedFields map[string]any
	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			storedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())
	svc.SetEmailSender(emailMock)

	err := svc.SendVerificationEmail(testUser.ID)

	require.NoError(t, err)
	assert.True(t, emailSent)
	assert.Equal(t, testUser.Email, sentTo)
	// Should have stored token hash and expiry
	require.NotNil(t, storedFields)
	assert.NotNil(t, storedFields["email_verify_token"])
	assert.NotNil(t, storedFields["email_verify_expires_at"])
}

func TestSendVerificationEmail_NoEmailSender(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")
	testUser.EmailVerified = false

	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())
	// No email sender set

	err := svc.SendVerificationEmail(testUser.ID)

	// Should succeed without error even without email sender
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

func TestVerifyEmail_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")

	var capturedFields map[string]any
	repo := &mockUserRepo{
		findByVerifyTokenFn: func(tokenHash string) (*model.User, error) {
			return testUser, nil
		},
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			capturedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	err := svc.VerifyEmail(VerifyEmailInput{Token: "some-valid-token"})

	require.NoError(t, err)
	require.NotNil(t, capturedFields)
	assert.Equal(t, true, capturedFields["email_verified"])
	assert.Nil(t, capturedFields["email_verify_token"])
	assert.Nil(t, capturedFields["email_verify_expires_at"])
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	repo := &mockUserRepo{
		findByVerifyTokenFn: func(tokenHash string) (*model.User, error) {
			return nil, nil // Not found
		},
	}
	svc := newTestService(repo)

	err := svc.VerifyEmail(VerifyEmailInput{Token: "invalid-token"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired verification token")
}

// ---------------------------------------------------------------------------
// ForgotPassword
// ---------------------------------------------------------------------------

func TestForgotPassword_ExistingUser(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")

	var emailSent bool
	emailMock := &mockEmailSender{
		sendPasswordResetEmailFn: func(to, token string) error {
			emailSent = true
			assert.Equal(t, testUser.Email, to)
			assert.NotEmpty(t, token)
			return nil
		},
	}

	var storedFields map[string]any
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			storedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())
	svc.SetEmailSender(emailMock)

	err := svc.ForgotPassword(ForgotPasswordInput{Email: "test@example.com"})

	require.NoError(t, err)
	assert.True(t, emailSent)
	require.NotNil(t, storedFields)
	assert.NotNil(t, storedFields["password_reset_token"])
	assert.NotNil(t, storedFields["password_reset_expires_at"])
}

func TestForgotPassword_NonExistentUser(t *testing.T) {
	repo := &mockUserRepo{
		findByEmailFn: func(email string) (*model.User, error) { return nil, nil },
	}
	svc := newTestService(repo)

	err := svc.ForgotPassword(ForgotPasswordInput{Email: "nobody@example.com"})

	// Anti-enumeration: returns nil even for non-existent user
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// AdminTriggerPasswordReset
// ---------------------------------------------------------------------------

func TestAdminTriggerPasswordReset_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "password123")

	var emailSent bool
	emailMock := &mockEmailSender{
		sendPasswordResetEmailFn: func(to, token string) error {
			emailSent = true
			assert.Equal(t, testUser.Email, to)
			assert.NotEmpty(t, token)
			return nil
		},
	}

	var storedFields map[string]any
	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return testUser, nil },
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			storedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())
	svc.SetEmailSender(emailMock)

	err := svc.AdminTriggerPasswordReset(testUser.ID)

	require.NoError(t, err)
	assert.True(t, emailSent)
	require.NotNil(t, storedFields)
	assert.NotNil(t, storedFields["password_reset_token"])
	assert.NotNil(t, storedFields["password_reset_expires_at"])
}

func TestAdminTriggerPasswordReset_UserNotFound(t *testing.T) {
	repo := &mockUserRepo{
		findByIDFn: func(id uuid.UUID) (*model.User, error) { return nil, nil },
	}
	svc := newTestService(repo)

	missingID, _ := uuid.NewV7()
	err := svc.AdminTriggerPasswordReset(missingID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// ResetPassword
// ---------------------------------------------------------------------------

func TestResetPassword_Success(t *testing.T) {
	hasher := testutil.FastHasher()
	testUser := testutil.TestUser(hasher, "oldpassword")

	var capturedFields map[string]any
	repo := &mockUserRepo{
		findByResetTokenFn: func(tokenHash string) (*model.User, error) {
			return testUser, nil
		},
		updateFieldsFn: func(id uuid.UUID, fields map[string]any) error {
			capturedFields = fields
			return nil
		},
	}
	svc := NewService(repo, hasher, testutil.TestAuthConfig())

	err := svc.ResetPassword(ResetPasswordInput{
		Token:       "valid-reset-token",
		NewPassword: "newstrongpassword",
	})

	require.NoError(t, err)
	require.NotNil(t, capturedFields)
	// Should have new password hash
	newHash, ok := capturedFields["password_hash"].(string)
	require.True(t, ok)
	match, err := hasher.Verify("newstrongpassword", newHash)
	require.NoError(t, err)
	assert.True(t, match)
	// Should clear reset token and lockout
	assert.Nil(t, capturedFields["password_reset_token"])
	assert.Nil(t, capturedFields["password_reset_expires_at"])
	assert.Equal(t, 0, capturedFields["failed_login_attempts"])
	assert.Nil(t, capturedFields["locked_until"])
}

func TestResetPassword_InvalidToken(t *testing.T) {
	repo := &mockUserRepo{
		findByResetTokenFn: func(tokenHash string) (*model.User, error) {
			return nil, nil // Not found
		},
	}
	svc := newTestService(repo)

	err := svc.ResetPassword(ResetPasswordInput{
		Token:       "invalid-token",
		NewPassword: "newstrongpassword",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired reset token")
}

func TestResetPassword_PasswordTooShort(t *testing.T) {
	svc := newTestService(&mockUserRepo{})

	err := svc.ResetPassword(ResetPasswordInput{
		Token:       "valid-token",
		NewPassword: "short",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "password must be at least")
}
