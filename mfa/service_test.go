package mfa

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/testutil"
)

// --- Mock Repository ---

type mockMFARepo struct {
	createFn             func(m *model.MFAMethod) error
	findByUserAndTypeFn  func(userID uuid.UUID, mfaType string) (*model.MFAMethod, error)
	findVerifiedByUserFn func(userID uuid.UUID) (*model.MFAMethod, error)
	updateFn             func(m *model.MFAMethod) error
	deleteFn             func(id uuid.UUID) error
}

func (m *mockMFARepo) Create(method *model.MFAMethod) error {
	if m.createFn != nil {
		return m.createFn(method)
	}
	return nil
}

func (m *mockMFARepo) FindByUserAndType(userID uuid.UUID, mfaType string) (*model.MFAMethod, error) {
	if m.findByUserAndTypeFn != nil {
		return m.findByUserAndTypeFn(userID, mfaType)
	}
	return nil, nil
}

func (m *mockMFARepo) FindVerifiedByUser(userID uuid.UUID) (*model.MFAMethod, error) {
	if m.findVerifiedByUserFn != nil {
		return m.findVerifiedByUserFn(userID)
	}
	return nil, nil
}

func (m *mockMFARepo) Update(method *model.MFAMethod) error {
	if m.updateFn != nil {
		return m.updateFn(method)
	}
	return nil
}

func (m *mockMFARepo) Delete(id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(id)
	}
	return nil
}

// --- Helpers ---

func newTestService(repo *mockMFARepo) *Service {
	return NewService(repo, testutil.FastHasher())
}

func generateTestMethod(userID uuid.UUID) *model.MFAMethod {
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "test",
		AccountName: "test@example.com",
	})
	id, _ := uuid.NewV7()
	return &model.MFAMethod{
		BaseModel: model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		UserID:    userID,
		Type:      "totp",
		Secret:    key.Secret(),
		Verified:  true,
	}
}

// --- Enroll Tests ---

func TestEnroll_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{}
	svc := newTestService(repo)

	resp, err := svc.Enroll(userID, "test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Secret)
	assert.NotEmpty(t, resp.URL)
	assert.NotNil(t, resp.MFAMethod)
	assert.False(t, resp.MFAMethod.Verified)
}

func TestEnroll_AlreadyVerified(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{
		findByUserAndTypeFn: func(_ uuid.UUID, _ string) (*model.MFAMethod, error) {
			return &model.MFAMethod{Verified: true}, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.Enroll(userID, "test@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already enrolled")
}

func TestEnroll_ReplacesUnverified(t *testing.T) {
	userID, _ := uuid.NewV7()
	deleted := false
	repo := &mockMFARepo{
		findByUserAndTypeFn: func(_ uuid.UUID, _ string) (*model.MFAMethod, error) {
			id, _ := uuid.NewV7()
			return &model.MFAMethod{BaseModel: model.BaseModel{ID: id}, Verified: false}, nil
		},
		deleteFn: func(_ uuid.UUID) error {
			deleted = true
			return nil
		},
	}
	svc := newTestService(repo)

	resp, err := svc.Enroll(userID, "test@example.com")
	require.NoError(t, err)
	assert.True(t, deleted)
	assert.NotNil(t, resp)
}

// --- Verify Tests ---

func TestVerify_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	method.Verified = false

	code, _ := totp.GenerateCode(method.Secret, time.Now())

	var updatedMethod *model.MFAMethod
	repo := &mockMFARepo{
		findByUserAndTypeFn: func(_ uuid.UUID, _ string) (*model.MFAMethod, error) {
			return method, nil
		},
		updateFn: func(m *model.MFAMethod) error {
			updatedMethod = m
			return nil
		},
	}
	svc := newTestService(repo)

	backupCodes, err := svc.Verify(userID, code)
	require.NoError(t, err)
	assert.Len(t, backupCodes, 10)
	assert.True(t, updatedMethod.Verified)
	assert.Len(t, updatedMethod.BackupCodes, 10)
}

func TestVerify_AlreadyVerified(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	method.Verified = true

	repo := &mockMFARepo{
		findByUserAndTypeFn: func(_ uuid.UUID, _ string) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.Verify(userID, "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already verified")
}

func TestVerify_InvalidCode(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	method.Verified = false

	repo := &mockMFARepo{
		findByUserAndTypeFn: func(_ uuid.UUID, _ string) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.Verify(userID, "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
}

func TestVerify_NoEnrollment(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{}
	svc := newTestService(repo)

	_, err := svc.Verify(userID, "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no TOTP enrollment")
}

// --- ValidateCode Tests ---

func TestValidateCode_TOTP_Valid(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	code, _ := totp.GenerateCode(method.Secret, time.Now())

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, code)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateCode_BackupCode_Valid(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	backupCode := "test-backup-code"
	backupHash := crypto.HashToken(backupCode)
	method.BackupCodes = pq.StringArray{backupHash, "other-hash"}

	var updatedMethod *model.MFAMethod
	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
		updateFn: func(m *model.MFAMethod) error {
			updatedMethod = m
			return nil
		},
	}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, backupCode)
	require.NoError(t, err)
	assert.True(t, valid)
	// Backup code should be consumed
	assert.Len(t, updatedMethod.BackupCodes, 1)
	assert.Equal(t, "other-hash", string(updatedMethod.BackupCodes[0]))
}

func TestValidateCode_InvalidCode(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, "000000")
	require.NoError(t, err)
	assert.False(t, valid)
}

// TestValidateCode_BackupCode_RefusesOnDBError is the regression test
// for Vuln 6. If the repository can't persist the invalidation of a
// consumed backup code, ValidateCode must refuse the authentication —
// otherwise the next call would re-read the unmodified row and accept
// the same code again. The previous implementation discarded the
// Update error and returned (true, nil), opening a replay window.
func TestValidateCode_BackupCode_RefusesOnDBError(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	backupCode := "test-backup-code"
	backupHash := crypto.HashToken(backupCode)
	method.BackupCodes = pq.StringArray{backupHash, "other-hash"}

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
		updateFn: func(_ *model.MFAMethod) error {
			return assert.AnError // simulate a transient DB failure
		},
	}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, backupCode)
	require.Error(t, err, "Update failure must surface as an auth refusal")
	assert.False(t, valid, "Backup code must not be accepted when invalidation fails")
}

func TestValidateCode_NoMFA(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, "123456")
	require.NoError(t, err)
	assert.False(t, valid)
}

// --- HasMFA Tests ---

func TestHasMFA_WithVerifiedMethod(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	has, err := svc.HasMFA(userID)
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasMFA_NoMethod(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{}
	svc := newTestService(repo)

	has, err := svc.HasMFA(userID)
	require.NoError(t, err)
	assert.False(t, has)
}

// --- Disable Tests ---

func TestDisable_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	code, _ := totp.GenerateCode(method.Secret, time.Now())

	deleted := false
	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
		deleteFn: func(_ uuid.UUID) error {
			deleted = true
			return nil
		},
	}
	svc := newTestService(repo)

	err := svc.Disable(userID, code)
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDisable_InvalidCode(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	err := svc.Disable(userID, "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
}

func TestDisable_NoMFA(t *testing.T) {
	userID, _ := uuid.NewV7()
	repo := &mockMFARepo{}
	svc := newTestService(repo)

	err := svc.Disable(userID, "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no verified MFA")
}

// --- RegenerateBackupCodes Tests ---

func TestRegenerateBackupCodes_Success(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)
	code, _ := totp.GenerateCode(method.Secret, time.Now())

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	codes, err := svc.RegenerateBackupCodes(userID, code)
	require.NoError(t, err)
	assert.Len(t, codes, 10)
}

func TestRegenerateBackupCodes_InvalidCode(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.RegenerateBackupCodes(userID, "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
}

// TestValidateCode_TOTPRejectsReplayInSameStep is the regression test
// for Vuln 12. A TOTP code accepted within step N must not be accepted
// a second time before the next step rolls over. We drive ValidateCode
// twice with the same freshly-generated code; the first call succeeds,
// the second must be refused with the "already used" error.
func TestValidateCode_TOTPRejectsReplayInSameStep(t *testing.T) {
	userID, _ := uuid.NewV7()
	method := generateTestMethod(userID)

	// Compute a fresh code from the secret for the CURRENT step so
	// totp.Validate accepts it.
	code, err := totp.GenerateCode(method.Secret, time.Now())
	require.NoError(t, err)

	repo := &mockMFARepo{
		findVerifiedByUserFn: func(_ uuid.UUID) (*model.MFAMethod, error) {
			return method, nil
		},
		updateFn: func(m *model.MFAMethod) error {
			// Persist the last-used step on the shared method pointer
			// so the second call sees the bumped value.
			method.LastUsedTOTPStep = m.LastUsedTOTPStep
			return nil
		},
	}
	svc := newTestService(repo)

	valid, err := svc.ValidateCode(userID, code)
	require.NoError(t, err, "first use of a fresh code must succeed")
	assert.True(t, valid)

	valid2, err2 := svc.ValidateCode(userID, code)
	require.Error(t, err2, "second use of the same code inside the step must be refused")
	assert.False(t, valid2)
}
