package mfa

import (
	"log/slog"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pquerna/otp/totp"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

const (
	totpIssuer     = "orion-auth-backend"
	backupCodeCount = 10
)

type Service struct {
	repo   *Repository
	hasher *crypto.Argon2Hasher
}

func NewService(repo *Repository, hasher *crypto.Argon2Hasher) *Service {
	return &Service{repo: repo, hasher: hasher}
}

type EnrollResponse struct {
	Secret    string `json:"secret"`
	URL       string `json:"url"`
	MFAMethod *model.MFAMethod `json:"mfa_method"`
}

// Enroll generates a new TOTP secret for the user.
func (s *Service) Enroll(userID uuid.UUID, email string) (*EnrollResponse, error) {
	// Check if already enrolled
	existing, err := s.repo.FindByUserAndType(userID, "totp")
	if err != nil {
		return nil, pkg.ErrInternal("failed to check existing MFA")
	}
	if existing != nil && existing.Verified {
		return nil, pkg.ErrConflict("TOTP already enrolled and verified")
	}

	// If there's an unverified enrollment, delete it
	if existing != nil {
		_ = s.repo.Delete(existing.ID)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: email,
	})
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate TOTP key")
	}

	method := &model.MFAMethod{
		UserID:   userID,
		Type:     "totp",
		Secret:   key.Secret(),
		Verified: false,
	}

	if err := s.repo.Create(method); err != nil {
		return nil, pkg.ErrInternal("failed to save MFA method")
	}

	slog.Info("TOTP enrolled (pending verification)", "user_id", userID)
	return &EnrollResponse{
		Secret:    key.Secret(),
		URL:       key.URL(),
		MFAMethod: method,
	}, nil
}

type VerifyInput struct {
	Code string `json:"code" binding:"required"`
}

// Verify confirms the TOTP enrollment with a valid code.
func (s *Service) Verify(userID uuid.UUID, code string) ([]string, error) {
	method, err := s.repo.FindByUserAndType(userID, "totp")
	if err != nil || method == nil {
		return nil, pkg.ErrNotFound("no TOTP enrollment found")
	}
	if method.Verified {
		return nil, pkg.ErrBadRequest("TOTP already verified")
	}

	valid := totp.Validate(code, method.Secret)
	if !valid {
		return nil, pkg.ErrBadRequest("invalid TOTP code")
	}

	// Generate backup codes
	backupCodes, hashedCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate backup codes")
	}

	method.Verified = true
	method.BackupCodes = pq.StringArray(hashedCodes)

	if err := s.repo.Update(method); err != nil {
		return nil, pkg.ErrInternal("failed to activate TOTP")
	}

	slog.Info("TOTP verified and activated", "user_id", userID)
	return backupCodes, nil
}

// ValidateCode validates a TOTP code or backup code for a user.
func (s *Service) ValidateCode(userID uuid.UUID, code string) (bool, error) {
	method, err := s.repo.FindVerifiedByUser(userID)
	if err != nil || method == nil {
		return false, nil // No MFA configured
	}

	// Try TOTP first
	if totp.Validate(code, method.Secret) {
		return true, nil
	}

	// Try backup codes
	codeHash := crypto.HashToken(code)
	for i, bc := range method.BackupCodes {
		if bc == codeHash {
			// Remove used backup code
			method.BackupCodes = append(method.BackupCodes[:i], method.BackupCodes[i+1:]...)
			_ = s.repo.Update(method)
			slog.Info("backup code used", "user_id", userID)
			return true, nil
		}
	}

	return false, nil
}

// HasMFA checks if the user has a verified MFA method.
func (s *Service) HasMFA(userID uuid.UUID) (bool, error) {
	method, err := s.repo.FindVerifiedByUser(userID)
	if err != nil {
		return false, err
	}
	return method != nil, nil
}

// Disable removes the TOTP enrollment for the user.
func (s *Service) Disable(userID uuid.UUID, code string) error {
	method, err := s.repo.FindVerifiedByUser(userID)
	if err != nil || method == nil {
		return pkg.ErrNotFound("no verified MFA method found")
	}

	// Require a valid code to disable
	if !totp.Validate(code, method.Secret) {
		return pkg.ErrBadRequest("invalid TOTP code")
	}

	if err := s.repo.Delete(method.ID); err != nil {
		return pkg.ErrInternal("failed to disable MFA")
	}

	slog.Info("TOTP disabled", "user_id", userID)
	return nil
}

// RegenerateBackupCodes generates new backup codes (requires valid TOTP code).
func (s *Service) RegenerateBackupCodes(userID uuid.UUID, code string) ([]string, error) {
	method, err := s.repo.FindVerifiedByUser(userID)
	if err != nil || method == nil {
		return nil, pkg.ErrNotFound("no verified MFA method found")
	}

	if !totp.Validate(code, method.Secret) {
		return nil, pkg.ErrBadRequest("invalid TOTP code")
	}

	backupCodes, hashedCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate backup codes")
	}

	method.BackupCodes = pq.StringArray(hashedCodes)
	if err := s.repo.Update(method); err != nil {
		return nil, pkg.ErrInternal("failed to save backup codes")
	}

	slog.Info("backup codes regenerated", "user_id", userID)
	return backupCodes, nil
}

func (s *Service) generateBackupCodes() (raw []string, hashed []string, err error) {
	raw = make([]string, backupCodeCount)
	hashed = make([]string, backupCodeCount)

	for i := 0; i < backupCodeCount; i++ {
		code, err := crypto.GenerateRandomString(6) // ~8 char code
		if err != nil {
			return nil, nil, err
		}
		raw[i] = code
		hashed[i] = crypto.HashToken(code)
	}

	return raw, hashed, nil
}
