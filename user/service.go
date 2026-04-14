package user

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/email"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Service struct {
	repo        *Repository
	hasher      *crypto.Argon2Hasher
	cfg         config.AuthConfig
	emailSender email.Sender
}

func NewService(repo *Repository, hasher *crypto.Argon2Hasher, cfg config.AuthConfig) *Service {
	return &Service{repo: repo, hasher: hasher, cfg: cfg}
}

// SetEmailSender sets the email sender (called after init to allow optional email).
func (s *Service) SetEmailSender(sender email.Sender) {
	s.emailSender = sender
}

type RegisterInput struct {
	Email       string  `json:"email" binding:"required,email"`
	Password    string  `json:"password" binding:"required"`
	DisplayName *string `json:"display_name"`
}

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UpdateProfileInput struct {
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Phone       *string `json:"phone"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (s *Service) Register(input RegisterInput) (*model.User, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if len(input.Password) < s.cfg.PasswordMinLen {
		return nil, pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}

	existing, err := s.repo.FindByEmail(input.Email)
	if err != nil {
		return nil, pkg.ErrInternal("failed to check existing user")
	}
	if existing != nil {
		return nil, pkg.ErrConflict("email already registered")
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, pkg.ErrInternal("failed to hash password")
	}

	user := &model.User{
		Email:        input.Email,
		PasswordHash: hash,
		DisplayName:  input.DisplayName,
		Active:       true,
	}

	if err := s.repo.Create(user); err != nil {
		slog.Error("failed to create user", "error", err)
		return nil, pkg.ErrInternal("failed to create user")
	}

	slog.Info("user registered", "user_id", user.ID, "email", user.Email)
	return user, nil
}

func (s *Service) Authenticate(input LoginInput) (*model.User, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	user, err := s.repo.FindByEmail(input.Email)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find user")
	}
	if user == nil {
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	if !user.Active {
		return nil, pkg.ErrForbidden("account is deactivated")
	}

	if user.IsLocked() {
		return nil, pkg.ErrAccountLocked("account is temporarily locked due to too many failed login attempts")
	}

	match, err := s.hasher.Verify(input.Password, user.PasswordHash)
	if err != nil || !match {
		s.incrementFailedAttempts(user)
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	// Reset failed attempts on successful login
	if user.FailedLoginAttempts > 0 {
		_ = s.repo.UpdateFields(user.ID, map[string]any{
			"failed_login_attempts": 0,
			"locked_until":         nil,
		})
	}

	return user, nil
}

func (s *Service) List(page, perPage int) ([]model.User, int64, error) {
	return s.repo.List(page, perPage)
}

type AdminUpdateInput struct {
	Email         *string `json:"email"`
	DisplayName   *string `json:"display_name"`
	Active        *bool   `json:"active"`
	EmailVerified *bool   `json:"email_verified"`
}

func (s *Service) AdminUpdate(id uuid.UUID, input AdminUpdateInput) (*model.User, error) {
	user, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*input.Email))
		existing, err := s.repo.FindByEmail(email)
		if err != nil {
			return nil, pkg.ErrInternal("failed to check email")
		}
		if existing != nil && existing.ID != id {
			return nil, pkg.ErrConflict("email already in use")
		}
		user.Email = email
	}
	if input.DisplayName != nil {
		user.DisplayName = input.DisplayName
	}
	if input.Active != nil {
		user.Active = *input.Active
	}
	if input.EmailVerified != nil {
		user.EmailVerified = *input.EmailVerified
	}

	if err := s.repo.Update(user); err != nil {
		return nil, pkg.ErrInternal("failed to update user")
	}
	return user, nil
}

func (s *Service) Delete(id uuid.UUID) error {
	_, err := s.GetByID(id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(id); err != nil {
		slog.Error("failed to delete user", "error", err)
		return pkg.ErrInternal("failed to delete user")
	}
	slog.Info("user deleted", "user_id", id)
	return nil
}

func (s *Service) GetByID(id uuid.UUID) (*model.User, error) {
	user, err := s.repo.FindByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find user")
	}
	if user == nil {
		return nil, pkg.ErrNotFound("user not found")
	}
	return user, nil
}

func (s *Service) UpdateProfile(id uuid.UUID, input UpdateProfileInput) (*model.User, error) {
	user, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		user.DisplayName = input.DisplayName
	}
	if input.AvatarURL != nil {
		user.AvatarURL = input.AvatarURL
	}
	if input.Phone != nil {
		user.Phone = input.Phone
	}

	if err := s.repo.Update(user); err != nil {
		return nil, pkg.ErrInternal("failed to update profile")
	}
	return user, nil
}

func (s *Service) ChangePassword(id uuid.UUID, input ChangePasswordInput) error {
	if len(input.NewPassword) < s.cfg.PasswordMinLen {
		return pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}

	user, err := s.GetByID(id)
	if err != nil {
		return err
	}

	match, err := s.hasher.Verify(input.CurrentPassword, user.PasswordHash)
	if err != nil || !match {
		return pkg.ErrUnauthorized("current password is incorrect")
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return pkg.ErrInternal("failed to hash password")
	}

	return s.repo.UpdateFields(id, map[string]any{"password_hash": hash})
}

// --- Email Verification ---

func (s *Service) SendVerificationEmail(userID uuid.UUID) error {
	u, err := s.GetByID(userID)
	if err != nil {
		return err
	}
	if u.EmailVerified {
		return pkg.ErrBadRequest("email already verified")
	}

	token, err := crypto.GenerateRandomString(32)
	if err != nil {
		return pkg.ErrInternal("failed to generate verification token")
	}

	tokenHash := crypto.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := s.repo.UpdateFields(userID, map[string]any{
		"email_verify_token":      tokenHash,
		"email_verify_expires_at": expiresAt,
	}); err != nil {
		return pkg.ErrInternal("failed to store verification token")
	}

	if s.emailSender != nil {
		if err := s.emailSender.SendVerificationEmail(u.Email, token); err != nil {
			slog.Error("failed to send verification email", "error", err)
		}
	} else {
		slog.Info("verification token generated (no email sender configured)", "token", token, "user_id", userID)
	}

	return nil
}

type VerifyEmailInput struct {
	Token string `json:"token" binding:"required"`
}

func (s *Service) VerifyEmail(input VerifyEmailInput) error {
	tokenHash := crypto.HashToken(input.Token)

	u, err := s.repo.FindByVerifyToken(tokenHash)
	if err != nil {
		return pkg.ErrInternal("failed to verify email")
	}
	if u == nil {
		return pkg.ErrBadRequest("invalid or expired verification token")
	}

	return s.repo.UpdateFields(u.ID, map[string]any{
		"email_verified":          true,
		"email_verify_token":      nil,
		"email_verify_expires_at": nil,
	})
}

// --- Password Reset ---

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required,email"`
}

func (s *Service) ForgotPassword(input ForgotPasswordInput) error {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	u, err := s.repo.FindByEmail(input.Email)
	if err != nil || u == nil {
		// Don't reveal whether the email exists
		return nil
	}

	token, err := crypto.GenerateRandomString(32)
	if err != nil {
		return pkg.ErrInternal("failed to generate reset token")
	}

	tokenHash := crypto.HashToken(token)
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.repo.UpdateFields(u.ID, map[string]any{
		"password_reset_token":      tokenHash,
		"password_reset_expires_at": expiresAt,
	}); err != nil {
		return pkg.ErrInternal("failed to store reset token")
	}

	if s.emailSender != nil {
		if err := s.emailSender.SendPasswordResetEmail(u.Email, token); err != nil {
			slog.Error("failed to send reset email", "error", err)
		}
	} else {
		slog.Info("reset token generated (no email sender configured)", "token", token, "email", u.Email)
	}

	return nil
}

type ResetPasswordInput struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func (s *Service) ResetPassword(input ResetPasswordInput) error {
	if len(input.NewPassword) < s.cfg.PasswordMinLen {
		return pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}

	tokenHash := crypto.HashToken(input.Token)
	u, err := s.repo.FindByResetToken(tokenHash)
	if err != nil {
		return pkg.ErrInternal("failed to verify reset token")
	}
	if u == nil {
		return pkg.ErrBadRequest("invalid or expired reset token")
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return pkg.ErrInternal("failed to hash password")
	}

	return s.repo.UpdateFields(u.ID, map[string]any{
		"password_hash":             hash,
		"password_reset_token":      nil,
		"password_reset_expires_at": nil,
		"failed_login_attempts":     0,
		"locked_until":              nil,
	})
}

func (s *Service) incrementFailedAttempts(user *model.User) {
	attempts := user.FailedLoginAttempts + 1
	fields := map[string]any{
		"failed_login_attempts": attempts,
	}

	if attempts >= s.cfg.MaxFailAttempts {
		lockUntil := time.Now().Add(s.cfg.LockoutDuration)
		fields["locked_until"] = lockUntil
		slog.Warn("account locked due to failed attempts", "user_id", user.ID, "attempts", attempts)
	}

	_ = s.repo.UpdateFields(user.ID, fields)
}
