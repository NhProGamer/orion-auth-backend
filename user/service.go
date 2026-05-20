package user

import (
	"encoding/json"
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

// RoleAssigner is the slice of rbac.Service used to auto-assign a default
// role on registration. Defined here to keep user/ free of an rbac import.
type RoleAssigner interface {
	AssignRole(userID, roleID uuid.UUID) error
}

type Service struct {
	repo            RepositoryInterface
	hasher          *crypto.Argon2Hasher
	cfg             config.AuthConfig
	emailSender     email.Sender
	roleAssigner    RoleAssigner
	defaultRoleID   uuid.UUID
}

func NewService(repo RepositoryInterface, hasher *crypto.Argon2Hasher, cfg config.AuthConfig) *Service {
	return &Service{repo: repo, hasher: hasher, cfg: cfg}
}

// SetEmailSender sets the email sender (called after init to allow optional email).
func (s *Service) SetEmailSender(sender email.Sender) {
	s.emailSender = sender
}

// SetDefaultRole wires the role auto-assigned on registration. If roleID is
// uuid.Nil, the feature is disabled.
func (s *Service) SetDefaultRole(roleID uuid.UUID, assigner RoleAssigner) {
	s.defaultRoleID = roleID
	s.roleAssigner = assigner
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
	DisplayName *string                `json:"display_name"`
	AvatarURL   *string                `json:"avatar_url"`
	Phone       *string                `json:"phone"`
	Metadata    *model.ProfileMetadata `json:"metadata"`
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
		PasswordHash: &hash,
		DisplayName:  input.DisplayName,
		Active:       true,
	}

	if err := s.repo.Create(user); err != nil {
		slog.Error("failed to create user", "error", err)
		return nil, pkg.ErrInternal("failed to create user")
	}

	if s.roleAssigner != nil && s.defaultRoleID != uuid.Nil {
		if err := s.roleAssigner.AssignRole(user.ID, s.defaultRoleID); err != nil {
			slog.Warn("failed to assign default role to new user", "user_id", user.ID, "role_id", s.defaultRoleID, "error", err)
		}
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

	// Federated-only accounts have no local password yet. Refuse the login
	// without revealing whether the email exists; the user must complete
	// the account or sign in via the federation provider.
	if user.PasswordHash == nil {
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	match, err := s.hasher.Verify(input.Password, *user.PasswordHash)
	if err != nil || !match {
		s.incrementFailedAttempts(user)
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	// Reset failed attempts on successful login
	if user.FailedLoginAttempts > 0 {
		_ = s.repo.UpdateFields(user.ID, map[string]any{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		})
	}

	return user, nil
}

func (s *Service) List(page, perPage int) ([]model.User, int64, error) {
	return s.repo.List(page, perPage)
}

// RegisterAdmin creates a user with explicit control over which roles are
// assigned, bypassing the default-role hook. Used by the M2M provisioning
// API where the caller specifies the exact rôle set. If roleIDs is empty,
// no role is assigned at all — the user will have zero roles until an admin
// (or another M2M call) sets some.
func (s *Service) RegisterAdmin(input RegisterInput, roleIDs []uuid.UUID) (*model.User, error) {
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

	u := &model.User{
		Email:        input.Email,
		PasswordHash: &hash,
		DisplayName:  input.DisplayName,
		Active:       true,
	}
	if err := s.repo.Create(u); err != nil {
		slog.Error("failed to create user via admin path", "error", err)
		return nil, pkg.ErrInternal("failed to create user")
	}

	if s.roleAssigner != nil {
		for _, rid := range roleIDs {
			if err := s.roleAssigner.AssignRole(u.ID, rid); err != nil {
				slog.Warn("failed to assign role to admin-created user", "user_id", u.ID, "role_id", rid, "error", err)
			}
		}
	}

	slog.Info("user registered via admin path", "user_id", u.ID, "email", u.Email, "roles", len(roleIDs))
	return u, nil
}

// M2MUpdateInput mirrors UpdateProfileInput and AdminUpdateInput but exposes
// every mutable user field at once so an M2M caller can PATCH any subset.
// All fields are optional pointers — only non-nil ones are applied.
type M2MUpdateInput struct {
	Email         *string                `json:"email"`
	EmailVerified *bool                  `json:"email_verified"`
	DisplayName   *string                `json:"display_name"`
	AvatarURL     *string                `json:"avatar_url"`
	Phone         *string                `json:"phone"`
	Active        *bool                  `json:"active"`
	Metadata      *model.ProfileMetadata `json:"metadata"`
}

// M2MUpdate applies any non-nil field of M2MUpdateInput on the target user.
// Email uniqueness is checked. Metadata is merged into existing claims (same
// semantics as UpdateProfile).
func (s *Service) M2MUpdate(id uuid.UUID, input M2MUpdateInput) (*model.User, error) {
	u, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*input.Email))
		if email != u.Email {
			existing, err := s.repo.FindByEmail(email)
			if err != nil {
				return nil, pkg.ErrInternal("failed to check email")
			}
			if existing != nil && existing.ID != id {
				return nil, pkg.ErrConflict("email already in use")
			}
			u.Email = email
		}
	}
	if input.EmailVerified != nil {
		u.EmailVerified = *input.EmailVerified
	}
	if input.DisplayName != nil {
		u.DisplayName = input.DisplayName
	}
	if input.AvatarURL != nil {
		u.AvatarURL = input.AvatarURL
	}
	if input.Phone != nil {
		u.Phone = input.Phone
	}
	if input.Active != nil {
		u.Active = *input.Active
	}
	if input.Metadata != nil {
		merged := u.GetProfileMetadata()
		mergeProfileMetadata(&merged, input.Metadata)
		raw, err := json.Marshal(merged)
		if err != nil {
			return nil, pkg.ErrInternal("failed to marshal metadata")
		}
		u.Metadata = raw
	}

	if err := s.repo.Update(u); err != nil {
		return nil, pkg.ErrInternal("failed to update user")
	}
	return u, nil
}

// SetPassword overwrites the user's password hash unconditionally (used by
// the M2M API — no current-password check, the caller is trusted via scope).
// Returns the user for downstream side effects (sessions revoke, audit).
func (s *Service) SetPassword(id uuid.UUID, newPassword string) error {
	if len(newPassword) < s.cfg.PasswordMinLen {
		return pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return pkg.ErrInternal("failed to hash password")
	}
	return s.repo.UpdateFields(id, map[string]any{
		"password_hash":     hash,
		"must_set_password": false,
	})
}

// SetInitialPassword finalises onboarding for a user provisioned without a
// local password (federation-only signup). Allowed only when the user
// currently has no PasswordHash or carries the MustSetPassword flag, to
// avoid letting authenticated users bypass the standard ChangePassword
// flow (which requires the current password).
func (s *Service) SetInitialPassword(id uuid.UUID, newPassword string) error {
	if len(newPassword) < s.cfg.PasswordMinLen {
		return pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}
	u, err := s.GetByID(id)
	if err != nil {
		return err
	}
	if u.PasswordHash != nil && !u.MustSetPassword {
		return pkg.ErrBadRequest("password already set; use the change-password endpoint instead")
	}
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return pkg.ErrInternal("failed to hash password")
	}
	return s.repo.UpdateFields(id, map[string]any{
		"password_hash":     hash,
		"must_set_password": false,
	})
}

// FederationProvisionInput carries the subset of normalised claims used to
// create or refresh a user from a federation provider.
type FederationProvisionInput struct {
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
}

// CreateFromFederation inserts a brand-new user with no local password.
// The caller (federation.Service.findOrProvisionUser) is responsible for
// gating this call by registration_enabled / invitation tokens; this
// method only enforces the basic email-uniqueness and persistence
// invariants. The returned user has MustSetPassword=true so the AuthUI
// onboarding flow forces the user through SetInitialPassword.
func (s *Service) CreateFromFederation(input FederationProvisionInput, roleIDs []uuid.UUID) (*model.User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		return nil, pkg.ErrBadRequest("federation provider returned no email")
	}

	existing, err := s.repo.FindByEmail(email)
	if err != nil {
		return nil, pkg.ErrInternal("failed to check existing user")
	}
	if existing != nil {
		return nil, pkg.ErrConflict("email already registered")
	}

	u := &model.User{
		Email:           email,
		EmailVerified:   input.EmailVerified,
		MustSetPassword: true,
		Active:          true,
	}
	if input.DisplayName != "" {
		d := input.DisplayName
		u.DisplayName = &d
	}
	if input.AvatarURL != "" {
		a := input.AvatarURL
		u.AvatarURL = &a
	}

	if err := s.repo.Create(u); err != nil {
		slog.Error("failed to create user via federation path", "error", err)
		return nil, pkg.ErrInternal("failed to create user")
	}

	if s.roleAssigner != nil {
		for _, rid := range roleIDs {
			if err := s.roleAssigner.AssignRole(u.ID, rid); err != nil {
				slog.Warn("failed to assign role to federation-created user", "user_id", u.ID, "role_id", rid, "error", err)
			}
		}
	}

	slog.Info("user provisioned via federation", "user_id", u.ID, "email", u.Email, "email_verified", input.EmailVerified)
	return u, nil
}

// Unlock clears the lock-out state on a user — failed login attempts reset
// to 0 and locked_until cleared.
func (s *Service) Unlock(id uuid.UUID) error {
	return s.repo.UpdateFields(id, map[string]any{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	})
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
	if input.Metadata != nil {
		merged := user.GetProfileMetadata()
		mergeProfileMetadata(&merged, input.Metadata)
		raw, err := json.Marshal(merged)
		if err != nil {
			return nil, pkg.ErrInternal("failed to marshal metadata")
		}
		user.Metadata = raw
	}

	if err := s.repo.Update(user); err != nil {
		return nil, pkg.ErrInternal("failed to update profile")
	}
	return user, nil
}

// VerifyPassword returns true iff the supplied plaintext matches the user's
// stored hash. Used by the reauth package to validate password-based step-up.
// Returns false (no error) when the user has no local password yet (a
// federation-only account that has not completed onboarding).
func (s *Service) VerifyPassword(id uuid.UUID, password string) (bool, error) {
	user, err := s.repo.FindByID(id)
	if err != nil {
		return false, err
	}
	if user == nil || user.PasswordHash == nil {
		return false, nil
	}
	return s.hasher.Verify(password, *user.PasswordHash)
}

// UpdateFields is a thin pass-through used by the account package to apply
// targeted partial updates (e.g. email change, deletion scheduling).
func (s *Service) UpdateFields(id uuid.UUID, fields map[string]any) error {
	return s.repo.UpdateFields(id, fields)
}

// FindByEmailChangeToken proxies to the repository.
func (s *Service) FindByEmailChangeToken(tokenHash string) (*model.User, error) {
	return s.repo.FindByEmailChangeToken(tokenHash)
}

// FindByDeletionToken proxies to the repository.
func (s *Service) FindByDeletionToken(tokenHash string) (*model.User, error) {
	return s.repo.FindByDeletionToken(tokenHash)
}

// FindByEmail proxies to the repository.
func (s *Service) FindByEmail(email string) (*model.User, error) {
	return s.repo.FindByEmail(email)
}

func (s *Service) ChangePassword(id uuid.UUID, input ChangePasswordInput) error {
	if len(input.NewPassword) < s.cfg.PasswordMinLen {
		return pkg.ErrBadRequest(fmt.Sprintf("password must be at least %d characters", s.cfg.PasswordMinLen))
	}

	user, err := s.GetByID(id)
	if err != nil {
		return err
	}

	if user.PasswordHash == nil {
		return pkg.ErrBadRequest("account has no password set yet; use the set-password endpoint instead")
	}

	match, err := s.hasher.Verify(input.CurrentPassword, *user.PasswordHash)
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
		slog.Warn("no email sender configured, verification token not sent", "user_id", userID)
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
		slog.Warn("no email sender configured, reset token not sent", "email", u.Email)
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

// mergeProfileMetadata updates dst fields with non-nil values from src.
func mergeProfileMetadata(dst *model.ProfileMetadata, src *model.ProfileMetadata) {
	if src.GivenName != nil {
		dst.GivenName = src.GivenName
	}
	if src.FamilyName != nil {
		dst.FamilyName = src.FamilyName
	}
	if src.MiddleName != nil {
		dst.MiddleName = src.MiddleName
	}
	if src.Nickname != nil {
		dst.Nickname = src.Nickname
	}
	if src.PreferredUsername != nil {
		dst.PreferredUsername = src.PreferredUsername
	}
	if src.ProfileURL != nil {
		dst.ProfileURL = src.ProfileURL
	}
	if src.Website != nil {
		dst.Website = src.Website
	}
	if src.Gender != nil {
		dst.Gender = src.Gender
	}
	if src.Birthdate != nil {
		dst.Birthdate = src.Birthdate
	}
	if src.Zoneinfo != nil {
		dst.Zoneinfo = src.Zoneinfo
	}
	if src.Locale != nil {
		dst.Locale = src.Locale
	}
	if src.PhoneVerified != nil {
		dst.PhoneVerified = src.PhoneVerified
	}
	if src.Address != nil {
		dst.Address = src.Address
	}
}
