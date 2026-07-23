package user

import (
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"gorm.io/gorm"

	"orion-auth-backend/actiontoken"
	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/email"
	"orion-auth-backend/model"
	"orion-auth-backend/password"
	"orion-auth-backend/pkg"
	"orion-auth-backend/pkg/clock"
)

// RoleAssigner is the slice of rbac.Service used to auto-assign a default
// role on registration. Defined here to keep user/ free of an rbac import.
//
// AssignRoleInTx binds the assignment to a caller-supplied transaction so
// the user create + role assignment commit together. Implementations
// should fall back to the non-Tx path when tx is nil — tests with mock
// repos pass nil since they have no transaction semantics.
type RoleAssigner interface {
	AssignRole(userID, roleID uuid.UUID) error
	AssignRoleInTx(tx *gorm.DB, userID, roleID uuid.UUID) error
}

// EmailVerificationGate is the read-side of the
// registration_email_verification_required setting. When the gate reports
// true (default) Authenticate refuses to sign in users with
// EmailVerified=false. Injected from invitation.Service (which owns the
// settings table) so user/ stays free of an invitation import.
type EmailVerificationGate interface {
	IsEmailVerificationRequired() bool
}

type Service struct {
	repo                  RepositoryInterface
	hasher                *crypto.Argon2Hasher
	cfg                   config.AuthConfig
	emailSender           email.Sender
	roleAssigner          RoleAssigner
	defaultRoleID         uuid.UUID
	regForm               RegFormProvider
	passwordValidator     *password.Validator
	actionTokenSigningKey []byte
	emailVerifyGate       EmailVerificationGate
	clock                 clock.Clock
	db                    *gorm.DB
}

// Options bundles every dependency a user.Service needs at
// construction time. Required fields are documented; optional fields
// disable a feature when zero-valued (e.g. an unset EmailSender skips
// verification emails). Passing everything via Options gives a single
// compile-time-visible struct rather than a chain of post-construction
// Set*() calls — a forgotten field is the wrong shape, not a
// runtime panic.
//
// Two dependencies remain on dedicated setters because they cannot be
// supplied at construction time:
//   - SetEmailVerificationGate: the invitation.Service depends on
//     user.Service, so the gate is wired AFTER both exist (real
//     circular dependency).
//   - SetDefaultRole: deliberately deferred until AFTER seedDefaults
//     so the seeded admin user doesn't pick up the default user role
//     on top of admin.
type Options struct {
	// Required
	Repo   RepositoryInterface
	Hasher *crypto.Argon2Hasher
	Cfg    config.AuthConfig

	// Optional — leaving them zero-valued disables the corresponding
	// code path with the documented secure default.
	EmailSender           email.Sender
	RegFormProvider       RegFormProvider
	PasswordValidator     *password.Validator
	ActionTokenSigningKey []byte

	// Clock injects the time source. When nil, the service falls back
	// to clock.Real() — tests opt into a *clock.Fake to control
	// lockout / TTL windows deterministically.
	Clock clock.Clock

	// DB is the gorm handle used to compose Register / verification /
	// password-reset writes in a single transaction. When nil (the
	// default in unit tests), the service runs each repo call directly
	// without a Tx; in production main.go wires the real *gorm.DB so
	// failures roll back the whole flow.
	DB *gorm.DB
}

func NewService(o Options) *Service {
	clk := o.Clock
	if clk == nil {
		clk = clock.Real()
	}
	return &Service{
		repo:                  o.Repo,
		hasher:                o.Hasher,
		cfg:                   o.Cfg,
		emailSender:           o.EmailSender,
		regForm:               o.RegFormProvider,
		passwordValidator:     o.PasswordValidator,
		actionTokenSigningKey: o.ActionTokenSigningKey,
		clock:                 clk,
		db:                    o.DB,
	}
}

// withTx runs fn inside a database transaction when one is available,
// or pass-through when no *gorm.DB is wired (unit tests). The supplied
// repo is the Tx-bound view when applicable; tx is nil in the
// pass-through case so callers can branch the rare site that still
// needs a raw DB handle.
func (s *Service) withTx(fn func(repo RepositoryInterface, tx *gorm.DB) error) error {
	if s.db == nil {
		return fn(s.repo, nil)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		return fn(s.repo.WithTx(tx), tx)
	})
}

// SetEmailVerificationGate wires the invitation-backed admin gate.
// Kept as a setter because invitation.Service has user.Service as a
// dependency — passing it at NewService time would form a cycle.
// When unset, secure-by-default behaviour requires email verification.
func (s *Service) SetEmailVerificationGate(g EmailVerificationGate) {
	s.emailVerifyGate = g
}

// SetDefaultRole wires the role auto-assigned on registration. Kept
// as a setter so it can be called AFTER seedDefaults: the seeded
// admin must not pick up the default user role on top of admin.
// Passing uuid.Nil + nil disables the feature.
func (s *Service) SetDefaultRole(roleID uuid.UUID, assigner RoleAssigner) {
	s.defaultRoleID = roleID
	s.roleAssigner = assigner
}

func (s *Service) requiresEmailVerification() bool {
	if s.emailVerifyGate == nil {
		return true
	}
	return s.emailVerifyGate.IsEmailVerificationRequired()
}

// validatePassword applies the active password policy. Hints are values
// the user already typed in the same form (email, display name…); they
// get fed to zxcvbn so it can penalise passwords that just repeat them.
func (s *Service) validatePassword(pwd string, hints ...string) error {
	return s.passwordValidator.Validate(pwd, hints...)
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// userHintsForID resolves email + display name for a known user, returning
// them as zxcvbn hints. Best-effort: a DB miss yields an empty slice so
// the password validation still runs (just without contextual penalties).
func (s *Service) userHintsForID(id uuid.UUID) []string {
	u, err := s.repo.FindByID(id)
	if err != nil || u == nil {
		return nil
	}
	hints := []string{u.Email}
	if u.DisplayName != nil && *u.DisplayName != "" {
		hints = append(hints, *u.DisplayName)
	}
	return hints
}

type RegisterInput struct {
	Email       string         `json:"email" binding:"required,email"`
	Password    string         `json:"password" binding:"required"`
	DisplayName *string        `json:"display_name"`
	ExtraFields map[string]any `json:"extra_fields,omitempty"`
	// SkipVerificationEmail suppresses the built-in verify-email enqueue.
	// Internal only (json:"-"): the OAuth authorize-register flow sets it so
	// it can send a single email carrying the authorization request id,
	// instead of Register sending a context-less one that gets overwritten.
	SkipVerificationEmail bool `json:"-"`
}

// RegFormProvider exposes the registration-fields schema lookup so
// user.Service can validate and apply admin-defined extra fields
// without taking a direct dependency on the regform package. Injected
// via SetRegFormProvider; nil = no dynamic fields (legacy behaviour).
type RegFormProvider interface {
	ListForContext(context string) ([]model.RegistrationField, error)
	Apply(u *model.User, extras map[string]any, schema []model.RegistrationField, context string) error
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

	if err := s.validatePassword(input.Password, input.Email, derefStr(input.DisplayName)); err != nil {
		return nil, err
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

	if err := s.applyRegFormExtras(user, input.ExtraFields, "register"); err != nil {
		return nil, err
	}

	// Atomic create + default-role assignment + verify-email enqueue.
	// Any failure rolls back the user row — better to surface a 5xx
	// than to leave a userless-of-role account or a verified email
	// gate that no email was ever sent for.
	err = s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		if err := repo.Create(user); err != nil {
			slog.Error("failed to create user", "error", err)
			return pkg.ErrInternal("failed to create user")
		}
		if s.roleAssigner != nil && s.defaultRoleID != uuid.Nil {
			if err := s.roleAssigner.AssignRoleInTx(tx, user.ID, s.defaultRoleID); err != nil {
				return pkg.ErrInternal("failed to assign default role: " + err.Error())
			}
		}
		if !input.SkipVerificationEmail {
			if err := s.enqueueVerifyEmailInTx(tx, repo, user, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	slog.Info("user registered", "user_id", user.ID, "email", user.Email)
	return user, nil
}

// enqueueVerifyEmailInTx persists the verification JTI on the user row
// and enqueues the email — both inside the supplied Tx when available.
// Behaviour matches SendVerificationEmail except a side-effect failure
// now returns an error (so the caller's Tx rolls back) instead of being
// swallowed by slog.Warn. The action token signing key being unset is
// not fatal here — the verify-email flow simply degrades to "no email
// sent" and the user can request a resend later.
func (s *Service) enqueueVerifyEmailInTx(tx *gorm.DB, repo RepositoryInterface, u *model.User, authRequestID *uuid.UUID) error {
	if len(s.actionTokenSigningKey) == 0 {
		// Boot-time misconfig: don't fail the registration over it.
		slog.Warn("action_token_signing_key not configured; skipping verify email", "user_id", u.ID)
		return nil
	}

	jti, err := uuid.NewV7()
	if err != nil {
		return pkg.ErrInternal("failed to generate verification jti")
	}
	now := s.clock.Now()
	expiresAt := now.Add(24 * time.Hour)

	tokenStr, err := actiontoken.Sign(actiontoken.Claims{
		Subject:   u.ID,
		Action:    actiontoken.ActionVerifyEmail,
		JTI:       jti.String(),
		RequestID: authRequestID,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}, s.actionTokenSigningKey)
	if err != nil {
		return pkg.ErrInternal("failed to sign verification token")
	}

	if err := repo.UpdateFields(u.ID, map[string]any{
		"email_verify_token":      jti.String(),
		"email_verify_expires_at": expiresAt,
	}); err != nil {
		return pkg.ErrInternal("failed to store verification jti")
	}

	if s.emailSender == nil {
		slog.Warn("no email sender configured, verification token not enqueued", "user_id", u.ID)
		return nil
	}
	if tx != nil {
		if txSender, ok := s.emailSender.(email.TxSender); ok {
			return txSender.SendVerificationEmailInTx(tx, u.Email, tokenStr)
		}
	}
	return s.emailSender.SendVerificationEmail(u.Email, tokenStr)
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

	if user.LockedUntil != nil && user.LockedUntil.After(s.clock.Now()) {
		return nil, pkg.ErrAccountLocked("account is temporarily locked due to too many failed login attempts")
	}

	// Federated-only accounts have no local password yet. Refuse the login
	// without revealing whether the email exists; the user must complete
	// the account or sign in via the federation provider.
	if user.PasswordHash == nil {
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	match, needsRehash, err := s.hasher.VerifyIdentify(input.Password, *user.PasswordHash)
	if err != nil || !match {
		s.incrementFailedAttempts(user)
		return nil, pkg.ErrUnauthorized("invalid email or password")
	}

	// Transparently upgrade a hash imported from a foreign IAM (Logto Argon2i,
	// bcrypt, or a legacy digest) to the native argon2id scheme now that we
	// hold the plaintext and know it is correct. Best-effort: never blocks login.
	s.maybeRehash(user, input.Password, needsRehash)

	// Email verification gate: check AFTER the password match so an
	// attacker probing existence cannot tell verified from unverified
	// accounts apart without also knowing the password.
	if !user.EmailVerified && s.requiresEmailVerification() {
		return nil, pkg.ErrEmailNotVerified("verify your email to sign in")
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

// Search lists users matching a case-insensitive substring against email,
// display name or ID. An empty q returns the full paginated list.
func (s *Service) Search(q string, page, perPage int) ([]model.User, int64, error) {
	return s.repo.Search(q, page, perPage)
}

// RegisterAdmin creates a user with explicit control over which roles are
// assigned, bypassing the default-role hook. Used by the M2M provisioning
// API where the caller specifies the exact rôle set. If roleIDs is empty,
// no role is assigned at all — the user will have zero roles until an admin
// (or another M2M call) sets some.
func (s *Service) RegisterAdmin(input RegisterInput, roleIDs []uuid.UUID) (*model.User, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if err := s.validatePassword(input.Password, input.Email, derefStr(input.DisplayName)); err != nil {
		return nil, err
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

	// Tx: user row + every requested role assignment commit together.
	// A partial failure used to leave a user with a subset of the
	// intended roles and was logged as a Warn only; now it rolls back
	// and the caller (M2M admin API) sees the exact failing role.
	if err := s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		if err := repo.Create(u); err != nil {
			slog.Error("failed to create user via admin path", "error", err)
			return pkg.ErrInternal("failed to create user")
		}
		if s.roleAssigner == nil {
			return nil
		}
		for _, rid := range roleIDs {
			if err := s.roleAssigner.AssignRoleInTx(tx, u.ID, rid); err != nil {
				return pkg.ErrInternal("failed to assign role " + rid.String() + ": " + err.Error())
			}
		}
		return nil
	}); err != nil {
		return nil, err
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
	hints := s.userHintsForID(id)
	if err := s.validatePassword(newPassword, hints...); err != nil {
		return err
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
	hints := s.userHintsForID(id)
	if err := s.validatePassword(newPassword, hints...); err != nil {
		return err
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
// create or refresh a user from a federation provider. Password is the
// chosen local password the user supplies during the /complete-signup
// step (required: federation-only accounts without a local password are
// no longer supported by the new staging flow). ExtraFields carries the
// admin-defined dynamic fields collected on /complete-account.
type FederationProvisionInput struct {
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
	Password      string
	ExtraFields   map[string]any
}

// CreateFromFederation inserts a brand-new user with the password the
// user picked on the /complete-account form. The caller
// (federation.Service.CompleteSignup) is responsible for gating this
// call by registration_enabled / invitation tokens; this method only
// enforces the basic email-uniqueness, password-length, and persistence
// invariants. MustSetPassword is false: the password is set right away.
func (s *Service) CreateFromFederation(input FederationProvisionInput, roleIDs []uuid.UUID) (*model.User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		return nil, pkg.ErrBadRequest("federation provider returned no email")
	}
	if err := s.validatePassword(input.Password, email, input.DisplayName); err != nil {
		return nil, err
	}

	existing, err := s.repo.FindByEmail(email)
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
		Email:           email,
		EmailVerified:   input.EmailVerified,
		PasswordHash:    &hash,
		MustSetPassword: false,
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

	if err := s.applyRegFormExtras(u, input.ExtraFields, "federation"); err != nil {
		return nil, err
	}

	// Tx: federation-provisioned user row + role assignments commit
	// together. Failure rolls back the whole thing so the caller
	// (federation.Service.CompleteSignup) can decide between retrying
	// and surfacing the error to the AuthUI.
	if err := s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		if err := repo.Create(u); err != nil {
			slog.Error("failed to create user via federation path", "error", err)
			return pkg.ErrInternal("failed to create user")
		}
		if s.roleAssigner == nil {
			return nil
		}
		// Caller-supplied roles (from an invitation) take precedence.
		// Otherwise fall back to the default user role, matching the
		// behaviour of the password-based Register path.
		assignRoles := roleIDs
		if len(assignRoles) == 0 && s.defaultRoleID != uuid.Nil {
			assignRoles = []uuid.UUID{s.defaultRoleID}
		}
		for _, rid := range assignRoles {
			if err := s.roleAssigner.AssignRoleInTx(tx, u.ID, rid); err != nil {
				return pkg.ErrInternal("failed to assign role " + rid.String() + ": " + err.Error())
			}
		}
		return nil
	}); err != nil {
		return nil, err
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
	match, needsRehash, err := s.hasher.VerifyIdentify(password, *user.PasswordHash)
	if err != nil {
		return false, err
	}
	if match {
		s.maybeRehash(user, password, needsRehash)
	}
	return match, nil
}

// maybeRehash transparently upgrades a foreign or legacy password hash to the
// native argon2id scheme after a successful verification. Best-effort: a
// failure here must never block an otherwise-valid authentication, so errors
// are logged and swallowed.
func (s *Service) maybeRehash(u *model.User, plaintext string, needsRehash bool) {
	if !needsRehash {
		return
	}
	hash, err := s.hasher.Hash(plaintext)
	if err != nil {
		slog.Warn("failed to rehash imported password", "user_id", u.ID, "error", err)
		return
	}
	if err := s.repo.UpdateFields(u.ID, map[string]any{"password_hash": hash}); err != nil {
		slog.Warn("failed to persist rehashed password", "user_id", u.ID, "error", err)
		return
	}
	u.PasswordHash = &hash
}

// UpdateFields is a thin pass-through used by the account package to apply
// targeted partial updates (e.g. email change, deletion scheduling).
func (s *Service) UpdateFields(id uuid.UUID, fields map[string]any) error {
	return s.repo.UpdateFields(id, fields)
}

// UpdateFieldsInTx is the Tx-aware variant. Callers that compose
// session-revoke + email enqueue with the update use this so the
// whole flow commits or rolls back atomically. When tx is nil it
// falls back to the non-Tx path.
func (s *Service) UpdateFieldsInTx(tx *gorm.DB, id uuid.UUID, fields map[string]any) error {
	if tx == nil {
		return s.repo.UpdateFields(id, fields)
	}
	return s.repo.WithTx(tx).UpdateFields(id, fields)
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
	hints := s.userHintsForID(id)
	if err := s.validatePassword(input.NewPassword, hints...); err != nil {
		return err
	}

	user, err := s.GetByID(id)
	if err != nil {
		return err
	}

	if user.PasswordHash == nil {
		return pkg.ErrBadRequest("account has no password set yet; use the set-password endpoint instead")
	}

	// VerifyIdentify (not Verify) so a user imported from a foreign IAM can
	// change their password before ever doing a fresh login. The new hash
	// written below is always native argon2id, so no rehash step is needed here.
	match, _, err := s.hasher.VerifyIdentify(input.CurrentPassword, *user.PasswordHash)
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

// SendVerificationEmail produces a signed action token (JWT HS256) bound
// to the user and an optional OAuth AuthorizationRequest. The JTI is stored
// in users.email_verify_token so we can revoke or single-use the link.
//
// When authRequestID is non-nil, the verify-email handler will resume the
// OAuth flow after the user clicks the link (auto-login + redirect to the
// client's redirect_uri). When nil, the handler renders a generic success
// page — used by the standalone (non-OAuth) register path.
func (s *Service) SendVerificationEmail(userID uuid.UUID, authRequestID *uuid.UUID) error {
	u, err := s.GetByID(userID)
	if err != nil {
		return err
	}
	if u.EmailVerified {
		return pkg.ErrBadRequest("email already verified")
	}
	if len(s.actionTokenSigningKey) == 0 {
		return pkg.ErrInternal("action token signing key not configured")
	}
	// JTI persistence and outbox enqueue share the Tx so the token
	// rows and the queued email commit together — no more "user has
	// a fresh verify token but the email vanished into SMTP".
	return s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		return s.enqueueVerifyEmailInTx(tx, repo, u, authRequestID)
	})
}

// ResendVerificationEmail looks up a user by email and reissues the
// verification token, ignoring the lookup result when the user does not
// exist or is already verified — both branches return nil to avoid
// leaking which is which (anti-enumeration). The optional authRequestID
// preserves the OAuth context for auto-login post-click.
func (s *Service) ResendVerificationEmail(email string, authRequestID *uuid.UUID) error {
	email = strings.ToLower(strings.TrimSpace(email))

	u, err := s.repo.FindByEmail(email)
	if err != nil {
		return pkg.ErrInternal("failed to look up user")
	}
	if u == nil || u.EmailVerified {
		return nil
	}

	return s.SendVerificationEmail(u.ID, authRequestID)
}

// ConsumeVerificationToken validates and consumes a verification action
// token: it parses the JWT, ensures the embedded JTI matches the one on
// record, marks the user as verified, and clears the slot so the link is
// single-use. Returns the user and the optional OAuth request id from the
// token so the caller can decide whether to bootstrap a session.
func (s *Service) ConsumeVerificationToken(raw string) (*model.User, *uuid.UUID, error) {
	if len(s.actionTokenSigningKey) == 0 {
		return nil, nil, pkg.ErrInternal("action token signing key not configured")
	}
	claims, err := actiontoken.Parse(raw, s.actionTokenSigningKey)
	if err != nil {
		return nil, nil, pkg.ErrBadRequest("invalid or expired verification token")
	}
	if claims.Action != actiontoken.ActionVerifyEmail {
		return nil, nil, pkg.ErrBadRequest("invalid token action")
	}

	u, err := s.repo.FindByVerifyToken(claims.JTI)
	if err != nil {
		return nil, nil, pkg.ErrInternal("failed to verify email")
	}
	if u == nil || u.ID != claims.Subject {
		return nil, nil, pkg.ErrBadRequest("invalid or expired verification token")
	}

	if err := s.repo.UpdateFields(u.ID, map[string]any{
		"email_verified":          true,
		"email_verify_token":      nil,
		"email_verify_expires_at": nil,
	}); err != nil {
		return nil, nil, pkg.ErrInternal("failed to mark email verified")
	}

	return u, claims.RequestID, nil
}

// Deprecated: use ConsumeVerificationToken. Kept for backward compat with
// the POST /auth/verify-email handler that may still be hit by older AuthUI
// builds; behaves the same as before (raw-token DB lookup).
type VerifyEmailInput struct {
	Token string `json:"token" binding:"required"`
}

func (s *Service) VerifyEmail(input VerifyEmailInput) error {
	u, _, err := s.ConsumeVerificationToken(input.Token)
	if err != nil {
		return err
	}
	_ = u
	return nil
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
	return s.issuePasswordResetInTx(u)
}

// issuePasswordResetInTx persists a one-hour reset token on the user
// row and enqueues the reset email — both inside the same Tx so a
// failure no longer leaves the user with a fresh reset token but no
// email to act on. Used by both ForgotPassword (anti-enumerated public
// endpoint) and AdminTriggerPasswordReset (admin-initiated reset).
func (s *Service) issuePasswordResetInTx(u *model.User) error {
	token, err := crypto.GenerateRandomString(32)
	if err != nil {
		return pkg.ErrInternal("failed to generate reset token")
	}
	tokenHash := crypto.HashToken(token)
	expiresAt := s.clock.Now().Add(1 * time.Hour)

	return s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		if err := repo.UpdateFields(u.ID, map[string]any{
			"password_reset_token":      tokenHash,
			"password_reset_expires_at": expiresAt,
		}); err != nil {
			return pkg.ErrInternal("failed to store reset token")
		}
		if s.emailSender == nil {
			slog.Warn("no email sender configured, reset token not sent", "email", u.Email)
			return nil
		}
		if tx != nil {
			if txSender, ok := s.emailSender.(email.TxSender); ok {
				return txSender.SendPasswordResetEmailInTx(tx, u.Email, token)
			}
		}
		return s.emailSender.SendPasswordResetEmail(u.Email, token)
	})
}

// AdminTriggerPasswordReset issues a password reset token for the target user
// and sends the standard reset email. Unlike ForgotPassword, the user is
// looked up by ID and missing users yield ErrNotFound — the caller is an
// authenticated admin, so leaking existence is not a concern.
func (s *Service) AdminTriggerPasswordReset(userID uuid.UUID) error {
	u, err := s.repo.FindByID(userID)
	if err != nil {
		return pkg.ErrInternal("failed to find user")
	}
	if u == nil {
		return pkg.ErrNotFound("user not found")
	}

	if err := s.issuePasswordResetInTx(u); err != nil {
		return err
	}
	slog.Info("admin-initiated password reset", "target_user_id", u.ID)
	return nil
}

type ResetPasswordInput struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func (s *Service) ResetPassword(input ResetPasswordInput) error {
	// Validate password against the policy first so we don't waste a DB
	// lookup on obviously bad inputs. zxcvbn user-input hints are skipped
	// here — we don't know who the user is until the token resolves.
	if err := s.validatePassword(input.NewPassword); err != nil {
		return err
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
		lockUntil := s.clock.Now().Add(s.cfg.LockoutDuration)
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

// applyRegFormExtras validates and writes the admin-defined dynamic
// fields onto the user about to be persisted. No-op when the
// registration-fields provider is not wired (legacy deployments).
func (s *Service) applyRegFormExtras(u *model.User, extras map[string]any, context string) error {
	if s.regForm == nil {
		return nil
	}
	schema, err := s.regForm.ListForContext(context)
	if err != nil {
		return err
	}
	return s.regForm.Apply(u, extras, schema, context)
}
