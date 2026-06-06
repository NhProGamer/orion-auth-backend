package invitation

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/crypto"
	"orion-auth-backend/email"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/rbac"
	"orion-auth-backend/user"
)

type Service struct {
	repo               RepositoryInterface
	userService        *user.Service
	rbacService        *rbac.Service
	emailSender        email.Sender
	issuer             string
	allowedOrigins     []string
	defaultSessionTTL  time.Duration
	extendedSessionTTL time.Duration
	db                 *gorm.DB
}

// Options is the constructor surface for invitation.Service. All
// fields can be supplied at NewService time — no post-construction
// setters needed.
type Options struct {
	// Required
	Repo        RepositoryInterface
	UserService *user.Service
	RbacService *rbac.Service
	EmailSender email.Sender
	Issuer      string

	// Optional
	AllowedOrigins     []string      // CORS allowlist for operator-supplied redirect URLs
	DefaultSessionTTL  time.Duration // fallback when admin has not overridden
	ExtendedSessionTTL time.Duration // fallback for remember_me sessions

	// DB is the gorm handle used to wrap Create (and future Tx flows) so
	// the invitation INSERT and the outbox enqueue commit together. Tests
	// leave it nil and the service falls back to per-call writes.
	DB *gorm.DB
}

func NewService(o Options) *Service {
	return &Service{
		repo:               o.Repo,
		userService:        o.UserService,
		rbacService:        o.RbacService,
		emailSender:        o.EmailSender,
		issuer:             o.Issuer,
		allowedOrigins:     o.AllowedOrigins,
		defaultSessionTTL:  o.DefaultSessionTTL,
		extendedSessionTTL: o.ExtendedSessionTTL,
		db:                 o.DB,
	}
}

// withTx mirrors user.Service.withTx — runs fn inside a database
// transaction when DB was wired, or pass-through with a nil tx in unit
// tests. Same shape so future refactors can collapse both helpers
// into a shared package if needed.
func (s *Service) withTx(fn func(repo RepositoryInterface, tx *gorm.DB) error) error {
	if s.db == nil {
		return fn(s.repo, nil)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		return fn(s.repo.WithTx(tx), tx)
	})
}

type CreateInput struct {
	Email   string   `json:"email" binding:"required,email"`
	RoleIDs []string `json:"role_ids"`
}

type RegisterInviteInput struct {
	Token       string  `json:"token" binding:"required"`
	Password    string  `json:"password" binding:"required"`
	DisplayName *string `json:"display_name"`
}

func (s *Service) Create(input CreateInput, invitedBy uuid.UUID) (*model.Invitation, error) {
	rawToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate invitation token")
	}
	tokenHash := crypto.HashToken(rawToken)

	inv := &model.Invitation{
		Email:     input.Email,
		Token:     tokenHash,
		RoleIDs:   input.RoleIDs,
		InvitedBy: invitedBy,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	// Invitation row + outbox enqueue commit together: a previous
	// failure mode left the row INSERTed but the email send swallowed
	// with slog.Error, so admins thought the invite went out when in
	// fact the recipient never got it. Now a side-effect failure rolls
	// the row back and the admin gets a 5xx.
	if err := s.withTx(func(repo RepositoryInterface, tx *gorm.DB) error {
		if err := repo.Create(inv); err != nil {
			slog.Error("failed to create invitation", "error", err)
			return pkg.ErrInternal("failed to create invitation")
		}
		if s.emailSender == nil {
			return nil
		}
		if tx != nil {
			if txSender, ok := s.emailSender.(email.TxSender); ok {
				return txSender.SendInvitationEmailInTx(tx, input.Email, rawToken)
			}
		}
		return s.emailSender.SendInvitationEmail(input.Email, rawToken)
	}); err != nil {
		return nil, err
	}

	slog.Info("invitation created", "email", input.Email, "invited_by", invitedBy)
	return inv, nil
}

func (s *Service) List(page, perPage int) ([]model.Invitation, int64, error) {
	return s.repo.List(page, perPage)
}

func (s *Service) Delete(id uuid.UUID) error {
	inv, err := s.repo.FindByID(id)
	if err != nil {
		return pkg.ErrInternal("failed to find invitation")
	}
	if inv == nil {
		return pkg.ErrNotFound("invitation not found")
	}
	if err := s.repo.Delete(id); err != nil {
		return pkg.ErrInternal("failed to delete invitation")
	}
	slog.Info("invitation deleted", "id", id)
	return nil
}

func (s *Service) RegisterWithInvite(input RegisterInviteInput) (*model.User, error) {
	tokenHash := crypto.HashToken(input.Token)

	inv, err := s.repo.FindByToken(tokenHash)
	if err != nil {
		return nil, pkg.ErrInternal("failed to check invitation")
	}
	if inv == nil {
		return nil, pkg.ErrBadRequest("invalid or expired invitation token")
	}
	if inv.IsExpired() {
		return nil, pkg.ErrBadRequest("invitation has expired")
	}

	newUser, err := s.userService.Register(user.RegisterInput{
		Email:       inv.Email,
		Password:    input.Password,
		DisplayName: input.DisplayName,
	})
	if err != nil {
		return nil, err
	}

	// Mark email as verified (invitation was sent to this email)
	newUser.EmailVerified = true
	_, _ = s.userService.AdminUpdate(newUser.ID, user.AdminUpdateInput{EmailVerified: &newUser.EmailVerified})

	// Assign pre-configured roles
	for _, roleIDStr := range inv.RoleIDs {
		roleID, err := uuid.Parse(roleIDStr)
		if err != nil {
			slog.Warn("invalid role ID in invitation", "role_id", roleIDStr)
			continue
		}
		if err := s.rbacService.AssignRole(newUser.ID, roleID); err != nil {
			slog.Warn("failed to assign role from invitation", "role_id", roleID, "error", err)
		}
	}

	// Mark invitation as used
	now := time.Now()
	inv.Used = true
	inv.UsedAt = &now
	if err := s.repo.MarkUsed(inv); err != nil {
		slog.Error("failed to mark invitation as used", "error", err)
	}

	slog.Info("user registered via invitation", "user_id", newUser.ID, "email", newUser.Email)
	return newUser, nil
}

// ValidateToken looks up an invitation by token without consuming it.
// Returns nil if no such invitation exists or it has expired or is used.
// Useful for federation-driven onboarding which finalises invitation
// consumption only after the user has been provisioned.
func (s *Service) ValidateToken(rawToken string) (*model.Invitation, error) {
	if rawToken == "" {
		return nil, nil
	}
	tokenHash := crypto.HashToken(rawToken)
	inv, err := s.repo.FindByToken(tokenHash)
	if err != nil {
		return nil, pkg.ErrInternal("failed to check invitation")
	}
	if inv == nil || inv.Used || inv.IsExpired() {
		return nil, nil
	}
	return inv, nil
}

// ConsumeToken marks an invitation as used. Idempotent — safe to call
// multiple times after a successful federation provisioning.
func (s *Service) ConsumeToken(inv *model.Invitation) error {
	now := time.Now()
	inv.Used = true
	inv.UsedAt = &now
	if err := s.repo.MarkUsed(inv); err != nil {
		return pkg.ErrInternal("failed to mark invitation as used")
	}
	return nil
}

// Settings

func (s *Service) IsRegistrationEnabled() bool {
	val, err := s.repo.GetSetting("registration_enabled")
	if err != nil || val == "" {
		return true // default enabled
	}
	return val == "true"
}

// IsEmailVerificationRequired returns true unless the admin explicitly turned
// the gate off. Secure-by-default: missing/unreadable setting means require.
func (s *Service) IsEmailVerificationRequired() bool {
	val, err := s.repo.GetSetting("registration_email_verification_required")
	if err != nil || val == "" {
		return true
	}
	return val == "true"
}

func (s *Service) GetAllSettings() (map[string]string, error) {
	settings, err := s.repo.GetAllSettings()
	if err != nil {
		return nil, pkg.ErrInternal("failed to get settings")
	}
	result := make(map[string]string, len(settings))
	for _, s := range settings {
		result[s.Key] = s.Value
	}
	return result, nil
}

// AllowedOrigins exposes the configured allowlist for the handler.
func (s *Service) AllowedOrigins() []string {
	return s.allowedOrigins
}

// SessionTTL implements session.TTLResolver: read the admin-overridable
// setting if present and > 0, otherwise fall back to the config default.
func (s *Service) SessionTTL(extended bool) time.Duration {
	key := "default_session_ttl"
	fallback := s.defaultSessionTTL
	if extended {
		key = "default_session_extended_ttl"
		fallback = s.extendedSessionTTL
	}
	val, err := s.repo.GetSetting(key)
	if err != nil || val == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(val)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// GetPostRegisterRedirectURL returns the configured URL or empty string.
// Surfaced verbatim in /api/v1/auth/settings for the AuthUI.
func (s *Service) GetPostRegisterRedirectURL() string {
	val, err := s.repo.GetSetting("default_post_register_redirect_url")
	if err != nil {
		return ""
	}
	return val
}

func (s *Service) UpdateSetting(key, value string) error {
	if err := s.repo.SetSetting(key, value); err != nil {
		return pkg.ErrInternal("failed to update setting")
	}
	slog.Info("setting updated", "key", key, "value", value)
	return nil
}
