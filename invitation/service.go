package invitation

import (
	"log/slog"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/email"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/rbac"
	"orion-auth-backend/user"
)

type Service struct {
	repo           RepositoryInterface
	userService    *user.Service
	rbacService    *rbac.Service
	emailSender    email.Sender
	issuer         string
	allowedOrigins []string
}

func NewService(repo RepositoryInterface, userService *user.Service, rbacService *rbac.Service, emailSender email.Sender, issuer string) *Service {
	return &Service{
		repo:        repo,
		userService: userService,
		rbacService: rbacService,
		emailSender: emailSender,
		issuer:      issuer,
	}
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

	if err := s.repo.Create(inv); err != nil {
		slog.Error("failed to create invitation", "error", err)
		return nil, pkg.ErrInternal("failed to create invitation")
	}

	if s.emailSender != nil {
		if err := s.emailSender.SendInvitationEmail(input.Email, rawToken); err != nil {
			slog.Error("failed to send invitation email", "error", err, "email", input.Email)
		}
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

// SetAllowedOrigins configures the same-origin allowlist used to validate
// operator-supplied URLs (e.g. default_post_register_redirect_url). Wired
// from cfg.CORS.AllowedOrigins at startup.
func (s *Service) SetAllowedOrigins(origins []string) {
	s.allowedOrigins = origins
}

// AllowedOrigins exposes the configured allowlist for the handler.
func (s *Service) AllowedOrigins() []string {
	return s.allowedOrigins
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
