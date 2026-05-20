package account

import (
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

type Service struct {
	users               UserStore
	sessions            SessionRevoker
	mailer              Mailer
	emailChangeTokenTTL time.Duration
	deletionGracePeriod time.Duration
}

func NewService(users UserStore, sessions SessionRevoker, mailer Mailer, emailChangeTTL, deletionGrace time.Duration) *Service {
	return &Service{
		users:               users,
		sessions:            sessions,
		mailer:              mailer,
		emailChangeTokenTTL: emailChangeTTL,
		deletionGracePeriod: deletionGrace,
	}
}

// --- Password change ---

// ChangePassword wraps user.Service.ChangePassword with session-wide
// revocation and a notification email. Step-up reauth is enforced at the
// middleware layer, the password is still required defense-in-depth.
func (s *Service) ChangePassword(userID uuid.UUID, input user.ChangePasswordInput) error {
	u, err := s.users.GetByID(userID)
	if err != nil {
		return err
	}
	if err := s.users.ChangePassword(userID, input); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeAll(userID, nil); err != nil {
		slog.Warn("failed to revoke sessions after password change", "user_id", userID, "error", err)
	}
	if s.mailer != nil {
		if err := s.mailer.SendPasswordChangedNotice(u.Email); err != nil {
			slog.Warn("failed to send password-change notice", "user_id", userID, "error", err)
		}
	}
	return nil
}

// SetInitialPassword finalises onboarding for a federation-provisioned
// user. Sessions are not revoked because the user has none to invalidate
// outside the current one. A change-notice email is still sent so the
// account-owner sees the trail.
func (s *Service) SetInitialPassword(userID uuid.UUID, newPassword string) error {
	u, err := s.users.GetByID(userID)
	if err != nil {
		return err
	}
	if err := s.users.SetInitialPassword(userID, newPassword); err != nil {
		return err
	}
	if s.mailer != nil {
		if err := s.mailer.SendPasswordChangedNotice(u.Email); err != nil {
			slog.Warn("failed to send initial-password notice", "user_id", userID, "error", err)
		}
	}
	return nil
}

// --- Email change (two-step) ---

type ChangeEmailRequestInput struct {
	NewEmail string `json:"new_email" binding:"required,email"`
}

// RequestEmailChange stores a verification token bound to the new email and
// dispatches the confirmation link to that address. The current email stays
// the live one until ConfirmEmailChange is called.
func (s *Service) RequestEmailChange(userID uuid.UUID, input ChangeEmailRequestInput) error {
	newEmail := strings.ToLower(strings.TrimSpace(input.NewEmail))

	u, err := s.users.GetByID(userID)
	if err != nil {
		return err
	}
	if newEmail == u.Email {
		return pkg.ErrBadRequest("new email must differ from current email")
	}

	existing, err := s.users.FindByEmail(newEmail)
	if err != nil {
		return pkg.ErrInternal("failed to check email availability")
	}
	if existing != nil {
		// Avoid leaking the conflict in detail (caller already authenticated)
		return pkg.ErrConflict("email is already in use")
	}

	rawToken, hash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return pkg.ErrInternal("failed to generate token")
	}
	expiresAt := time.Now().Add(s.emailChangeTokenTTL)

	if err := s.users.UpdateFields(userID, map[string]any{
		"email_change_new":        newEmail,
		"email_change_token":      hash,
		"email_change_expires_at": expiresAt,
	}); err != nil {
		return pkg.ErrInternal("failed to record email change request")
	}

	if s.mailer != nil {
		if err := s.mailer.SendEmailChangeConfirmation(newEmail, rawToken); err != nil {
			slog.Warn("failed to send email change confirmation", "user_id", userID, "error", err)
		}
	}
	slog.Info("email change requested", "user_id", userID, "new_email", newEmail)
	return nil
}

type ConfirmEmailChangeInput struct {
	Token string `json:"token" binding:"required"`
}

// ConfirmEmailChange validates the token, swaps email atomically, sets
// email_verified, notifies the old address, and revokes other sessions.
// Returns the updated user (mainly for the notice email).
func (s *Service) ConfirmEmailChange(input ConfirmEmailChangeInput) (oldEmail, newEmail string, userID uuid.UUID, err error) {
	hash := crypto.HashToken(input.Token)
	u, err := s.users.FindByEmailChangeToken(hash)
	if err != nil {
		return "", "", uuid.Nil, pkg.ErrInternal("failed to validate token")
	}
	if u == nil || u.EmailChangeNew == nil {
		return "", "", uuid.Nil, pkg.ErrBadRequest("invalid or expired token")
	}

	// Re-check uniqueness — another user may have grabbed the email in the meantime.
	existing, err := s.users.FindByEmail(*u.EmailChangeNew)
	if err != nil {
		return "", "", uuid.Nil, pkg.ErrInternal("failed to check email availability")
	}
	if existing != nil && existing.ID != u.ID {
		return "", "", uuid.Nil, pkg.ErrConflict("email is already in use")
	}

	old := u.Email
	new := *u.EmailChangeNew

	if err := s.users.UpdateFields(u.ID, map[string]any{
		"email":                   new,
		"email_verified":          true,
		"email_change_new":        nil,
		"email_change_token":      nil,
		"email_change_expires_at": nil,
	}); err != nil {
		return "", "", uuid.Nil, pkg.ErrInternal("failed to apply email change")
	}

	if _, err := s.sessions.RevokeAll(u.ID, nil); err != nil {
		slog.Warn("failed to revoke sessions after email change", "user_id", u.ID, "error", err)
	}
	if s.mailer != nil {
		if err := s.mailer.SendEmailChangedNotice(old, new); err != nil {
			slog.Warn("failed to send email-changed notice", "user_id", u.ID, "error", err)
		}
	}
	slog.Info("email changed", "user_id", u.ID, "old_email", old, "new_email", new)
	return old, new, u.ID, nil
}

// --- Account deletion (soft + grace) ---

// RequestDeletion schedules the account for deletion at now + grace period,
// deactivates the account immediately, revokes sessions, and emails a cancel
// link to the user.
func (s *Service) RequestDeletion(userID uuid.UUID) error {
	u, err := s.users.GetByID(userID)
	if err != nil {
		return err
	}
	if u.DeletedAt != nil {
		return pkg.ErrConflict("account deletion already requested")
	}

	rawToken, hash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return pkg.ErrInternal("failed to generate cancellation token")
	}
	now := time.Now()
	purgeAfter := now.Add(s.deletionGracePeriod)

	if err := s.users.UpdateFields(userID, map[string]any{
		"deleted_at":           now,
		"deletion_token":       hash,
		"deletion_purge_after": purgeAfter,
		"active":               false,
	}); err != nil {
		return pkg.ErrInternal("failed to schedule deletion")
	}

	if _, err := s.sessions.RevokeAll(userID, nil); err != nil {
		slog.Warn("failed to revoke sessions during deletion request", "user_id", userID, "error", err)
	}
	if s.mailer != nil {
		if err := s.mailer.SendAccountDeletionEmail(u.Email, rawToken); err != nil {
			slog.Warn("failed to send deletion email", "user_id", userID, "error", err)
		}
	}
	slog.Info("account deletion requested", "user_id", userID, "purge_after", purgeAfter)
	return nil
}

type CancelDeletionInput struct {
	Token string `json:"token" binding:"required"`
}

// CancelDeletion validates the cancellation token and restores the account.
func (s *Service) CancelDeletion(input CancelDeletionInput) error {
	hash := crypto.HashToken(input.Token)
	u, err := s.users.FindByDeletionToken(hash)
	if err != nil {
		return pkg.ErrInternal("failed to validate token")
	}
	if u == nil {
		return pkg.ErrBadRequest("invalid or expired token")
	}

	if err := s.users.UpdateFields(u.ID, map[string]any{
		"deleted_at":           nil,
		"deletion_token":       nil,
		"deletion_purge_after": nil,
		"active":               true,
	}); err != nil {
		return pkg.ErrInternal("failed to cancel deletion")
	}
	slog.Info("account deletion cancelled", "user_id", u.ID)
	return nil
}
