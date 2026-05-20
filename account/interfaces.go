package account

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

// UserStore exposes the slice of user.Service operations the account package
// needs. Defined here to keep account/ decoupled from user/ for testability.
type UserStore interface {
	GetByID(id uuid.UUID) (*model.User, error)
	FindByEmail(email string) (*model.User, error)
	FindByEmailChangeToken(tokenHash string) (*model.User, error)
	FindByDeletionToken(tokenHash string) (*model.User, error)
	UpdateFields(id uuid.UUID, fields map[string]any) error
	ChangePassword(id uuid.UUID, input user.ChangePasswordInput) error
	SetInitialPassword(id uuid.UUID, newPassword string) error
}

// SessionRevoker revokes user sessions after sensitive changes (password,
// email, deletion). Implemented by session.Service.
type SessionRevoker interface {
	RevokeAll(userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error)
}

// Mailer issues self-service notifications. Implemented by email.Sender.
type Mailer interface {
	SendEmailChangeConfirmation(to, token string) error
	SendEmailChangedNotice(oldEmail, newEmail string) error
	SendPasswordChangedNotice(to string) error
	SendAccountDeletionEmail(to, cancelToken string) error
}
