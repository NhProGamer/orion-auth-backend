package account

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

// UserStore exposes the slice of user.Service operations the account package
// needs. Defined here to keep account/ decoupled from user/ for testability.
//
// UpdateFieldsInTx mirrors UpdateFields but runs against a caller-supplied
// transaction so the account package can compose email-change /
// deletion writes with their side-effects (session revoke, email
// enqueue) atomically.
type UserStore interface {
	GetByID(id uuid.UUID) (*model.User, error)
	FindByEmail(email string) (*model.User, error)
	FindByEmailChangeToken(tokenHash string) (*model.User, error)
	FindByDeletionToken(tokenHash string) (*model.User, error)
	UpdateFields(id uuid.UUID, fields map[string]any) error
	UpdateFieldsInTx(tx *gorm.DB, id uuid.UUID, fields map[string]any) error
	ChangePassword(id uuid.UUID, input user.ChangePasswordInput) error
	SetInitialPassword(id uuid.UUID, newPassword string) error
}

// SessionRevoker revokes user sessions after sensitive changes (password,
// email, deletion). Implemented by session.Service.
//
// RevokeAllInTx is the Tx-aware variant so the email-change / deletion
// flow can revoke sessions atomically with the user-table update.
type SessionRevoker interface {
	RevokeAll(userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error)
	RevokeAllInTx(tx *gorm.DB, userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error)
}

// Mailer issues self-service notifications. Implemented by email.Sender.
type Mailer interface {
	SendEmailChangeConfirmation(to, token string) error
	SendEmailChangedNotice(oldEmail, newEmail string) error
	SendPasswordChangedNotice(to string) error
	SendAccountDeletionEmail(to, cancelToken string) error
}
