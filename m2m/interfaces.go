package m2m

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

// All upstream services are injected as narrow interfaces so the package is
// trivially testable and stays decoupled from concrete implementations.

type UserStore interface {
	GetByID(id uuid.UUID) (*model.User, error)
	FindByEmail(email string) (*model.User, error)
	List(page, perPage int) ([]model.User, int64, error)
	Delete(id uuid.UUID) error
	RegisterAdmin(input user.RegisterInput, roleIDs []uuid.UUID) (*model.User, error)
	M2MUpdate(id uuid.UUID, input user.M2MUpdateInput) (*model.User, error)
	SetPassword(id uuid.UUID, newPassword string) error
	Unlock(id uuid.UUID) error
}

type RoleService interface {
	AssignRole(userID, roleID uuid.UUID) error
	RemoveRole(userID, roleID uuid.UUID) error
	GetUserRoles(userID uuid.UUID) ([]model.Role, error)
}

type SessionService interface {
	ListActive(userID uuid.UUID) ([]model.Session, error)
	Revoke(sessionID, userID uuid.UUID) error
	RevokeAll(userID uuid.UUID, currentSessionID *uuid.UUID) (int64, error)
}

type MFAService interface {
	ForceDisable(userID uuid.UUID) error
}

type PasskeyService interface {
	List(userID uuid.UUID) ([]model.Passkey, error)
	Delete(passkeyID, userID uuid.UUID) error
}

type FederationService interface {
	GetLinkedAccounts(userID uuid.UUID) ([]model.FederationLink, error)
	UnlinkAccount(linkID, userID uuid.UUID) error
}
