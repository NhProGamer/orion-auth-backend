package m2m

import (
	"log/slog"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

// UserService orchestrates user-related operations exposed to M2M callers.
// It owns no data; every operation delegates to the upstream services and
// applies the side effects required by the M2M trust model — chiefly: when
// a credential changes (password, MFA), all live sessions are revoked.
type UserService struct {
	users      UserStore
	roles      RoleService
	sessions   SessionService
	mfa        MFAService
	passkeys   PasskeyService
	federation FederationService
	// protectedRoles enumerates role UUIDs the M2M API may never assign
	// (Vuln 14). Defaults to the admin role per config.AuthConfig.
	protectedRoles map[uuid.UUID]struct{}
}

func NewUserService(
	users UserStore,
	roles RoleService,
	sessions SessionService,
	mfa MFAService,
	passkeys PasskeyService,
	federation FederationService,
) *UserService {
	return &UserService{
		users:      users,
		roles:      roles,
		sessions:   sessions,
		mfa:        mfa,
		passkeys:   passkeys,
		federation: federation,
	}
}

// SetProtectedRoles installs the M2M role-assignment denylist. Roles in
// this set are refused by AssignRole regardless of caller, even with the
// m2m:users:manage_roles scope. Idempotent; invalid UUIDs are skipped
// with a warning.
func (s *UserService) SetProtectedRoles(roleIDs []string) {
	set := make(map[uuid.UUID]struct{}, len(roleIDs))
	for _, raw := range roleIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			slog.Warn("m2m: ignoring invalid protected role UUID", "raw", raw)
			continue
		}
		set[id] = struct{}{}
	}
	s.protectedRoles = set
}

// --- CRUD ---

func (s *UserService) Get(id uuid.UUID) (*model.User, error) {
	return s.users.GetByID(id)
}

func (s *UserService) List(page, perPage int) ([]model.User, int64, error) {
	return s.users.List(page, perPage)
}

// Create provisions a user with the caller-supplied roles. If `password` is
// empty, a 24-char random one is generated and returned in the second slot
// (single occurrence, plaintext, surfaced exactly once).
func (s *UserService) Create(input CreateUserInput) (*model.User, string, error) {
	generatedPassword := ""
	password := input.Password
	if password == "" {
		raw, err := crypto.GenerateRandomString(24)
		if err != nil {
			return nil, "", pkg.ErrInternal("failed to generate password")
		}
		password = raw
		generatedPassword = raw
	}

	displayName := input.DisplayName
	regInput := user.RegisterInput{
		Email:       input.Email,
		Password:    password,
		DisplayName: displayName,
	}
	u, err := s.users.RegisterAdmin(regInput, input.RoleIDs)
	if err != nil {
		return nil, "", err
	}

	// Apply any additional fields not handled by Register (phone, avatar,
	// metadata, email_verified, active overrides) via a follow-up update.
	if input.EmailVerified != nil || input.Active != nil ||
		input.Phone != nil || input.AvatarURL != nil || input.Metadata != nil {
		updateInput := user.M2MUpdateInput{
			EmailVerified: input.EmailVerified,
			Active:        input.Active,
			Phone:         input.Phone,
			AvatarURL:     input.AvatarURL,
			Metadata:      input.Metadata,
		}
		updated, uerr := s.users.M2MUpdate(u.ID, updateInput)
		if uerr != nil {
			slog.Warn("m2m: user created but post-create update failed", "user_id", u.ID, "error", uerr)
		} else {
			u = updated
		}
	}

	return u, generatedPassword, nil
}

func (s *UserService) Update(id uuid.UUID, input UpdateUserInput) (*model.User, error) {
	return s.users.M2MUpdate(id, user.M2MUpdateInput{
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		DisplayName:   input.DisplayName,
		AvatarURL:     input.AvatarURL,
		Phone:         input.Phone,
		Active:        input.Active,
		Metadata:      input.Metadata,
	})
}

func (s *UserService) Delete(id uuid.UUID) error {
	// Ensure existence first so 404 is consistent.
	if _, err := s.users.GetByID(id); err != nil {
		return err
	}
	return s.users.Delete(id)
}

// --- Credentials & auth state ---

// SetPassword overwrites the password and revokes every existing session.
// The generated password is **never** logged — it's the caller's responsibility
// to relay it to the user out-of-band.
func (s *UserService) SetPassword(id uuid.UUID, newPassword string) error {
	if _, err := s.users.GetByID(id); err != nil {
		return err
	}
	if err := s.users.SetPassword(id, newPassword); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeAll(id, nil); err != nil {
		slog.Warn("m2m: failed to revoke sessions after password set", "user_id", id, "error", err)
	}
	return nil
}

func (s *UserService) Unlock(id uuid.UUID) error {
	if _, err := s.users.GetByID(id); err != nil {
		return err
	}
	return s.users.Unlock(id)
}

func (s *UserService) ResetMFA(id uuid.UUID) error {
	if _, err := s.users.GetByID(id); err != nil {
		return err
	}
	return s.mfa.ForceDisable(id)
}

// --- Roles ---

func (s *UserService) ListRoles(userID uuid.UUID) ([]model.Role, error) {
	if _, err := s.users.GetByID(userID); err != nil {
		return nil, err
	}
	return s.roles.GetUserRoles(userID)
}

func (s *UserService) AssignRole(userID, roleID uuid.UUID) error {
	if _, ok := s.protectedRoles[roleID]; ok {
		slog.Warn("m2m: protected role assignment refused", "role_id", roleID, "target_user_id", userID)
		return pkg.ErrForbidden("role is protected from m2m assignment")
	}
	if _, err := s.users.GetByID(userID); err != nil {
		return err
	}
	return s.roles.AssignRole(userID, roleID)
}

func (s *UserService) RemoveRole(userID, roleID uuid.UUID) error {
	if _, err := s.users.GetByID(userID); err != nil {
		return err
	}
	return s.roles.RemoveRole(userID, roleID)
}

// --- Sessions ---

func (s *UserService) ListSessions(userID uuid.UUID) ([]model.Session, error) {
	if _, err := s.users.GetByID(userID); err != nil {
		return nil, err
	}
	return s.sessions.ListActive(userID)
}

func (s *UserService) RevokeSession(sessionID, userID uuid.UUID) error {
	if _, err := s.users.GetByID(userID); err != nil {
		return err
	}
	return s.sessions.Revoke(sessionID, userID)
}

func (s *UserService) RevokeAllSessions(userID uuid.UUID) (int64, error) {
	if _, err := s.users.GetByID(userID); err != nil {
		return 0, err
	}
	return s.sessions.RevokeAll(userID, nil)
}

// --- Passkeys ---

func (s *UserService) ListPasskeys(userID uuid.UUID) ([]model.Passkey, error) {
	if _, err := s.users.GetByID(userID); err != nil {
		return nil, err
	}
	return s.passkeys.List(userID)
}

func (s *UserService) DeletePasskey(passkeyID, userID uuid.UUID) error {
	if _, err := s.users.GetByID(userID); err != nil {
		return err
	}
	return s.passkeys.Delete(passkeyID, userID)
}

// --- Linked accounts ---

func (s *UserService) ListLinkedAccounts(userID uuid.UUID) ([]model.FederationLink, error) {
	if _, err := s.users.GetByID(userID); err != nil {
		return nil, err
	}
	return s.federation.GetLinkedAccounts(userID)
}

func (s *UserService) UnlinkAccount(linkID, userID uuid.UUID) error {
	if _, err := s.users.GetByID(userID); err != nil {
		return err
	}
	return s.federation.UnlinkAccount(linkID, userID)
}
