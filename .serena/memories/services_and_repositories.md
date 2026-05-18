# OrionAuth - Services and Repositories Detail

## User Service (user/service.go)
**Dependencies**: Repository, Argon2Hasher, AuthConfig, email.Sender (optional), RoleAssigner (optional)
- Register(RegisterInput) → *User — normalize email, validate password length,
  hash, create user, auto-assign default role if SetDefaultRole was wired
- **RegisterAdmin(input, roleIDs)** — like Register but bypasses the default
  role hook and assigns the caller-supplied roles (used by M2M provisioning)
- Authenticate(LoginInput) → *User
- GetByID, UpdateProfile, ChangePassword (validates current password)
- **VerifyPassword(id, password)** — used by reauth
- **UpdateFields(id, map)** — pass-through, exposed for account/m2m
- **M2MUpdate(id, M2MUpdateInput)** — permissive update for the M2M API
  (covers email, email_verified, display_name, avatar_url, phone, active,
  metadata in one call; all fields optional pointers)
- **SetPassword(id, newPassword)** — bypasses current_password check (M2M)
- **Unlock(id)** — clears failed_login_attempts + locked_until (M2M)
- FindByEmail / FindByEmailChangeToken / FindByDeletionToken — proxies
- SendVerificationEmail, VerifyEmail, ForgotPassword, ResetPassword
- SetDefaultRole(roleID, RoleAssigner) — wires post-Register role hook

## User Repository (user/repository.go)
- Create, FindByID, FindByEmail, Update, UpdateFields(uuid, map), List(page, perPage)
- FindByResetToken, FindByVerifyToken
- FindByEmailChangeToken, FindByDeletionToken

## Session Service (session/service.go)
- Create, ListActive, Revoke, RevokeAll(userID, exceptSessionID *uuid.UUID)
- RevokeAll(uid, nil) revokes everything (used by account/m2m after sensitive changes)

## Client Service (client/service.go) — unchanged
## OAuth Service (oauth/service.go) — unchanged
## OIDC Service (oidc/service.go) — unchanged

## MFA Service (mfa/service.go)
- Enroll, Verify, Disable (requires TOTP code), RegenerateBackupCodes
- **ForceDisable(userID)** — unconditional MFA reset, used by M2M
- Implements reauth.MFAValidator (HasMFA, ValidateCode)

## RBAC Service (rbac/service.go) — unchanged
Implements user.RoleAssigner (AssignRole) + account.RoleProvider via main.go adapter.

## Audit Service (audit/service.go)
- Log(LogEntry) async
- Query(QueryInput) supports `Action` (exact) and `ActionPrefix` (LIKE) filters
- Action constants for account.* and m2m.user.* in audit/actions.go

## Reauth Service (reauth/service.go)
**Dependencies**: Repository, PasswordVerifier (user.Service), tokenTTL,
optional MFAValidator, PasskeyValidator
- Issue/Verify/Consume/RevokeForSession/CleanupExpired
- Methods: password, totp, backup_code, passkey

## Passkey Service (passkey/service.go)
**Dependencies**: Repository, UserFinder (user.Service), *webauthn.WebAuthn, challengeTTL
- BeginRegistration / FinishRegistration / BeginLogin / FinishLogin (discoverable)
- BeginReauth / ValidateReauthAssertion
- HasUserVerifiedPasskey, List, Rename, Delete, CleanupExpiredChallenges

## Account Service (account/service.go)
**Dependencies**: UserStore, SessionRevoker, Mailer, emailChangeTokenTTL, deletionGracePeriod
- ChangePassword (delegates + revokes sessions + emails notice)
- RequestEmailChange / ConfirmEmailChange (2-step)
- RequestDeletion (soft + grace) / CancelDeletion

## Account PolicyGate (account/policy.go)
Builder ; `.Middleware(action)` evaluates `account_action` Rego policies.

## M2M UserService (m2m/service.go) — NEW
**Dependencies (injected as interfaces)**: UserStore, RoleService, SessionService,
MFAService, PasskeyService, FederationService — narrow contracts in m2m/interfaces.go.
Owns no data; delegates everything to upstream services.

Methods:
- CRUD: Get, List, Create (returns *User + generated_password if omitted),
  Update (any field except id), Delete
- Credentials: SetPassword (auto-revokes all sessions), Unlock, ResetMFA
- Roles: ListRoles, AssignRole, RemoveRole
- Sessions: ListSessions, RevokeSession, RevokeAllSessions
- Passkeys: ListPasskeys, DeletePasskey
- Linked accounts: ListLinkedAccounts, UnlinkAccount

m2m/handler.go exposes everything under /api/v1/m2m/users/*. Each route is
gated by `middleware.RequireClientScope(db, scope, "urn:orion:m2m")` applied
in main.go via 5 sub-groups (read, write, delete, manage_auth, manage_roles).

## DCR Handler (client/dcr_handler.go) — unchanged
## Federation Service (federation/service.go) — unchanged
## Email Sender (email/) — extended with account.* notifications
