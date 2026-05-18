# OrionAuth - Services and Repositories Detail

## User Service (user/service.go)
**Dependencies**: Repository, Argon2Hasher, AuthConfig, email.Sender (optional), RoleAssigner (optional)
- Register(RegisterInput) → *User — normalize email, validate password length, hash password, create user, auto-assign default role if configured
- Authenticate(LoginInput) → *User
- GetByID, UpdateProfile, ChangePassword (validates current password), VerifyPassword (used by reauth), UpdateFields (exposed for account/)
- FindByEmail / FindByEmailChangeToken / FindByDeletionToken — proxies for account/
- SendVerificationEmail, VerifyEmail, ForgotPassword, ResetPassword
- SetDefaultRole(roleID, RoleAssigner) — wires the post-Register role assignment
- incrementFailedAttempts(user) — lock if attempts >= MaxFailAttempts

## User Repository (user/repository.go)
- Create, FindByID, FindByEmail, Update, UpdateFields(uuid, map), List(page, perPage)
- FindByResetToken, FindByVerifyToken
- FindByEmailChangeToken, FindByDeletionToken (added for account self-service flows)

## Session Service (session/service.go)
**Dependencies**: Repository, AuthConfig
- Create, ListActive, Revoke, RevokeAll(userID, exceptSessionID *uuid.UUID)
- RevokeAll(uid, nil) is called by account.Service after password/email change or account deletion

## Client Service (client/service.go) — unchanged

## OAuth Service (oauth/service.go) — unchanged

## OIDC Service (oidc/service.go) — unchanged

## MFA Service (mfa/service.go) — unchanged
Implements reauth.MFAValidator (HasMFA, ValidateCode) — wired in main.go via `reauthService.SetMFAValidator(mfaService)`.

## RBAC Service (rbac/service.go) — unchanged
Implements user.RoleAssigner (AssignRole) and (through the existing main.go adapter) account.RoleProvider.

## Audit Service (audit/service.go)
- Log(LogEntry) — async
- Query(QueryInput) — now supports both `Action` (exact) and `ActionPrefix` (LIKE) filters so the admin UI can show all `account.*` events with one filter.
- Action constants for `account.*` events live in `audit/actions.go`.

## Reauth Service (reauth/service.go) — NEW
**Dependencies**: Repository, PasswordVerifier (user.Service), tokenTTL — optional MFAValidator, PasskeyValidator
- Issue(userID, sessionID, IssueRequest) → IssueResponse{Token, ExpiresAt, Method}
- Verify(rawToken, userID, sessionID) → *ReauthToken (nil if invalid/expired/wrong-session)
- Consume(hash, consumedBy) — single-use marker; only called by handlers after the sensitive op succeeds
- RevokeForSession(sessionID) — cascade revoke on session logout
- CleanupExpired() — called by database.StartCleanupJob

Methods accepted: `password`, `totp`, `backup_code`, `passkey`. Token format: SHA-256 hash of an opaque 32-byte random string (same as access tokens). Lifetime: `cfg.Account.ReauthTokenTTL` (default 10 min).

## Reauth Repository (reauth/repository.go)
- Create, FindByHash, MarkUsed, DeleteExpired, DeleteForSession

## Passkey Service (passkey/service.go) — NEW
**Dependencies**: Repository, UserFinder (user.Service), *webauthn.WebAuthn, challengeTTL
- BeginRegistration(userID) → CredentialCreation + challengeID (stores SessionData gob-encoded in `passkey_challenges`)
- FinishRegistration(userID, FinishRegistrationInput) → *Passkey
- BeginLogin() → CredentialAssertion + challengeID (usernameless, via webauthn.BeginDiscoverableLogin)
- FinishLogin(FinishLoginInput) → (*User, *Passkey) — wraps FinishDiscoverableLogin with a UserHandle→User resolver
- BeginReauth(userID) → CredentialAssertion + challengeID (allowed-credentials scoped to user's passkeys)
- ValidateReauthAssertion(userID, challengeID, response) → bool — implements reauth.PasskeyValidator
- HasUserVerifiedPasskey(userID) → bool — used by account.PolicyGate
- List/Rename/Delete
- CleanupExpiredChallenges() — called by database cleanup job

Uses lib `github.com/go-webauthn/webauthn` v0.17+. RP config read from `cfg.WebAuthn` (RPID, RPDisplayName, RPOrigins).

## Passkey Repository (passkey/repository.go)
- Passkeys: Create, FindByCredentialID, FindByID, ListByUser, UpdateName, UpdateSignCount, Delete
- Challenges: CreateChallenge, FindChallenge, DeleteChallenge, DeleteExpiredChallenges

## Account Service (account/service.go) — NEW
**Dependencies**: UserStore (user.Service), SessionRevoker (session.Service), Mailer (email.Sender), emailChangeTokenTTL, deletionGracePeriod
- ChangePassword(userID, ChangePasswordInput) — delegates to user.Service.ChangePassword + revokes other sessions + emails notice
- RequestEmailChange(userID, ChangeEmailRequestInput) — token + email to new address (1h TTL by default)
- ConfirmEmailChange(ConfirmEmailChangeInput) → (old, new, userID) — swaps email atomically, revokes sessions, notifies old address
- RequestDeletion(userID) — soft-delete (active=false), token, cancel-link email (7d grace by default)
- CancelDeletion(CancelDeletionInput) — restores account from token

## Account PolicyGate (account/policy.go) — NEW
Builder around userService + rbacService adapter + mfaService + passkeyService + policyService adapter. `.Middleware(action)` returns a gin.HandlerFunc that evaluates `account_action` Rego policies for the given action string (`update_profile`, `change_email`, ...). Fail-open on internal errors; deny → 403 with policy reason.

## DCR Handler (client/dcr_handler.go) — unchanged
## Federation Service (federation/service.go) — unchanged
## Email Sender (email/) — extended with 4 new methods
- SendEmailChangeConfirmation(to, token)
- SendEmailChangedNotice(oldEmail, newEmail)
- SendPasswordChangedNotice(to)
- SendAccountDeletionEmail(to, cancelToken)

Templates live in `email/templates/account_*.gohtml` and follow the existing dark/light design system.
