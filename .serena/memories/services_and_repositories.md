# OrionAuth - Services and Repositories Detail

## User Service (user/service.go)
**Dependencies**: Repository, Argon2Hasher, AuthConfig, email.Sender (optional)
- Register(RegisterInput) → *User — normalize email, validate password length, hash password, create user
- Authenticate(LoginInput) → *User — find by email, check active/locked, verify password, increment failed attempts on failure, reset on success
- GetByID(uuid) → *User
- UpdateProfile(uuid, UpdateProfileInput) — update DisplayName, AvatarURL, Phone if non-nil
- ChangePassword(uuid, ChangePasswordInput) — verify current, validate length, hash new
- SendVerificationEmail(uuid) — generate 32-byte token, hash, store, send email (24h expiry)
- VerifyEmail(VerifyEmailInput) — hash token, find user by hash, set email_verified=true
- ForgotPassword(ForgotPasswordInput) — always returns nil (no enumeration), token 1h expiry
- ResetPassword(ResetPasswordInput) — hash token, find user, update password, clear lockout
- incrementFailedAttempts(user) — lock if attempts >= MaxFailAttempts

## User Repository (user/repository.go)
- Create, FindByID, FindByEmail, Update, UpdateFields(uuid, map), List(page, perPage), FindByResetToken(hash), FindByVerifyToken(hash)

## Session Service (session/service.go)
**Dependencies**: Repository, AuthConfig
- Create(CreateInput) → *Session — TTL from config, stores IP/UserAgent
- ListActive(userID) → []Session
- Revoke(sessionID, userID) — ownership validation
- RevokeAll(userID, exceptSessionID) — keeps current session

## Session Repository
- Create, FindByID, FindActiveByUser, Revoke, RevokeAllForUser(userID, *exceptID), UpdateLastActive

## Client Service (client/service.go)
**Dependencies**: Repository, Argon2Hasher
- Create(CreateInput) → (*Client, plainSecret) — auto-generate 32-char secret, hash with Argon2, set defaults
- GetByID, Update, List(page, perPage), Delete (soft: active=false)
- RotateSecret(uuid) → (*Client, newPlainSecret) — generate new secret

## Client Repository
- Create, FindByID, FindActiveByID, Update, List(page, perPage), Delete(active=false)

## OAuth Service (oauth/service.go)
**Dependencies**: Repository, UserService, SessionService, Argon2Hasher, AuthConfig
**Interfaces**: IDTokenGenerator (from OIDC adapter), MFAValidator (from MFA service)
- Authorization flow: InitAuthorize, AuthorizeLogin, AuthorizeMFA, AuthorizeConsent, CompleteAuthorizeFirstParty
- Token exchange: ExchangeAuthorizationCode, ExchangeClientCredentials, ExchangeRefreshToken, ExchangeDeviceCode
- Token management: Introspect, Revoke
- Device flow: InitDeviceAuthorization, DeviceVerify, DeviceApprove
- Internal: issueTokens, issueTokensWithOpts, completeAuthorize, completeImplicit

## OAuth Repository
- Auth requests: Create/Find/Update/Delete AuthRequest
- Auth codes: Create/Find/MarkUsed AuthCode
- Access tokens: Create/Find/Revoke/RevokeByRefreshToken/RevokeBySession
- Refresh tokens: Create/Find/Rotate/RevokeFamiliy/RevokeBySession
- Consent: FindActive/Create/Update
- Device codes: Create/Find/FindByUserCode/Update
- Transaction(fn) for atomic operations
- findClient(clientIDStr)

## OIDC Service (oidc/service.go)
**Dependencies**: *gorm.DB, UserService, issuer string
- EnsureSigningKey() — loads or generates RSA 2048-bit key pair
- RotateKey() — new key, deactivate old with 24h grace period
- GenerateIDToken(IDTokenClaims) → JWT string (RS256, includes user claims per scope)
- GetJWKS() → JWKS (all active/non-expired keys)
- GetDiscovery() → OpenIDConfiguration
- GetUserInfo(userID, scopes) → map of claims
- Thread-safe with sync.RWMutex

## MFA Service (mfa/service.go)
**Dependencies**: Repository, Argon2Hasher
- Enroll(userID, email) → secret, provisioningURL — TOTP setup with issuer "OrionAuth"
- Verify(userID, code) → []backupCodes — validates TOTP, generates 10 hashed backup codes
- ValidateCode(userID, code) → bool — checks TOTP then backup codes
- HasMFA(userID) → bool
- Disable(userID, code) — requires valid code
- RegenerateBackupCodes(userID, code) → []newCodes

## MFA Repository
- Create, FindByUserAndType, FindVerifiedByUser, Update, Delete

## RBAC Service (rbac/service.go)
**Dependencies**: Repository
- Role CRUD: CreateRole, GetRole, ListRoles, UpdateRole, DeleteRole
- Permission listing: ListPermissions
- Role-Permission: SetPermissions(roleID, permissionIDs)
- User-Role: AssignRole(userID, roleID), RemoveRole, GetUserRoles
- HasPermission(userID, permission) → bool

## RBAC Repository
- Roles: Create/FindByID/FindByName/List/Update/Delete
- Permissions: List, FindByIDs
- SetRolePermissions (transaction: delete old + insert new)
- User-Role: Assign/Remove/GetUserRoles
- GetUserPermissions(userID) → all permissions across all roles

## RBAC Middleware (rbac/middleware.go)
- RequirePermission(svc, permission) → gin.HandlerFunc
- RequireAnyPermission(svc, ...permissions) → gin.HandlerFunc (OR logic)

## Audit Service (audit/service.go)
**Dependencies**: *gorm.DB (direct, no repository)
- Log(LogEntry) — async, non-blocking, serializes metadata to JSON
- Query(QueryInput) → paginated results with filters (UserID, Action, From, To, Page, PerPage)

## Federation Service (federation/service.go)
**Dependencies**: Repository, issuer string
- Admin: CreateProvider, GetProvider, ListProviders, UpdateProvider, DeleteProvider
- Social login: InitSocialLogin(providerName) → authURL + state
- ProcessCallback(providerName, input, existingUserID) → CallbackResult (UserID, ExternalID, Email, IsNewUser, IsNewLink)
- Account management: GetLinkedAccounts(userID), UnlinkAccount(linkID, userID)

## Federation Repository
- Providers: Create/FindByID/FindByName/List/Update/Delete
- Links: Create/FindLink(providerID, externalID)/FindLinksByUser/FindLinkByID/Delete

## Email Sender (email/)
- Interface: SendVerificationEmail(to, token), SendPasswordResetEmail(to, token)
- SMTPSender: go-mail implementation, HTML templates with token and API instructions
