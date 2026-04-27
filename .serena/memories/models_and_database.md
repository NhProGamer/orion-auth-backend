# OrionAuth - Models and Database Schema

## Base Model
All models with BaseModel use UUID v7 IDs (auto-generated via BeforeCreate hook).
```
BaseModel: ID (uuid PK), CreatedAt, UpdatedAt
```

## Models

### User (table: users)
- BaseModel
- Email (varchar 255, unique, not null)
- EmailVerified (bool, default false)
- EmailVerifyToken (*string, varchar 255, json:"-")
- EmailVerifyExpiresAt (*time.Time, json:"-")
- PasswordHash (varchar 255, not null, json:"-")
- PasswordResetToken (*string, varchar 255, json:"-")
- PasswordResetExpiresAt (*time.Time, json:"-")
- DisplayName (*string, varchar 255)
- AvatarURL (*string, varchar 512)
- Phone (*string, varchar 50)
- LockedUntil (*time.Time)
- FailedLoginAttempts (int, default 0, json:"-")
- Active (bool, default true)
- Metadata (json.RawMessage, jsonb, default '{}')
- Methods: IsLocked(), PublicProfile(), OIDCClaims(scopes), AdminView()
- Type alias: UserID = uuid.UUID

### OAuthClient (table: oauth_clients)
- BaseModel
- SecretHash (*string, varchar 255, json:"-")
- Name (varchar 255, not null)
- Description (*string, text)
- RedirectURIs (pq.StringArray, text[])
- GrantTypes (pq.StringArray, text[])
- ResponseTypes (pq.StringArray, text[])
- Scopes (pq.StringArray, text[])
- TokenAuthMethod (varchar 50, default "client_secret_basic")
- IsPublic (bool, default false)
- IsFirstParty (bool, default false)
- JWKSUri (*string, varchar 512)
- AccessTokenTTL (int, default 3600)
- RefreshTokenTTL (int, default 86400)
- IDTokenTTL (int, default 3600)
- PostLogoutRedirectURIs (pq.StringArray, text[])
- BackchannelLogoutURI (*string, varchar 512)
- BackchannelLogoutSessionReq (bool, default false)
- FrontchannelLogoutURI (*string, varchar 512)
- FrontchannelLogoutSessionReq (bool, default false)
- SubjectType (string, varchar 20, default "public")
- SectorIdentifierURI (*string, varchar 512)
- UserinfoSignedResponseAlg (*string, varchar 10)
- RegistrationAccessTokenHash (*string, varchar 64, json:"-")
- Active (bool, default true)
- Methods: HasGrantType(), HasScope(), HasRedirectURI(), HasPostLogoutRedirectURI(), ValidateScopes()

### PushedAuthorizationRequest (table: pushed_authorization_requests)
- RequestURI (varchar 128, PK, format: urn:ietf:params:oauth:request_uri:<uuid>)
- ClientID (uuid, not null)
- Params (jsonb, stores serialized InitAuthorizeParams)
- ExpiresAt, CreatedAt
- Methods: IsExpired()

### AccessToken (table: access_tokens)
- ID (varchar 64, PK — SHA-256 hash)
- ClientID, UserID (*uuid), SessionID (*uuid), RefreshTokenID (*string varchar 64)
- Scopes (pq.StringArray), ExpiresAt, Revoked (default false), CreatedAt
- Method: IsValid()

### RefreshToken (table: refresh_tokens)
- ID (varchar 64, PK — SHA-256 hash)
- ClientID, UserID, SessionID (all uuid, not null)
- Scopes (pq.StringArray)
- FamilyID (uuid, for rotation chain tracking)
- ParentID (*string varchar 64)
- ExpiresAt, Revoked (default false), RotatedAt (*time.Time), CreatedAt
- Methods: IsValid(), WasRotated()

### AuthorizationCode (table: authorization_codes)
- CodeHash (varchar 64, PK)
- ClientID, UserID (uuid), RedirectURI (varchar 512)
- Scopes (pq.StringArray)
- CodeChallenge (*string, varchar 128), CodeChallengeMethod (*string, varchar 10)
- Nonce (*string, varchar 128), SessionID (*uuid)
- AuthTime (*time.Time), AuthMethods (pq.StringArray)
- ClaimsParam (*string, jsonb)
- ExpiresAt, Used (default false), CreatedAt
- Methods: IsValid(), HasPKCE()

### AuthorizationRequest (table: authorization_requests)
- BaseModel
- ClientID (uuid), RedirectURI (varchar 512), ResponseType (varchar 50)
- Scopes (pq.StringArray), State (*string), Nonce (*string)
- CodeChallenge (*string), CodeChallengeMethod (*string)
- UserID (*uuid), Authenticated (default false), ConsentGiven (default false)
- ExpiresAt
- AuthMethods (pq.StringArray, tracks pwd/otp/fed during auth flow)
- Methods: IsExpired(), IsReady()

### Session (table: sessions)
- ID (uuid PK, BeforeCreate hook for v7)
- UserID (uuid), IPAddress (*string, inet), UserAgent (*string, varchar 512)
- DeviceInfo (*string, varchar 255)
- LastActiveAt, AuthenticatedAt, Revoked (default false), RevokedAt (*time.Time)
- ExpiresAt, CreatedAt
- Methods: IsActive(), Revoke()

### Consent (table: consents)
- BaseModel
- UserID, ClientID (uuid), Scopes (pq.StringArray)
- GrantedAt, RevokedAt (*time.Time)
- Methods: IsActive(), CoversScopes(requested)

### MFAMethod (table: mfa_methods)
- BaseModel
- UserID (uuid), Type (varchar 20, default "totp")
- Secret (varchar 255, json:"-"), Verified (default false)
- BackupCodes (pq.StringArray, json:"-")

### Role (table: roles)
- BaseModel
- Name (varchar 100, unique), Description (*string)
- Permissions ([]Permission, many2many:role_permissions)

### Permission (table: permissions)
- BaseModel
- Name (varchar 100, unique), Description (*string)

### UserRole (table: user_roles) — join table
- UserID (PK), RoleID (PK)

### RolePermission (table: role_permissions) — join table
- RoleID (PK), PermissionID (PK), CreatedAt

### DeviceCode (table: device_codes)
- DeviceCodeHash (varchar 64, PK)
- UserCode (varchar 9, unique), ClientID (uuid)
- Scopes (pq.StringArray), UserID (*uuid), SessionID (*uuid)
- Status (varchar 20, default "pending": pending/authorized/denied/consumed)
- IntervalSecs (default 5), ExpiresAt, LastPolledAt (*time.Time), CreatedAt
- Methods: IsExpired(), IsPending()

### AuditLog (table: audit_logs)
- ID (uuid PK), UserID (*uuid), ClientID (*uuid)
- Action (varchar 100), IPAddress (*string, inet), UserAgent (*string, varchar 512)
- Metadata (json.RawMessage, jsonb), CreatedAt

### SigningKey (table: signing_keys)
- ID (uuid PK), PrivateKeyPEM (text, json:"-"), PublicKeyPEM (text, json:"-")
- Algorithm (varchar 10, default "RS256")
- Active (default true), ExpiresAt (*time.Time), CreatedAt

### FederationProvider (table: federation_providers)
- BaseModel
- Name (varchar 100, unique), DisplayName (*string, varchar 255)
- Type (varchar 20, default "oidc")
- ClientID (varchar 255), ClientSecret (varchar 255, json:"-")
- IssuerURL, AuthorizationURL, TokenURL, UserinfoURL (*string, varchar 512)
- Scopes (pq.StringArray), Active (default true)

### FederationLink (table: federation_links)
- BaseModel
- UserID (uuid), ProviderID (uuid), ExternalID (varchar 255)
- Email (*string, varchar 255), Metadata (json.RawMessage, jsonb)

## Seeded Data (migration 011)
- Role "admin" (UUID 00000000-0000-0000-0000-000000000001) with all 11 permissions:
  clients:read, clients:write, users:read, users:write, roles:read, roles:write,
  audit:read, keys:read, keys:write, federation:read, federation:write

## Key Patterns
- Tokens (access, refresh, auth code, device code) stored as SHA-256 hashes, never raw
- PostgreSQL-specific: pq.StringArray (TEXT[]), json.RawMessage (JSONB), INET for IPs
- Sensitive fields hidden with json:"-" (passwords, secrets, tokens, backup codes)
- Refresh token family tracking via FamilyID/ParentID for rotation reuse detection
