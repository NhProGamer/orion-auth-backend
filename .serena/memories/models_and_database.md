# OrionAuth - Models and Database Schema

## Base Model
All models with BaseModel use UUID v7 IDs (auto-generated via BeforeCreate hook).
```
BaseModel: ID (uuid PK), CreatedAt, UpdatedAt
```

## Models

### User (table: users)
- BaseModel
- Email (varchar 255, unique, not null), EmailVerified, EmailVerifyToken/EmailVerifyExpiresAt
- PasswordHash (varchar 255, not null), PasswordResetToken/PasswordResetExpiresAt
- DisplayName, AvatarURL, Phone (*string)
- LockedUntil (*time.Time), FailedLoginAttempts, Active (bool)
- Metadata (jsonb, OIDC profile claims)
- **DeletedAt, DeletionToken, DeletionPurgeAfter** (migration 031) — soft-delete with 7d grace period
- **EmailChangeNew, EmailChangeToken, EmailChangeExpiresAt** (migration 033) — pending email change flow
- Methods: IsLocked(), IsPendingDeletion(), PublicProfile(), AdminView(), OIDCClaims(scopes), GetProfileMetadata()

### OAuthClient — unchanged

### PushedAuthorizationRequest — unchanged

### AccessToken / RefreshToken / AuthorizationCode / AuthorizationRequest / Session / Consent / DeviceCode / AuditLog / SigningKey — unchanged

### MFAMethod — unchanged

### Role / Permission / UserRole / RolePermission — unchanged structure
- Migration 032 seeds a default `user` role (UUID `00000000-0000-0000-0000-000000000004`) granted all `account:*` permissions and back-fills existing users that have no role assignment yet.

### APIResource / ResourcePermission / ClientResourcePermission / RoleResourcePermission — unchanged structure
- Migration 028 seeds the `orion-account` resource (UUID `00000000-0000-0000-0000-000000000003`) and 9 `account:*` permissions, mirrored into the RBAC `permissions` table and granted to the admin role.

### Policy — unchanged structure
- Type whitelist now includes `account_action` (validated in policy.Service.CreatePolicyInput binding tag).

### FederationProvider / FederationLink — unchanged

### Passkey (table: passkeys) — NEW (migration 030)
- BaseModel
- UserID (uuid FK, indexed, on delete cascade)
- CredentialID ([]byte, BYTEA, unique) — WebAuthn credential ID
- PublicKey ([]byte, BYTEA) — CBOR-encoded
- AttestationType (varchar 50), AAGUID ([]byte BYTEA)
- SignCount (uint32)
- Transports (pq.StringArray, TEXT[]: usb, nfc, ble, internal, hybrid)
- Flags (uint8 stored as INT) — raw `CredentialFlags.ProtocolValue()` per the go-webauthn recommendation
- CloneWarning (bool), Name (varchar 100, default "Passkey")
- LastUsedAt (*time.Time)
- Method PublicView() — JSON-safe representation, never leaks credential material

### PasskeyChallenge (table: passkey_challenges) — NEW (migration 030)
- ID (uuid PK), UserID (*uuid, nullable for usernameless login)
- Purpose (varchar 20: `registration` | `login` | `reauth`)
- SessionData ([]byte BYTEA) — gob-encoded `webauthn.SessionData`
- ExpiresAt (indexed), CreatedAt
- Method IsExpired()

### ReauthToken (table: reauth_tokens) — NEW (migration 029)
- ID (varchar 64, SHA-256 hash of raw token)
- UserID (uuid FK, indexed, cascade), SessionID (uuid FK, indexed, cascade)
- Method (varchar 20: password | totp | backup_code | passkey)
- ExpiresAt, Used (bool, default false), UsedAt (*time.Time), ConsumedBy (*string varchar 100)
- Methods: IsValid()

## Migrations (chronological, latest)
- 027_require_pkce.sql — pre-existing
- **028_create_account_resource.sql** — seed orion-account resource + account:* perms in both resource_permissions and RBAC permissions
- **029_create_reauth_tokens.sql** — table for step-up tokens
- **030_create_passkeys.sql** — passkeys + passkey_challenges tables
- **031_add_users_deleted_at.sql** — users.deleted_at + deletion_token + deletion_purge_after columns
- **032_seed_user_role.sql** — default `user` role with all account:* perms + backfill user_roles for existing accounts
- **033_add_users_email_change.sql** — users.email_change_new + email_change_token + email_change_expires_at columns

## Cleanup Job (database/cleanup.go)
Runs every 1h (see main.go). Deletes:
- expired access_tokens / refresh_tokens / authorization_codes / device_codes / sessions
- **expired or used reauth_tokens (older than 24h)**
- **expired passkey_challenges**
- **users whose `deletion_purge_after` has elapsed (hard delete)**

## Seeded Data (migration 011 + 028 + 032)
- Role `admin` (UUID `00000000-0000-0000-0000-000000000001`)
- Role `user` (UUID `00000000-0000-0000-0000-000000000004`) — auto-assigned to all registrations
- 11 admin permissions (clients:*, users:*, roles:*, audit:read, keys:*, federation:*)
- 2 policy permissions (policies:read/write)
- 2 resource-meta permissions (resources:read/write)
- 9 account:* permissions (granted to both admin and user roles)

## Key Patterns
- Tokens (access, refresh, auth code, device code, reauth) stored as SHA-256 hashes, never raw
- Passkey credential public keys stored as CBOR-encoded bytes (decoded only inside go-webauthn calls)
- PostgreSQL-specific: pq.StringArray (TEXT[]), json.RawMessage (JSONB), INET for IPs, BYTEA for binary credentials
- Sensitive fields hidden with json:"-" (passwords, secrets, tokens, backup codes, passkey credential material)
- Refresh token family tracking via FamilyID/ParentID for rotation reuse detection
