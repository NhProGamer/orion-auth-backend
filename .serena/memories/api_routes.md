# OrionAuth - Complete API Routes

## Health Endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /health | None | Service health check |
| GET | /ready | None | Database readiness check |

## OAuth2 Endpoints (root level)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /authorize | None | Initiate authorization request |
| POST | /authorize/login | None | User login step in auth flow |
| POST | /authorize/mfa | None | MFA verification step in auth flow |
| POST | /authorize/consent | None | User consent step in auth flow |
| POST | /token | ClientAuth | Token endpoint (all grant types) |
| POST | /introspect | ClientAuth | RFC 7662 token introspection |
| POST | /revoke | ClientAuth | RFC 7009 token revocation |
| POST | /device_authorization | ClientAuth | RFC 8628 device code initiation |
| POST | /device/verify | None | Device code user verification |
| POST | /device/approve | None | Device code user approval |
| POST | /par | ClientAuth | Pushed Authorization Request (RFC 9126) |
| POST | /register | None | Dynamic Client Registration (RFC 7591) |

## OIDC Endpoints (root level)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /.well-known/openid-configuration | None | OIDC discovery document |
| GET | /.well-known/jwks.json | None | JWKS (Cache-Control: public, max-age=3600) |
| GET | /userinfo | Bearer | User info claims |
| POST | /userinfo | Bearer | User info claims |
| GET | /end_session | None | RP-Initiated Logout (OIDC) |
| GET | /check_session | None | OIDC Session Management iframe |

## Public API Routes (/api/v1, rate limited)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/auth/register | None | User registration (auto-assigns "user" role) |
| POST | /api/v1/auth/login | None | User login |
| POST | /api/v1/auth/forgot-password | None | Initiate password reset |
| POST | /api/v1/auth/reset-password | None | Complete password reset |
| POST | /api/v1/auth/verify-email | None | Verify email with token |
| GET | /api/v1/auth/federation/:provider | None | Get social login authorization URL |
| POST | /api/v1/auth/federation/:provider/callback | None | Process social login callback |
| POST | /api/v1/me/passkeys/login/begin | None | Begin usernameless passkey login (CredentialAssertion) |
| POST | /api/v1/me/passkeys/login/finish | None | Finish usernameless passkey login; returns matching user |
| POST | /api/v1/me/account/email/confirm | None | Confirm email change with token from email |
| POST | /api/v1/me/account/cancel-deletion | None | Cancel a pending account deletion with token |

## Authenticated User Account API (/api/v1, bearer auth + RBAC + optional step-up)
The "User Account API" is gated by RBAC permissions seeded under the `orion-account` API resource (migration 028). Default `user` role (migration 032) has them all; admins can revoke per-role. Sensitive endpoints additionally require an `X-Reauth-Token` header from `POST /api/v1/me/reauth`.

| Method | Path | Permission | Step-up | Description |
|--------|------|------------|---------|-------------|
| GET | /api/v1/me | account:read_profile | no | Profile |
| PATCH | /api/v1/me | account:update_profile | no | Update display name / avatar / phone / OIDC metadata |
| PUT | /api/v1/me/password | account:change_password | **yes** | Change password (also requires current_password in body); revokes other sessions and emails a notice |
| POST | /api/v1/me/account/email/change-request | account:change_email | **yes** | Send confirm link to the new email |
| DELETE | /api/v1/me | account:delete_account | **yes** | Soft-delete + 7d grace period; emails cancel link |
| GET | /api/v1/me/sessions | account:read_profile | no | List own active sessions |
| DELETE | /api/v1/me/sessions/:id | account:manage_sessions | no | Revoke a specific session |
| DELETE | /api/v1/me/sessions | account:manage_sessions | no | Revoke all other sessions |
| POST | /api/v1/me/mfa/totp/enroll | account:manage_mfa | no | Start TOTP enrollment |
| POST | /api/v1/me/mfa/totp/verify | account:manage_mfa | no | Confirm TOTP, return backup codes |
| POST | /api/v1/me/mfa/backup-codes | account:manage_mfa | no | Regenerate backup codes (requires TOTP code) |
| DELETE | /api/v1/me/mfa/totp | account:manage_mfa | **yes** | Disable TOTP (also requires TOTP code in body) |
| GET | /api/v1/me/passkeys | account:read_profile | no | List own passkeys |
| POST | /api/v1/me/passkeys/register/begin | account:manage_passkeys | no | Start WebAuthn registration |
| POST | /api/v1/me/passkeys/register/finish | account:manage_passkeys | no | Persist a new passkey |
| PATCH | /api/v1/me/passkeys/:id | account:manage_passkeys | no | Rename a passkey |
| POST | /api/v1/me/passkeys/reauth/begin | account:manage_passkeys | no | Start a passkey-based step-up challenge |
| DELETE | /api/v1/me/passkeys/:id | account:manage_passkeys | **yes** | Remove a passkey |
| GET | /api/v1/me/linked-accounts | account:read_profile | no | List linked federation accounts |
| DELETE | /api/v1/me/linked-accounts/:id | account:manage_linked_accounts | **yes** | Unlink a federation account |
| POST | /api/v1/me/reauth | (authenticated) | n/a | Issue a single-use step-up token (10 min, session-bound). Body: `{"method": "password|totp|backup_code|passkey", ...}` |

Every account.* action is logged with a dedicated audit constant (`account.profile_updated`, `account.email_changed`, `account.passkey_added`, etc.). The `/admin/audit-logs` endpoint accepts both `action=` (exact) and `action_prefix=` (LIKE prefix) filters.

## Admin API Routes (/api/v1/admin, bearer + RBAC)
Unchanged from the previous index; `policies:read/write` and `resources:read/write` already in place. The Resources screen now also lists the `orion-account` resource and its 9 permissions, which an admin can attribute to custom roles to fine-tune what end-users can do on their own account.

## Middleware Stack
- **RequestID, CORS, RateLimiter, BearerAuth, ClientAuth**: as before
- **RequireReauth(svc)**: enforces the `X-Reauth-Token` header; on success stashes `*model.ReauthToken` in ctx so handlers can `ConsumeReauth(c, svc, action)` after the sensitive op succeeds (single-use, only consumed on success — failures don't burn the token).
- **account.PolicyGate.Middleware(action)**: chained after RBAC, evaluates `account_action` Rego policies. Fail-open on lookup errors so a misconfig doesn't lock users out of their own data.

## OIDC Discovery Values
(unchanged)
