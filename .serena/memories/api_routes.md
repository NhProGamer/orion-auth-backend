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
(unchanged — auth/register, auth/login, forgot-password, reset-password, verify-email,
federation/:provider, federation/:provider/callback, /me/passkeys/login/{begin,finish},
/me/account/email/confirm, /me/account/cancel-deletion)

## Authenticated User Account API (/api/v1/me/*, bearer auth + RBAC + optional step-up)
(unchanged — see previous index; gated by orion-account resource permissions
account:read_profile, account:update_profile, account:change_email,
account:change_password, account:manage_sessions, account:manage_mfa,
account:manage_passkeys, account:manage_linked_accounts, account:delete_account.
Step-up X-Reauth-Token required on sensitive endpoints.)

## M2M API (/api/v1/m2m/users/*, client_credentials bearer)
Service-to-service admin API. Consumed by services authenticated in OAuth2
`client_credentials` with audience **`urn:orion:m2m`** and scope-gated access.
Equivalent of /api/v1/admin/users/* but with the M2M audience instead of
user RBAC. **No step-up reauth** — the scope on the token is the only barrier.

Each call is logged with the caller `client_id` (from the bearer) and the
affected user in `metadata.target_user_id`. Filter via
`/admin/audit-logs?action_prefix=m2m.`.

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | /api/v1/m2m/users | m2m:users:read | List paginated |
| POST | /api/v1/m2m/users | m2m:users:write | Create (body: email, password optional, display_name, email_verified, active, phone, avatar_url, metadata, role_ids). Returns generated_password once if omitted. |
| GET | /api/v1/m2m/users/:id | m2m:users:read | Get (AdminView) |
| PATCH | /api/v1/m2m/users/:id | m2m:users:write | Update any field except id |
| DELETE | /api/v1/m2m/users/:id | m2m:users:delete | Hard delete (cascade) |
| PUT | /api/v1/m2m/users/:id/password | m2m:users:manage_auth | Set password (no current_password); revokes all sessions |
| POST | /api/v1/m2m/users/:id/unlock | m2m:users:manage_auth | Clear failed_login_attempts + locked_until |
| POST | /api/v1/m2m/users/:id/mfa/reset | m2m:users:manage_auth | Force-disable TOTP |
| GET | /api/v1/m2m/users/:id/roles | m2m:users:read | List user's roles |
| POST | /api/v1/m2m/users/:id/roles | m2m:users:manage_roles | Body: { role_id } |
| DELETE | /api/v1/m2m/users/:id/roles/:roleId | m2m:users:manage_roles | Remove role |
| GET | /api/v1/m2m/users/:id/sessions | m2m:users:read | List active sessions |
| DELETE | /api/v1/m2m/users/:id/sessions/:sid | m2m:users:manage_auth | Revoke session |
| DELETE | /api/v1/m2m/users/:id/sessions | m2m:users:manage_auth | Revoke all |
| GET | /api/v1/m2m/users/:id/passkeys | m2m:users:read | List passkeys (PublicView) |
| DELETE | /api/v1/m2m/users/:id/passkeys/:pid | m2m:users:manage_auth | Remove passkey |
| GET | /api/v1/m2m/users/:id/linked-accounts | m2m:users:read | List federation links |
| DELETE | /api/v1/m2m/users/:id/linked-accounts/:linkId | m2m:users:manage_auth | Unlink |

Error codes on the M2M path (RFC 6750 style):
- `403 m2m_only` — the token is user-bound (rejected by RequireClientScope)
- `403 wrong_audience` — token's aud != urn:orion:m2m
- `403 insufficient_scope` — token missing the required scope. Response carries
  `WWW-Authenticate: Bearer error="insufficient_scope", scope="m2m:users:..."`.

## Admin API Routes (/api/v1/admin, bearer + RBAC)
(unchanged)

## Middleware Stack
- **RequestID, CORS, RateLimiter, BearerAuth, ClientAuth**: as before
- **RequireReauth(svc)**: enforces X-Reauth-Token for /me sensitive ops
- **account.PolicyGate.Middleware(action)**: evaluates account_action Rego policies
- **RequireClientScope(db, scope, audience)** (NEW): the M2M gate. Rejects
  user-bound tokens, checks aud + scope, sets ClientID in context. Pure
  helpers (`containsScope`, `parseScopes`) + token lookup factored via
  `LookupAccessToken(db, raw)` shared with BearerAuth.

## OIDC Discovery Values
(unchanged)
