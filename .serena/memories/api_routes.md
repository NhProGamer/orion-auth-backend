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
| POST | /api/v1/auth/register | None | User registration |
| POST | /api/v1/auth/login | None | User login |
| POST | /api/v1/auth/forgot-password | None | Initiate password reset |
| POST | /api/v1/auth/reset-password | None | Complete password reset |
| POST | /api/v1/auth/verify-email | None | Verify email with token |
| GET | /api/v1/auth/federation/:provider | None | Get social login authorization URL |
| POST | /api/v1/auth/federation/:provider/callback | None | Process social login callback |

## Authenticated API Routes (/api/v1, bearer auth)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/me | Bearer | Get current user profile |
| PATCH | /api/v1/me | Bearer | Update profile |
| PUT | /api/v1/me/password | Bearer | Change password |
| GET | /api/v1/me/sessions | Bearer | List active sessions |
| DELETE | /api/v1/me/sessions/:id | Bearer | Revoke specific session |
| DELETE | /api/v1/me/sessions | Bearer | Revoke all other sessions |
| POST | /api/v1/me/mfa/totp/enroll | Bearer | Start TOTP enrollment |
| POST | /api/v1/me/mfa/totp/verify | Bearer | Confirm TOTP with code, returns backup codes |
| DELETE | /api/v1/me/mfa/totp | Bearer | Disable TOTP (requires valid code) |
| POST | /api/v1/me/mfa/backup-codes | Bearer | Regenerate backup codes |
| GET | /api/v1/me/linked-accounts | Bearer | List linked federation accounts |
| DELETE | /api/v1/me/linked-accounts/:id | Bearer | Unlink federation account |

## Admin API Routes (/api/v1/admin, bearer + RBAC)
| Method | Path | Permissions | Description |
|--------|------|------------|-------------|
| POST | /api/v1/admin/clients | clients:write | Create OAuth client |
| GET | /api/v1/admin/clients | clients:read | List clients (paginated) |
| GET | /api/v1/admin/clients/:id | clients:read | Get client details |
| PATCH | /api/v1/admin/clients/:id | clients:write | Update client |
| DELETE | /api/v1/admin/clients/:id | clients:write | Deactivate client |
| POST | /api/v1/admin/clients/:id/rotate-secret | clients:write | Rotate client secret |
| POST | /api/v1/admin/roles | roles:write | Create role |
| GET | /api/v1/admin/roles | roles:read | List roles |
| GET | /api/v1/admin/roles/:id | roles:read | Get role details |
| PATCH | /api/v1/admin/roles/:id | roles:write | Update role |
| DELETE | /api/v1/admin/roles/:id | roles:write | Delete role |
| GET | /api/v1/admin/permissions | roles:read | List all permissions |
| POST | /api/v1/admin/roles/:id/permissions | roles:write | Set role permissions |
| POST | /api/v1/admin/users/:id/roles | roles:write | Assign role to user |
| DELETE | /api/v1/admin/users/:id/roles/:roleId | roles:write | Remove role from user |
| GET | /api/v1/admin/users/:id/roles | roles:read | Get user roles |
| GET | /api/v1/admin/keys | keys:read | List signing keys |
| POST | /api/v1/admin/keys/rotate | keys:write | Rotate signing key |
| POST | /api/v1/admin/federation | federation:write | Create federation provider |
| GET | /api/v1/admin/federation | federation:read | List federation providers |
| PATCH | /api/v1/admin/federation/:id | federation:write | Update federation provider |
| DELETE | /api/v1/admin/federation/:id | federation:write | Delete federation provider |
| GET | /api/v1/admin/audit-logs | audit:read | Query audit logs (filters: user_id, action, from, to) |

## Middleware Stack
- **RequestID**: Generates/echoes X-Request-ID header (UUID)
- **CORS**: Configurable origin whitelist, credential support, OPTIONS preflight
- **RateLimiter**: Token bucket per IP (20 burst, 5 req/s on public auth routes)
- **BearerAuth**: Validates access token (SHA-256 hash lookup), checks session validity, sets context (userID, sessionID, tokenID, scopes)
- **ClientAuth**: Validates OAuth client via Basic Auth, POST form, or "none" (public). Sets OAuthClient in context
- **RBAC RequirePermission/RequireAnyPermission**: Checks user permissions via role assignments

## OIDC Discovery Values
- Response Types: ["code", "code id_token", "code token", "code id_token token"]
- Grant Types: ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]
- Subject Type: ["public", "pairwise"]
- ID Token Signing: ["RS256"]
- Scopes: ["openid", "profile", "email", "roles", "offline_access"]
- Token Auth Methods: ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"]
- Claims: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "acr", "amr", "c_hash", "s_hash", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "email", "email_verified", "phone_number", "phone_number_verified", "address", "updated_at", "roles", "groups"]
- Code Challenge Methods: ["S256"]
- End Session Endpoint: /end_session
- request_parameter_supported: true
- request_uri_parameter_supported: false
- authorization_response_iss_parameter_supported: true
- pushed_authorization_request_endpoint: /par
- frontchannel_logout_supported: true
- frontchannel_logout_session_supported: true
- check_session_iframe: /check_session
- userinfo_signing_alg_values_supported: ["RS256"]
- registration_endpoint: /register
- claims_parameter_supported: true

## OIDC Core Parameters Supported in /authorize
prompt (none|login|consent|select_account), max_age, display (page|popup|touch|wap), ui_locales, claims_locales, acr_values, login_hint, claims (JSON), id_token_hint
