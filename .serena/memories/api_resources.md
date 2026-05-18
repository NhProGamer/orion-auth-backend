# OrionAuth - API Resources (Resource Servers)

## Purpose
API Resources enable audience-scoped tokens following the Auth0/RFC 8707 pattern. Each API Resource represents a protected API identified by a unique URI (audience), with its own set of permissions/scopes.

## Package: resource/
- interfaces.go — RepositoryInterface
- repository.go — GORM queries (resources, permissions, client-resource perms)
- service.go — CRUD + ValidateAudience/ValidateClientScopes for OAuth
- handler.go — Gin admin handlers

## Data Model
- `api_resources` table — id, name, identifier (audience URI), description, signing_alg, access_token_ttl, active
- `resource_permissions` table — id, resource_id FK, name, description
- `client_resource_permissions` join table — which client has access to which resource permissions
- Audience columns added to: access_tokens, refresh_tokens, authorization_codes, authorization_requests, device_codes, consents

## Migrations
- 018_create_api_resources.sql — initial schema
- 028_create_account_resource.sql — seeds the `orion-account` resource for the User Account API

## OAuth Integration
- `ResourceValidator` interface in oauth/service.go (ValidateAudience, ValidateClientScopes)
- `audience` parameter accepted in InitAuthorize (GET /authorize) and ExchangeClientCredentials (POST /token)
- Audience propagated through auth codes and refresh tokens
- Introspection returns `aud` field when token has audience
- Backwards compatible: no audience = existing behavior

## Admin Endpoints (/api/v1/admin)
- CRUD: POST/GET/PATCH/DELETE /resources
- Permissions: POST/DELETE /resources/:id/permissions/:permId
- Client access: POST/GET /clients/:id/resource-permissions
- Role access: POST/GET /roles/:id/resource-permissions

## Frontend
- Admin UI: ResourcesListView + ResourceFormView with inline permission management
- Auth UI: ConsentPage shows resource permissions grouped when audience is specified

## Seeded resource: `orion-account`
Identifier: `urn:orion:account` (id `00000000-0000-0000-0000-000000000003`).
Models the User Account API — every self-service `/api/v1/me*` endpoint is gated by one of its permissions. The same permissions are mirrored into the RBAC `permissions` table so the existing `RequirePermission` middleware works unchanged.

Permissions (IDs `00000000-0000-0000-0000-0000000000a0`..`a8`):
- `account:read_profile`
- `account:update_profile`
- `account:change_email`
- `account:change_password`
- `account:manage_sessions`
- `account:manage_mfa`
- `account:manage_passkeys`
- `account:manage_linked_accounts`
- `account:delete_account`

Default `user` role (migration 032, id `00000000-0000-0000-0000-000000000004`) has them all; the admin role got them via 028's blanket grant. New registrations auto-receive the `user` role via `userService.SetDefaultRole(...)` in main.go.
