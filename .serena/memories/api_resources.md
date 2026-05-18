# OrionAuth - API Resources (Resource Servers)

## Purpose
API Resources enable audience-scoped tokens following the Auth0/RFC 8707
pattern. Each API Resource represents a protected API identified by a unique
URI (audience), with its own set of permissions/scopes.

## Package: resource/
- interfaces.go — RepositoryInterface
- repository.go — GORM queries (resources, permissions, client-resource perms)
- service.go — CRUD + ValidateAudience/ValidateClientScopes for OAuth
- handler.go — Gin admin handlers

## Data Model
- `api_resources` table — id, name, identifier (audience URI), description,
  signing_alg, access_token_ttl, active
- `resource_permissions` table — id, resource_id FK, name, description
- `client_resource_permissions` — join (which client has which permission)
- Audience columns added to: access_tokens, refresh_tokens, authorization_codes,
  authorization_requests, device_codes, consents

## Migrations
- 018_create_api_resources.sql — initial schema
- 028_create_account_resource.sql — `orion-account` (User Account API)
- 034_create_m2m_resource.sql — `orion-m2m` (M2M admin API)

## OAuth Integration
- `ResourceValidator` interface in oauth/service.go
- `audience` parameter accepted in /authorize and /token (client_credentials)
- Audience propagated through codes + refresh tokens
- Introspection returns `aud` field when audience set

## Admin Endpoints (/api/v1/admin)
- CRUD: POST/GET/PATCH/DELETE /resources
- Permissions: POST/DELETE /resources/:id/permissions/:permId
- Client access: POST/GET /clients/:id/resource-permissions
- Role access: POST/GET /roles/:id/resource-permissions

## Frontend
- Admin UI: ResourcesListView + ResourceFormView
- Auth UI: ConsentPage shows permissions grouped per audience

## Seeded resource: `orion-account`
Identifier: `urn:orion:account` (id `00000000-0000-0000-0000-000000000003`).
Models the User Account API. Mirrored into RBAC `permissions` so the existing
`RequirePermission` middleware works.

Permissions (IDs `…0000a0`..`…0000a8`):
- account:read_profile, account:update_profile, account:change_email,
  account:change_password, account:manage_sessions, account:manage_mfa,
  account:manage_passkeys, account:manage_linked_accounts, account:delete_account

Default `user` role (migration 032, id `…00000004`) holds them all; the admin
role got them via 028. New registrations auto-receive `user`.

## Seeded resource: `orion-m2m`
Identifier: `urn:orion:m2m` (id `00000000-0000-0000-0000-000000000005`).
Models the M2M admin API at /api/v1/m2m/users/*. Consumed by services
authenticated in `client_credentials`. **Not** mirrored into RBAC (these
permissions are exclusively granted to OAuth clients via
client_resource_permissions, never to user roles).

Permissions (IDs `…0000b0`..`…0000b4`):
- m2m:users:read         — list/get/sessions/roles/passkeys/linked-accounts
- m2m:users:write        — POST create, PATCH update (any field except id)
- m2m:users:delete       — DELETE user (destructive)
- m2m:users:manage_auth  — password, unlock, MFA reset, revoke sessions/passkeys/links
- m2m:users:manage_roles — assign/remove user roles

No default client grant — the admin must explicitly attribute m2m:* to a
client via POST /admin/clients/:id/resource-permissions. Three actions
required before any service can call the M2M API:
1. Create the client as confidential
2. Add `client_credentials` to its grant_types
3. Attribute the desired m2m:* permissions
