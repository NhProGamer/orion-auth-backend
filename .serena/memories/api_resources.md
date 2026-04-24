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

## Migration: 018_create_api_resources.sql

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

## Frontend
- Admin UI: ResourcesListView + ResourceFormView with inline permission management
- Auth UI: ConsentPage shows resource permissions grouped when audience is specified
