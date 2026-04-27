# OrionAuth - Project Overview

## Purpose
OrionAuth is a full-featured OAuth2/OIDC authorization server written in Go. It implements a complete identity and access management system.

## Features
- User registration, authentication, email verification, password reset with account lockout
- OAuth2 flows: Authorization Code (with PKCE), Client Credentials, Refresh Token, Device Code (RFC 8628)
- OAuth2 security: Pushed Authorization Requests (PAR, RFC 9126), Request Objects (JAR, RFC 9101), authorization response iss (RFC 9207)
- OpenID Connect Core: ID tokens (RS256) with acr/amr claims, JWKS, Discovery, UserInfo (JSON + signed JWT), Hybrid flows (code id_token, code token, code id_token token)
- OIDC Advanced: Dynamic Client Registration (RFC 7591), Session Management (check_session_iframe), Back-Channel Logout, Front-Channel Logout, RP-Initiated Logout, Pairwise Subject Identifiers
- Client Auth Methods: client_secret_basic, client_secret_post, private_key_jwt (RFC 7523), none
- Multi-Factor Authentication: TOTP with backup codes
- Role-Based Access Control (RBAC) with permission middleware
- Policy-Based Authorization (OPA/Rego) for dynamic, context-aware access control
- Audit logging (async, queryable with filters)
- Federation: Social login with external OAuth/OIDC providers, account linking
- Session management with IP/User-Agent tracking
- Rate limiting (token bucket, per-IP)
- CORS, Request ID tracing

## Tech Stack
- **Language**: Go 1.25
- **Web Framework**: Gin (github.com/gin-gonic/gin)
- **ORM**: GORM (gorm.io/gorm) with PostgreSQL driver
- **Database**: PostgreSQL (pq.StringArray for arrays, JSONB, INET types)
- **Migrations**: goose/v3 with embedded SQL files (26 migrations)
- **Password Hashing**: Argon2id (crypto/argon2) with constant-time comparison
- **JWT**: golang-jwt/jwt/v5 with RS256 signing (2048-bit RSA keys)
- **TOTP**: github.com/pquerna/otp
- **Email**: go-mail (wneessen/go-mail) via SMTP
- **Config**: Viper with YAML + env var override (ORION_ prefix)
- **IDs**: UUID v7 (google/uuid)
- **Logging**: log/slog (structured)

## Architecture
Clean 3-layer architecture per domain package:
1. **Repository** (repository.go) — GORM queries, data access
2. **Service** (service.go) — Business logic, input DTOs, validation
3. **Handler** (handler.go) — HTTP handlers, request parsing, response formatting via pkg helpers

Dependencies injected via constructors (NewService, NewHandler pattern).
Routes registered via RegisterRoutes() methods on handlers.

## Entry Point
`main.go` — Initializes config, database, all repositories/services/handlers, sets up Gin router with middleware, starts HTTP server with graceful shutdown (SIGINT/SIGTERM).

## Configuration
`config.yaml` at project root (or /etc/orionauth), loaded via Viper.
Env vars with ORION_ prefix override file values.

### Config Sections
- **Server**: Host, Port, Mode (debug/release/test)
- **Database**: PostgreSQL connection params + pool settings (MaxOpenConns, MaxIdleConns, ConnMaxLifetime)
- **Auth**: AccessTokenTTL (1h), RefreshTokenTTL (24h), SessionTTL (720h/30d), AuthCodeTTL (60s), DeviceCodeTTL (10m), PasswordMinLen (8), MaxFailAttempts (5), LockoutDuration (15m)
- **Argon2**: Memory (64MB), Iterations (3), Parallelism (4), SaltLength (16), KeyLength (32)
- **CORS**: AllowedOrigins, Methods, Headers, MaxAge
- **SMTP**: Host, Port, Username, Password, From, FromName, TLS
- **Issuer**: Base URL for OIDC (e.g., http://localhost:8080)

## Package Structure
```
OrionAuth/
├── main.go              # Entry point, router setup, DI wiring
├── config.yaml          # Default configuration
├── config/              # Config struct and Viper loading
├── model/               # GORM models (15+ models, including PushedAuthorizationRequest)
├── database/            # DB connection + goose migration runner
├── migrations/          # 14 embedded SQL migration files
├── crypto/              # Argon2 hashing, opaque token generation, RSA key management, JWK parsing
├── pkg/                 # OAuthError, AppError types, JSON response helpers, pagination
├── middleware/           # BearerAuth, ClientAuth (incl. private_key_jwt), JWKSCache, CORS, RateLimiter, RequestID
├── user/                # User registration, login, profile, email verification, password reset
├── session/             # Session CRUD, revocation
├── client/              # OAuth client CRUD, secret rotation, Dynamic Client Registration (dcr_handler.go)
├── oauth/               # Authorization flows, token exchange, introspect, revoke, device code, PAR
├── oidc/                # OIDC discovery, JWKS, ID token generation, UserInfo, key rotation, session management, back/front-channel logout, pairwise sub
├── mfa/                 # TOTP enrollment, verification, backup codes
├── rbac/                # Roles, permissions, user-role assignment, permission middleware
├── policy/              # OPA/Rego policy engine, CRUD, evaluation, middleware
├── audit/               # Async audit logging, queryable logs
├── federation/          # Social login providers, account linking
├── email/               # Sender interface + SMTP implementation
```
