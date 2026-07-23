<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="email/templates/assets/logo-dark.svg">
    <img alt="OrionAuth" src="email/templates/assets/logo-light.svg" width="120">
  </picture>

  <h1>orion-auth-backend</h1>

  <p>
    <b>OAuth 2.0 + OpenID Connect authorization server.</b><br>
    Single Go binary &middot; PostgreSQL &middot; optional SMTP &middot; ready to run behind any reverse proxy.
  </p>
</div>

---

## What it is

A full OIDC Identity Provider written in Go. It speaks the core OAuth 2.0
and OpenID Connect specs, ships a complete user-management surface
(registration, MFA, passkeys, federation, RBAC, audit), and is operated
through two adjacent SPAs (`orion-auth-frontend` for admins,
`orion-auth-authui` for end users).

This README is the operator manual: **how to run it, how to integrate a
client against it, and how to keep it healthy in production**. It is not
an exhaustive code walkthrough — for that, the Swagger UI is mounted at
`/swagger/*` in debug mode, and the `.serena/memories/` directory holds
architectural notes.

### Standards coverage at a glance

| Spec | Status |
|------|--------|
| OAuth 2.0 (RFC 6749) authorization code, refresh, client credentials | ✓ |
| OAuth 2.0 PKCE (RFC 7636), S256 only | ✓ |
| OAuth 2.0 Device Authorization Grant (RFC 8628) | ✓ |
| OAuth 2.0 Pushed Authorization Requests (RFC 9126) | ✓ |
| OAuth 2.0 JWT-Secured Authorization Request — JAR (RFC 9101) | ✓ |
| OAuth 2.0 Authorization Server Issuer Identification (RFC 9207) | ✓ |
| OAuth 2.0 Token Introspection (RFC 7662) | ✓ |
| OAuth 2.0 Token Revocation (RFC 7009) | ✓ |
| OIDC Core 1.0 — discovery, ID tokens (RS256), UserInfo, hybrid flows | ✓ |
| OIDC Initiating User Registration 1.0 (`prompt=create`) | ✓ |
| OIDC Session Management 1.0 — `check_session`, front-channel logout | ✓ |
| OIDC Back-Channel Logout 1.0 | ✓ |
| OIDC RP-Initiated Logout 1.0 | ✓ |
| OIDC Dynamic Client Registration 1.0 (RFC 7591) | ✓ |
| OIDC Pairwise Subject Identifiers (per-sector) | ✓ |
| Client auth: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `none` | ✓ |
| DPoP (RFC 9449), mTLS client auth (RFC 8705), RAR (RFC 9396), CIBA | — roadmap |

---

## Table of contents

- [Quickstart (docker-compose)](#quickstart-docker-compose)
- [Configuration reference](#configuration-reference)
- [Integrating an OAuth / OIDC client](#integrating-an-oauth--oidc-client)
- [Federation (social login)](#federation-social-login)
- [Migrating from another IAM](MIGRATION.md)
- [Operating in production](#operating-in-production)
  - [Health and readiness](#health-and-readiness)
  - [Metrics and dashboards](#metrics-and-dashboards)
  - [Key rotation](#key-rotation)
  - [Backup and restore](#backup-and-restore)
  - [Email outbox](#email-outbox)
- [Troubleshooting](#troubleshooting)

---

## Quickstart (docker-compose)

```yaml
# docker-compose.yml — single-node dev/staging
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: orionauth
      POSTGRES_USER: orionauth
      POSTGRES_PASSWORD: change-me
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U orionauth"]
      interval: 5s

  mailhog:
    image: mailhog/mailhog
    ports: ["8025:8025"]      # web UI

  auth:
    build: .
    depends_on:
      postgres: { condition: service_healthy }
    environment:
      ORION_SERVER_MODE: release
      ORION_DATABASE_HOST: postgres
      ORION_DATABASE_PASSWORD: change-me
      ORION_SMTP_HOST: mailhog
      ORION_SMTP_PORT: "1025"
      ORION_SMTP_TLS: "false"     # acceptable against mailhog only
      ORION_ISSUER: http://localhost:8080
      ORION_AUTH_HMAC_SECRET_ENCRYPTION_KEY: <see secret generation>
      ORION_AUTH_ACTION_TOKEN_SIGNING_KEY:   <see secret generation>
      ORION_PAIRWISE_SALT:                   <see secret generation>
    ports: ["8080:8080"]

volumes:
  pgdata:
```

Generate the three required secrets **before first boot**:

```bash
# 32-byte AES-256 key (base64) — seals client_secret_jwt + federation secrets at rest
openssl rand -base64 32

# 32-byte HMAC key (base64) — signs verify-email action tokens
openssl rand -base64 32

# 32-byte salt (hex) — derives per-sector pairwise OIDC subs
openssl rand -hex 32
```

Then:

```bash
docker compose up -d
curl http://localhost:8080/ready
# {"status":"ok","checks":{"database":"ok","jwks":"ok"}}
```

The discovery document is served at
`http://localhost:8080/.well-known/openid-configuration`.

---

## Configuration reference

Configuration loads in this order (later wins):

1. `config.yaml` in the working directory
2. `/etc/orionauth/config.yaml`
3. Environment variables prefixed `ORION_` (e.g. `database.host` → `ORION_DATABASE_HOST`)

In release mode (`ORION_SERVER_MODE=release`), `config.Validate()` refuses
startup when any **required** value is empty or holds the shipped
placeholder.

### Required in release mode

| Key | Env var | Purpose |
|-----|---------|---------|
| `server.mode` | `ORION_SERVER_MODE` | Set to `release` to enforce invariants and emit HSTS. |
| `database.password` | `ORION_DATABASE_PASSWORD` | Postgres connection password. |
| `auth.hmac_secret_encryption_key` | `ORION_AUTH_HMAC_SECRET_ENCRYPTION_KEY` | base64 32-byte AES-256; seals client_secret_jwt + federation secrets. |
| `auth.action_token_signing_key` | `ORION_AUTH_ACTION_TOKEN_SIGNING_KEY` | base64 32+-byte HMAC; signs verify-email links. Rotating invalidates outstanding links. |
| `issuer` | `ORION_ISSUER` | Public HTTPS URL the discovery document advertises. |
| `pairwise_salt` | `ORION_PAIRWISE_SALT` | Random hex; derives pairwise OIDC `sub` values. **Do not rotate after launch** — breaks downstream RP identity continuity. |

### Strongly recommended behind a reverse proxy / CDN

| Key | Purpose |
|-----|---------|
| `server.trusted_proxies` | List of IP/CIDR ranges Gin trusts to set `X-Forwarded-For`. Without this, `c.ClientIP()` reads the header verbatim — audit logs and per-IP rate-limit buckets become attacker-controlled. Example: `["10.0.0.0/8", "172.16.0.0/12"]`. |
| `server.trusted_platform` | Set when fronted by a known CDN (e.g. `CF-Connecting-IP` for Cloudflare). Overrides `trusted_proxies` for IP lookup. |
| `cors.allowed_origins` | Browser SPAs allowed to call the API. Wildcard + credentials is rejected; configure exact origins. |
| `database.sslmode` | `require` when Postgres is on a separate host. `disable` is only safe inside a private network (docker bridge / pod network). |
| `smtp.tls` | `true` in production. `false` only when targeting MailHog or another loopback test server. |

### Auth + token lifetimes

| Key | Default | Notes |
|-----|---------|-------|
| `auth.access_token_ttl` | `1h` | Short — clients refresh as needed. |
| `auth.refresh_token_ttl` | `24h` | Family-tracked with reuse detection. |
| `auth.session_ttl` | `720h` (30d) | Default browser session. |
| `auth.session_extended_ttl` | `720h` | Used when `remember_me=true`. Admin override via settings table. |
| `auth.auth_code_ttl` | `60s` | OAuth authorization code lifetime. |
| `auth.device_code_ttl` | `10m` | RFC 8628 device flow. |
| `auth.password_min_length` | `8` | Hard floor; admin password policy can be stricter. |
| `auth.max_failed_attempts` | `5` | Login lockout threshold per user. |
| `auth.lockout_duration` | `15m` | Fixed lockout window after the threshold. |

### Argon2id (password hashing)

Defaults match the OWASP recommendation. Increase `memory` on beefy
hosts to slow brute-force further:

```yaml
argon2:
  memory: 65536      # 64 MiB
  iterations: 3
  parallelism: 4
  salt_length: 16
  key_length: 32
```

---

## Integrating an OAuth / OIDC client

### 1. Register a client

Two paths:

- **Manual** via the AdminUI (`orion-auth-frontend`) or by inserting
  into `oauth_clients` directly. Set `redirect_uris`, `allowed_scopes`,
  `token_endpoint_auth_method`.
- **Dynamic Client Registration** (RFC 7591): `POST /register` with a
  metadata JSON document. Gate the endpoint behind
  `auth.dcr_initial_access_token` if you don't want it open to the
  internet.

### 2. Discover endpoints

```bash
curl https://auth.example.test/.well-known/openid-configuration
```

The response advertises every endpoint you'll call:
`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`jwks_uri`, `end_session_endpoint`, `device_authorization_endpoint`,
`introspection_endpoint`, `revocation_endpoint`.

### 3. Authorization Code + PKCE (recommended)

Public clients (SPAs, native apps) **must** use PKCE with `S256`:

```
GET /ui/authorize?
    response_type=code
    &client_id=<your-id>
    &redirect_uri=https://your-app/callback
    &scope=openid profile email
    &code_challenge=<S256 challenge>
    &code_challenge_method=S256
    &state=<csrf>
    &nonce=<replay guard>
```

User completes login + consent → redirect back with `code` + `state`.
Exchange the code at the token endpoint:

```
POST /token
  grant_type=authorization_code
  code=<code>
  redirect_uri=<must match the authorize call>
  code_verifier=<PKCE verifier>
  client_id=<your-id>           # public clients
  # OR
  client_secret=<secret>        # client_secret_post
  client_assertion=<JWT>        # private_key_jwt / client_secret_jwt
```

### 4. Initiating signup (OIDC `prompt=create`)

Add `prompt=create` to the authorize URL. The user lands on the signup
form instead of login, completes signup, clicks the verify-email link
in their inbox, and is **auto-logged-in** into your app. See
`.serena/memories/oauth_flows_detail.md` for the full handshake.

---

## Federation (social login)

Register an external provider (Discord, GitHub, or any generic
OIDC/OAuth2 IdP) via the AdminUI or by inserting into
`federation_providers`. Required fields: `name`, `type`
(`oidc` | `oauth2`), `client_id`, `client_secret`, `authorization_url`,
`token_url`, `userinfo_url`, `scopes`.

> **Account takeover policy (hard rule):**
> the server **never auto-links** an external identity to a local
> account on matching email. Users who already have a local account
> must sign in locally first, then link the provider from their
> profile. This is enforced server-side; do not weaken it.

---

## Operating in production

### Health and readiness

| Endpoint | Purpose | Probe target |
|----------|---------|--------------|
| `GET /health` | Liveness: process is up. Always 200 if the server is responding. | Kubernetes `livenessProbe`. |
| `GET /ready` | Readiness: DB ping + active JWKS signing key. 503 if either fails. | Kubernetes `readinessProbe`, ALB target health. |

### Metrics and dashboards

Scrape `GET /metrics` (Prometheus exposition format). Series exposed:

```
orionauth_login_total{result}                          # success|fail|locked|mfa_required|email_not_verified
orionauth_oauth_token_issued_total{grant_type}         # authorization_code, refresh_token, ...
orionauth_http_request_duration_seconds_bucket{method,route,status}
go_* / process_*                                       # runtime collectors
```

Useful PromQL starters:

```promql
# Login failure ratio (5 min)
sum(rate(orionauth_login_total{result!="success"}[5m]))
  / sum(rate(orionauth_login_total[5m]))

# p95 token-endpoint latency
histogram_quantile(0.95,
  sum by (le) (rate(orionauth_http_request_duration_seconds_bucket{route="/token"}[5m])))
```

For outbox depth (no Prometheus series yet), query the DB directly:

```sql
SELECT status, COUNT(*) FROM outbound_emails GROUP BY status;
```

### Key rotation

| Key | Rotation policy | Procedure |
|-----|-----------------|-----------|
| RSA signing key (JWKS) | Rotate on operator action; old key is kept 24 h for the verification window. | AdminUI → Settings → **Rotate signing key**. |
| `auth.action_token_signing_key` | Rotate on suspected leak. **Invalidates all outstanding verify-email links** — users mid-signup must click "resend". | Generate a new key, update the env var / config, restart. No DB change. |
| `auth.hmac_secret_encryption_key` | Rotate carefully; re-encrypts every stored client_secret_jwt seal. | Manual SQL until a rotation tool ships. |
| `pairwise_salt` | **Do not rotate after launch.** Changing it changes every pairwise `sub`, breaking downstream RP identity mapping. | n/a |

### Backup and restore

```bash
# Backup: pg_dump nightly + archive WAL for PITR
pg_dump -Fc -d orionauth -f orionauth-$(date +%Y%m%d).dump

# Restore (DB must be empty)
createdb orionauth
pg_restore -d orionauth orionauth-20260605.dump
```

What you lose without backups:

- Every user account, password hash, MFA enrollment.
- Every OAuth client + secret.
- Every audit log line (no other persistence layer).
- Every pending verify-email row (users will need to request resend).

There is no built-in user-data export endpoint yet (GDPR Art. 15 is on
the roadmap). Until then, query the relevant tables directly:
`users`, `audit_logs`, `federation_links`, `sessions`, `mfa_methods`.

### Email outbox

`outbound_emails` is the persistent retry queue. Every `Send*` call
inserts a row; a background worker drains it via SMTP with exponential
backoff (2 m → 4 m → 8 m → 16 m → cap 1 h, 5 attempts by default —
total retry window ~30 min).

Operational queries:

```sql
-- Pending backlog
SELECT status, COUNT(*) FROM outbound_emails GROUP BY status;

-- Stuck rows (still retrying, will fail eventually)
SELECT id, recipient, subject, attempts, last_error, next_retry_at
FROM outbound_emails
WHERE status = 'pending' AND attempts >= 3
ORDER BY next_retry_at;

-- Replay a failed row
UPDATE outbound_emails
SET status='pending', attempts=0, next_retry_at=NOW(), last_error=NULL
WHERE id = '<uuid>';
```

Retention: the periodic cleanup job purges `sent` and `failed` rows
older than 7 days.

---

## Troubleshooting

> **Startup error: `auth.action_token_signing_key is empty`**
> You're in release mode without the key set. Generate one
> (`openssl rand -base64 32`) and export
> `ORION_AUTH_ACTION_TOKEN_SIGNING_KEY`.

> **Login returns 403 `email_not_verified`**
> The default gate refuses login until email is verified. Either ask
> the user to click the verify link,
> `POST /api/v1/auth/resend-verification`, or disable the gate via
> AdminUI → Settings → **Require email verification**.

> **OAuth client gets `invalid_grant` on code exchange**
> Usual suspects: PKCE `code_verifier` mismatch, expired code
> (60 s default), reused code (one-shot), or `redirect_uri` not
> matching exactly.

> **Verify-email link 302s to the error page**
> The action-token JWT failed validation: expired (24 h), tampered, or
> signed with a prior key. The user must request a new link.

> **Behind a reverse proxy, audit logs show the proxy IP**
> `server.trusted_proxies` is not set. Add the proxy IP/CIDR and
> restart; `c.ClientIP()` will then deduce the real client from
> `X-Forwarded-For`.

> **Outbox worker silent on email delivery**
> Inspect `outbound_emails` directly. Rows stuck `pending` with
> `attempts=0` mean the worker isn't running (check logs for
> "email outbox worker started"). Rows with `last_error` mean SMTP
> config is wrong.

---

For deeper architectural context, see the Serena memories in
`.serena/memories/` (`project_overview`, `oauth_flows_detail`,
`policy_engine`, `services_and_repositories`, …).
