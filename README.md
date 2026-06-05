# orion-auth-backend

OAuth2 / OpenID Connect authorization server. Single Go binary,
PostgreSQL for state, optional SMTP for transactional email.

This README is the operator manual: how to run it, how to integrate a
client against it, and how to keep it healthy in production. It is
**not** an exhaustive code walkthrough — for that, browse the package
docs or the Swagger UI mounted at `/swagger/*` in debug mode.

---

## Table of contents

1. [Quickstart (docker-compose)](#quickstart-docker-compose)
2. [Configuration reference](#configuration-reference)
3. [Integrating an OAuth/OIDC client](#integrating-an-oauthoidc-client)
4. [Federation: social login providers](#federation-social-login-providers)
5. [Operating in production](#operating-in-production)
   - [Health & readiness](#health--readiness)
   - [Metrics & dashboards](#metrics--dashboards)
   - [Key rotation](#key-rotation)
   - [Backup & restore](#backup--restore)
   - [Email outbox](#email-outbox)
6. [Troubleshooting](#troubleshooting)

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
    ports: ["8025:8025"]   # web UI

  auth:
    build: .
    depends_on:
      postgres: { condition: service_healthy }
    environment:
      ORION_SERVER_MODE: release
      ORION_DATABASE_HOST: postgres
      ORION_DATABASE_PASSWORD: change-me
      ORION_SMTP_HOST: mailhog
      ORION_SMTP_PORT: 1025
      ORION_SMTP_TLS: "false"   # ok against mailhog only
      ORION_ISSUER: http://localhost:8080
      ORION_AUTH_HMAC_SECRET_ENCRYPTION_KEY: <see key generation below>
      ORION_AUTH_ACTION_TOKEN_SIGNING_KEY: <see key generation below>
      ORION_PAIRWISE_SALT: <see key generation below>
    ports: ["8080:8080"]

volumes:
  pgdata:
```

**Generate the required secrets** before first boot:

```bash
# HMAC seal key (32 bytes, base64) — encrypts per-client secrets at rest
openssl rand -base64 32

# Action-token signing key (32 bytes, base64) — signs verify-email JWTs
openssl rand -base64 32

# Pairwise subject salt (32 bytes, hex) — derives per-sector OIDC subs
openssl rand -hex 32
```

Then `docker compose up -d` and watch:

```
$ curl http://localhost:8080/ready
{"status":"ok","checks":{"database":"ok","jwks":"ok"}}
```

The `/.well-known/openid-configuration` discovery document is now
served at `http://localhost:8080`.

---

## Configuration reference

Configuration is loaded from `config.yaml` (project root or
`/etc/orionauth/`) and overlaid by `ORION_*` env vars. Env vars use
upper-snake-case path mapping: `database.host` →
`ORION_DATABASE_HOST`. Env vars **win** over the file.

Release-mode validation (in `config/validate.go`) refuses startup
when any of the must-override values is empty or holds the shipped
placeholder.

### Required in release mode

| YAML path | Env var | Purpose |
|---|---|---|
| `server.mode` | `ORION_SERVER_MODE` | Set to `release` to enable Validate() invariants and emit HSTS. |
| `database.password` | `ORION_DATABASE_PASSWORD` | Postgres connection password. |
| `auth.hmac_secret_encryption_key` | `ORION_AUTH_HMAC_SECRET_ENCRYPTION_KEY` | base64 32-byte AES-256 key; seals client_secret_jwt + federation secrets at rest. |
| `auth.action_token_signing_key` | `ORION_AUTH_ACTION_TOKEN_SIGNING_KEY` | base64 32+-byte HMAC key; signs verify-email links. Rotating invalidates outstanding links. |
| `issuer` | `ORION_ISSUER` | Public HTTPS URL the discovery document advertises. |
| `pairwise_salt` | `ORION_PAIRWISE_SALT` | Random hex string; derives pairwise OIDC `sub` values. Rotating breaks downstream RP identity continuity — do not rotate after launch. |

### Recommended, behind reverse proxy / CDN

| YAML path | Purpose |
|---|---|
| `server.trusted_proxies` | List of IP/CIDR ranges Gin trusts to set `X-Forwarded-For`. Without this, `c.ClientIP()` reads the header verbatim — audit logs and per-IP rate-limit buckets become attacker-controlled. Example: `["10.0.0.0/8", "172.16.0.0/12"]`. |
| `server.trusted_platform` | Set when behind a known CDN (e.g. `CF-Connecting-IP` for Cloudflare). Overrides `trusted_proxies` for the IP lookup. |
| `cors.allowed_origins` | Browser SPAs that may call the API. Wildcard + credentials is rejected; configure exact origins. |
| `database.sslmode` | `require` when Postgres is on a separate host. `disable` only safe inside a private network (docker bridge / pod network). |
| `smtp.tls` | `true` in production. `false` only when targeting MailHog/localhost. |

### Auth + token TTLs

| YAML path | Default | Notes |
|---|---|---|
| `auth.access_token_ttl` | `1h` | Short — clients should rely on refresh. |
| `auth.refresh_token_ttl` | `24h` | Family-tracked with reuse detection. |
| `auth.session_ttl` | `720h` (30d) | Default browser session. |
| `auth.session_extended_ttl` | `720h` | Used when `remember_me=true`. Admin override via settings table. |
| `auth.auth_code_ttl` | `60s` | OAuth authorization code lifetime. |
| `auth.device_code_ttl` | `10m` | RFC 8628 device flow. |
| `auth.password_min_length` | `8` | Hard floor; admin password policy can be stricter. |
| `auth.max_failed_attempts` | `5` | Lockout threshold per user. |
| `auth.lockout_duration` | `15m` | Fixed lockout window after threshold. |

### Argon2id (password hashing)

Defaults match the OWASP recommendation. Tune `memory` upward on
beefy hosts to slow brute-force further:

```yaml
argon2:
  memory: 65536      # 64MB
  iterations: 3
  parallelism: 4
  salt_length: 16
  key_length: 32
```

---

## Integrating an OAuth/OIDC client

### 1. Register a client

Two paths:

- **Manual**: insert via the AdminUI (orion-auth-frontend) or
  `INSERT INTO oauth_clients ...`. Set `redirect_uris`,
  `allowed_scopes`, `token_endpoint_auth_method`.
- **Dynamic Client Registration (RFC 7591)**: `POST /register` with
  a JSON metadata document. Gated by `auth.dcr_initial_access_token`
  if you don't want it open.

### 2. Discover endpoints

```bash
curl https://auth.example.test/.well-known/openid-configuration
```

Returns `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`jwks_uri`, `end_session_endpoint`, etc.

### 3. Authorization code + PKCE (recommended)

Public clients (SPAs, native) **must** use PKCE S256:

```
GET /ui/authorize?
    response_type=code
    &client_id=<your-id>
    &redirect_uri=https://your-app/callback
    &scope=openid profile email
    &code_challenge=<S256-challenge>
    &code_challenge_method=S256
    &state=<csrf>
    &nonce=<replay-guard>
```

User completes login + consent → redirect back with `code` + `state`.
Then:

```
POST /token
  grant_type=authorization_code
  code=<code>
  redirect_uri=<must match>
  code_verifier=<PKCE verifier>
  client_id=<your-id>     # for public clients
```

Confidential clients add `client_secret`, or `client_assertion` for
`private_key_jwt` / `client_secret_jwt`.

### 4. Initiating signup (OIDC `prompt=create`)

Add `prompt=create` to the authorize URL. The user lands on the
signup form instead of login, completes signup, clicks the
verify-email link, and is auto-logged-in into your app. See
`/.serena/memories/oauth_flows_detail` for details.

---

## Federation: social login providers

Register an external provider (Discord, GitHub, generic OIDC) via the
AdminUI or `INSERT INTO federation_providers ...`. Required fields:
`name`, `type` (`oidc` or `oauth2`), `client_id`, `client_secret`,
`authorization_url`, `token_url`, `userinfo_url`, `scopes`.

### Anti-takeover policy

The server **never auto-links** an external identity to a local
account on matching email. Users who already have a local account
must sign in locally first, then link the provider from their
profile. This is enforced server-side and documented in the
federation memory; do not weaken it.

---

## Operating in production

### Health & readiness

| Endpoint | Purpose | Probe |
|---|---|---|
| `GET /health` | Liveness: process is up. Always 200. | Kubernetes liveness. |
| `GET /ready` | Readiness: DB ping + active JWKS signing key. 503 if either fails. | Kubernetes readiness, ALB health. |

### Metrics & dashboards

Scrape `GET /metrics` (Prometheus exposition format). Key series:

```
orionauth_login_total{result}                      # success|fail|locked|mfa_required|email_not_verified
orionauth_oauth_token_issued_total{grant_type}     # authorization_code, refresh_token, ...
orionauth_http_request_duration_seconds_bucket{method,route,status}
go_* / process_*                                   # runtime collectors
```

Useful PromQL starters:

```
# Login failure ratio
sum(rate(orionauth_login_total{result!="success"}[5m]))
 / sum(rate(orionauth_login_total[5m]))

# p95 token-endpoint latency
histogram_quantile(0.95,
  sum by (le) (rate(orionauth_http_request_duration_seconds_bucket{route="/token"}[5m])))

# Outbox stalls (no successful deliveries despite pending rows)
# → query the DB directly: SELECT COUNT(*), MAX(attempts) FROM outbound_emails WHERE status='pending'
```

### Key rotation

| Key | Rotation policy | Procedure |
|---|---|---|
| RSA signing key (JWKS) | Auto-rotates on operator action via the AdminUI; old key kept 24h for verification window. | AdminUI → Settings → "Rotate signing key". |
| `auth.action_token_signing_key` | Rotate on suspected leak. **Invalidates all outstanding verify-email links** — users mid-signup must click "resend". | Generate new key, update env var / config, restart. No DB change. |
| `auth.hmac_secret_encryption_key` | Rotate carefully — re-encrypts all stored client_secret_jwt seals. | (todo: rotation tool — manual SQL until then). |
| `pairwise_salt` | **Do not rotate after launch.** Changing it changes every pairwise `sub` value, breaking downstream RP identity mapping. | n/a |

### Backup & restore

```bash
# Backup: pg_dump nightly + archive WAL for PITR.
pg_dump -Fc -d orionauth -f orionauth-$(date +%Y%m%d).dump

# Restore (DB must be empty):
createdb orionauth
pg_restore -d orionauth orionauth-20260605.dump
```

What you lose if you skip backups:

- Every user account, password hash, MFA enrollment.
- Every OAuth client + secret.
- Every audit log line (no other persistence layer).
- Every pending verify-email row (users will need to resend).

There is no built-in user-data export endpoint yet (GDPR Art. 15 is
on the roadmap — see plan). Until then, use `SELECT` queries against
`users`, `audit_logs`, `federation_links`, `sessions`, `mfa_methods`.

### Email outbox

`outbound_emails` is the persistent retry queue. Every `Send*` call
inserts a row; a background worker drains it via SMTP with
exponential backoff (2m → 1h cap, 5 attempts by default = ~30min
total retry window).

Operational queries:

```sql
-- Pending backlog
SELECT status, COUNT(*) FROM outbound_emails GROUP BY status;

-- Stuck rows (kept retrying, will fail eventually)
SELECT id, recipient, subject, attempts, last_error, next_retry_at
FROM outbound_emails
WHERE status = 'pending' AND attempts >= 3
ORDER BY next_retry_at;

-- Replay a failed row (admin action — bump status, reset attempts)
UPDATE outbound_emails
SET status='pending', attempts=0, next_retry_at=NOW(), last_error=NULL
WHERE id = '<uuid>';
```

Retention: the periodic cleanup job purges `sent` and `failed` rows
older than 7 days.

---

## Troubleshooting

**Startup error: `auth.action_token_signing_key is empty`**
You're in release mode without the key set. Generate one
(`openssl rand -base64 32`) and export
`ORION_AUTH_ACTION_TOKEN_SIGNING_KEY`.

**Login returns 403 `email_not_verified`**
The default gate refuses login until email is verified. Either ask
the user to click the verify link, hit `POST /api/v1/auth/resend-verification`,
or disable the gate via AdminUI → Settings →
"Require email verification".

**OAuth client gets `invalid_grant` on code exchange**
Most common causes: PKCE `code_verifier` mismatch, expired code
(60s default), reused code (one-shot), or `redirect_uri` doesn't
match exactly.

**Verify-email link 302s to error page**
The action-token JWT failed validation: expired (24h), tampered,
or signed with a prior key. Tell the user to request a new link.

**Behind reverse proxy, audit logs show proxy IP**
You haven't set `server.trusted_proxies`. Add the proxy's IP/CIDR
and restart; `c.ClientIP()` will then deduce the real client from
`X-Forwarded-For`.

**Background worker silent on email delivery**
Check `outbound_emails` directly. If rows are `pending` with `attempts=0`
the worker isn't running (check logs for "email outbox worker started").
If rows have `last_error`, the SMTP config is wrong.

---

For deeper architectural context, see the Serena memories in
`.serena/memories/` (project_overview, oauth_flows_detail, etc.).
