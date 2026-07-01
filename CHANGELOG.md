# Changelog

All notable changes to this project will be documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com), and this project
adheres to [Semantic Versioning](https://semver.org) — see
[VERSIONING.md](VERSIONING.md) for the local policy.

## [Unreleased]

—

## [v0.25.1] — 2026-07-01

### Fixed

- **Bootstrap admin email is now verified.** The seeded admin
  (`admin@orionauth.local`) is created through the normal `Register` path,
  which leaves `email_verified` false — so with email verification enabled the
  operator was locked out by the login gate. `seedAdminUser` now marks the
  bootstrap admin verified right after the role assignment.
- **Existing admins verified** (migration `054`). Any user holding the admin
  role is marked `email_verified = TRUE`, unlocking operators provisioned
  before this fix. The down migration is intentionally a no-op.

## [v0.25.0] — 2026-06-26

### Added

- **Silent SSO via an IdP session cookie.** `/authorize` now issues an
  HttpOnly, SameSite=Lax `orionauth_sid` cookie when a session is created and
  reads it back on the next authorization request: an already-authenticated
  user is silently re-authorized across services without re-entering
  credentials. `prompt=login` still forces re-auth, `max_age` is honoured, and
  the consent rules are unchanged (first-party auto-consents; third-party still
  shows the consent screen, now without a login step). Cleared on
  `/end_session`.
- **`sessions.cookie_token_hash` / `sessions.extended`** (migration `053`). The
  cookie carries an opaque 32-byte secret; only its SHA-256 is stored, so the
  cookie stays revocable and unrecoverable. `extended` records the remember_me
  choice so a silent re-auth inherits the persistent-cookie behaviour.
- **`session.Service.FindByCookieToken`** + `Repository.FindActiveByCookieHash`
  — resolve a raw cookie to its live (non-revoked, non-expired) session.

### Changed

- `remember_me` now drives cookie persistence: a remembered session gets a
  persistent `orionauth_sid` cookie sized to the session lifetime; otherwise a
  browser-session cookie that dies when the browser closes. Session TTL
  resolution (`SessionExtendedTTL`) is unchanged.

## [v0.24.0] — 2026-06-06

First release under the new SemVer-by-content tagging policy. All historical
tags have been remapped from the legacy `-hf*` / `-pre*` / `-b*` / `-pr*`
suffix soup onto stable `vX.Y.Z` names (see the
[remap script](scripts/remap-tags.sh) for the 63-row mapping table). No SHA
was rewritten — only the labels.

### Added

- **`pkg/clock`** — minimal `Clock` interface with `Real()` (wall clock) and
  `Fake` (test-controlled). Injected through `Options.Clock` into `user`,
  `oauth`, `oidc`, `session`. Time-dependent flows (token expiry, lockout
  windows, signing-key grace period) can now be tested deterministically.
- **`email.TxSender` interface** — adds `Send*EmailInTx(tx, …)` variants on
  every transactional mail type. Only `OutboxSender` satisfies it; `SMTPSender`
  stays a plain `Sender` since it has no DB to participate in a Tx.
- **`metrics.outbound_email_queue_depth`** (Gauge) and
  **`metrics.outbound_email_delivered_total`** (CounterVec by result).
  Operators alert on growing depth; `/ready` stays binary as discussed.
- **`OutboxWorker.Stop(ctx)`** — drains the in-flight tick before returning so
  a SIGTERM during an SMTP send no longer kills the goroutine mid-Tx (which
  would risk double-delivery at the next boot).
- **`VERSIONING.md`** + this changelog.
- **CI tag-format gate** — `.forgejo/workflows/test.yml` rejects pushes of
  tags not matching `^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$`.

### Changed (refactor only — no public API break)

- **Atomicity, 9 flows** — `user.Register`, `RegisterAdmin`,
  `CreateFromFederation`, `SendVerificationEmail`, `invitation.Create`,
  `account.RequestEmailChange`, `ConfirmEmailChange`,
  `user.ForgotPassword` + `AdminTriggerPasswordReset`, `account.RequestDeletion`
  now run inside a single `db.Transaction`. Domain writes + role assignments +
  session revocation + email enqueue commit-or-rollback together. The legacy
  `slog.Warn` swallows of role-assignment and email failures are gone.
- **Middleware decoupling** — `ClientAuth`, `BearerAuth`, `RequireClientScope`
  no longer take `*gorm.DB`. They consume narrow interfaces (`ClientFinder`,
  `TokenLookup`, `SessionValidator`) implemented by the service layer — the
  active-client / active-token / active-session rule has one source of truth
  and the middlewares are unit-testable without a database.
- `user.RoleAssigner` gains `AssignRoleInTx(tx, userID, roleID)`; `rbac.Service`
  implements it.
- `oauth.RepositoryInterface.LookupActiveAccessToken(raw)` replaces the raw
  SELECT that used to live in `middleware/auth.go`.

### Fixed

- Verification email can no longer be persisted on the user row without an
  actual outbox enqueue happening — both share a Tx.
- Email change confirm + session revoke are now atomic. Previously the new
  email could go live while the old sessions still authorised the account.
- Account deletion (deactivation + cancel email + session revoke) is atomic.
  The previous failure mode could deactivate the account without ever sending
  the cancellation link.

### Removed

- 63 legacy tags (`0.1.0-hf*`, `0.2.0-hf*`, `0.2.0-hf*`, `0.2.1-hf*`,
  `0.2.2-hf*`, `0.2.3-pre1`, `0.2.4-pre*`, `0.2.5-pre*`, `0.2.6-pre*`,
  `0.2.7-pre*`, `0.2.7-pr5` typo, `0.2.8-b*`). Each remapped to a stable
  `vX.Y.Z` by content type. See `scripts/remap-tags.sh` and the audit at
  `/tmp/tags-before.txt` (snapshot taken before the remap).

## Legacy history (pre-remap)

The 63 historical tags were renamed to stable `vX.Y.Z` releases based on the
commit-content classification described in `VERSIONING.md`. Each new tag
points at the same SHA as the old one — no commit was lost or rewritten. A
high-level summary of the lines:

- **`v0.1.x` — v0.1.0..v0.1.1** — initial release + first hotfix.
- **`v0.2.0..v0.4.0`** — admin user CRUD endpoints (3 feats).
- **`v0.5.x` — v0.5.0..v0.5.4** — public settings endpoint + email rendering
  refactor + dark theme.
- **`v0.6.x` — v0.6.0..v0.6.4** — audit logging extensions + various fixes.
- **`v0.7.0`** — groups claim emission in ID token / UserInfo.
- **`v0.8.0..v0.9.x`** — policy evaluation integrated into OAuth login + token
  issuance; resource permissions linked to roles.
- **`v0.10.0..v0.16.x`** — large feature wave: federation providers public,
  PKCE per-client, brand-token email templates, paginated admin envelope,
  richer policy inputs, requesting-client policy hook + many fixes.
- **`v0.17.0..v0.18.0`** — federation /complete-account flow + admin
  settings whitelist.
- **`v0.19.0..v0.21.x`** — regform public schema; admin/ post-logout redirect;
  password public endpoint; federation provider_name in linked accounts.
- **`v0.22.0..v0.23.x`** — admin-overridable session TTLs + email-verification
  toggle; final action-token-key fix + email-template CRUD coverage.

[Unreleased]: https://git.nhsoul.fr/nhpro/orion-auth-backend/compare/v0.25.1...HEAD
[v0.25.1]: https://git.nhsoul.fr/nhpro/orion-auth-backend/releases/tag/v0.25.1
[v0.25.0]: https://git.nhsoul.fr/nhpro/orion-auth-backend/releases/tag/v0.25.0
[v0.24.0]: https://git.nhsoul.fr/nhpro/orion-auth-backend/releases/tag/v0.24.0
