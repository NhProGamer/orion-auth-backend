# Migrating an existing IAM into OrionAuth

OrionAuth can bulk-import users from another identity provider. The importer is
built around an IAM-agnostic core: a **source** reads the foreign system and
produces canonical user records, and a shared **engine** writes them into
OrionAuth. **Logto** is the first supported source.

Passwords are **not** reset on migration where they can be preserved: OrionAuth
verifies the foreign hash on the user's next login and transparently re-hashes
it to its native `argon2id` scheme (see [Password handling](#password-handling)).

## Quick start (Logto)

The importer is a subcommand of the server binary and connects to **two**
databases: the OrionAuth target DB (via the usual server config/env) and the
Logto source DB (via `--source-dsn`, read-only).

```bash
orion-auth import logto \
  --source-dsn "postgres://user:pass@logto-db:5432/logto?sslmode=disable" \
  --tenant default \
  --mapping ./examples/logto-mapping.json \
  --dry-run
```

Run with `--dry-run` first: it resolves everything and prints the full report
(what would be created, forced to reset, or skipped) **without writing**. Drop
the flag to apply.

### Flags

| Flag           | Required | Default   | Meaning                                             |
| -------------- | -------- | --------- | --------------------------------------------------- |
| `--source-dsn` | yes      | —         | Logto Postgres connection string (read-only).       |
| `--mapping`    | yes      | —         | Path to the mapping JSON (see below).               |
| `--tenant`     | no       | `default` | Logto tenant id to import (OSS Logto uses `default`). |
| `--dry-run`    | no       | `false`   | Report without writing.                             |

## Mapping file

The mapping bridges Logto names to OrionAuth entities and sets edge-case policy.
See [`examples/logto-mapping.json`](examples/logto-mapping.json).

```json
{
  "providers": { "discord": "discord" },
  "roles": { "admin": "admin", "user": "user" },
  "assume_verified_email": true,
  "default_role": "user",
  "on_unsupported_password": "reset"
}
```

- **`providers`** — maps a Logto social identity *target* (the key in Logto's
  `users.identities`, e.g. `discord`) to an existing OrionAuth
  `federation_providers.name`. Identities whose target is not listed are skipped
  and counted in the report. The referenced OrionAuth provider must already
  exist (create it first); a typo fails the run immediately.
- **`roles`** — maps a Logto role name to an existing OrionAuth `roles.name`.
  Unmapped roles are skipped and reported.
- **`assume_verified_email`** — mark every imported user with an email as
  verified. Logto only keeps verified primary emails, so this is normally `true`
  and avoids locking users out behind the email-verification gate.
- **`default_role`** — OrionAuth role assigned to a user who ends up with no
  mapped role. Empty means "assign nothing".
- **`on_unsupported_password`** — `reset` (default), `skip`, or `fail`. See below.

## Password handling

Logto stores `password_encryption_method` alongside each hash. The importer maps
them as follows:

| Logto method        | Handling                                                        |
| ------------------- | --------------------------------------------------------------- |
| `Argon2i`           | Imported verbatim; verified on login, then re-hashed to `argon2id`. |
| `Bcrypt`            | Imported verbatim; verified on login, then re-hashed.           |
| `SHA256/SHA1/MD5`   | Wrapped in a self-describing envelope; verified, then re-hashed. |
| `Legacy` / unknown  | Cannot be verified → **unsupported** (see policy below).        |
| none (social-only)  | Imported password-less; user onboards via reset / federation.   |

The re-hash to `argon2id` happens automatically on the **first successful
login** (and on any password change) — the migration is invisible to users who
kept a supported hash. No schema migration is needed: the scheme is encoded in
the stored hash string itself.

**`on_unsupported_password`** controls users whose hash cannot be verified:

- `reset` — import them with `must_set_password = true` and no password; they go
  through the normal password-reset onboarding.
- `skip` — do not import those users at all.
- `fail` — abort the whole run (use to audit before committing).

## What is imported

- **Users** — email (required; Logto accounts without a `primary_email` are
  skipped and reported), display name, avatar, phone, `active`
  (from `is_suspended`), OIDC profile claims and `custom_data` (stored in the
  metadata JSONB, with an `_import` provenance block recording the source and
  the original Logto id).
- **Passwords** — as above.
- **Social identities** — Logto `users.identities` → `federation_links`, via the
  provider mapping.
- **Roles** — Logto `users_roles` → `user_roles`, via the role mapping.

Out of scope for now: OAuth applications/clients, enterprise SSO identities
(`user_sso_identities`), and MFA factors.

## Idempotency

The importer keys on email and **never overwrites** an account that already
exists in OrionAuth — re-running is safe and simply reports those users as
skipped. To re-import a changed user, delete the local account first.

## Adding another IAM

Implement `importer.Source` (see `importer/canonical.go`) for the new system and
wire a subcommand in `cmd_import.go`. The engine, mapping, password handling and
reporting are reused unchanged.
