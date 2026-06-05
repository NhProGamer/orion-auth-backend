# Migrations

Schema + seed migrations consumed by `goose` at startup
(`database.Migrate(db)` in main.go). Embedded via `//go:embed *.sql`
in `migrations/embed.go`; no need to ship the directory alongside the
binary.

## Naming

Sequential 3-digit prefix: `NNN_short_description.sql`. Pick the next
free number — no gaps allowed. `goose` records applied versions in
`goose_db_version`.

## Pattern: seeding a new RBAC permission

The first dozen migrations allocated permission UUIDs by hand
(`00000000-0000-0000-0000-0000000000xx`). The slot was tracked by
`grep -rho` against existing migrations, which scales poorly and is
error-prone. **For any new permission, prefer the name-keyed pattern
below** (the `name` column is uniquely indexed so it's a safe
deduplication key):

```sql
-- +goose Up
INSERT INTO permissions (id, name, description) VALUES
    (gen_random_uuid(), 'email_templates:read',  'Read transactional email template overrides'),
    (gen_random_uuid(), 'email_templates:write', 'Create/update/delete email template overrides')
ON CONFLICT (name) DO NOTHING;

-- Grant to admin role by name lookup, no UUID literals
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles       WHERE name = 'admin'),
    (SELECT id FROM permissions WHERE name = 'email_templates:read')
ON CONFLICT DO NOTHING;
-- repeat per permission

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE name IN ('email_templates:read','email_templates:write')
);
DELETE FROM permissions WHERE name IN ('email_templates:read','email_templates:write');
```

This is idempotent (safe to re-run after a crashed migration), avoids
hardcoded UUIDs, and means future operators don't have to keep a
mental ledger of free slots.

Existing hardcoded-UUID migrations stay as-is — rewriting them buys
nothing and risks breaking the seeded DB rows downstream services
already reference.

## Seed UUIDs that ARE referenced in Go code

Three IDs are pinned in the Go side too — see `model/seed_ids.go`.
Keep them in sync if you ever rename a row in a migration:

| Constant (`model.`)         | Seeded by migration                        | UUID                                       |
| --------------------------- | ------------------------------------------ | ------------------------------------------ |
| `AdminRoleID`               | `011_create_roles_permissions.sql`         | `00000000-0000-0000-0000-000000000001`     |
| `AdminClientID`             | (seeded at startup by main.go)             | `00000000-0000-0000-0000-000000000002`     |
| `DefaultUserRoleID`         | `011_create_roles_permissions.sql`         | `00000000-0000-0000-0000-000000000004`     |
