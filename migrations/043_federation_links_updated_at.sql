-- +goose Up
-- model.FederationLink embeds BaseModel which carries an UpdatedAt
-- field; GORM emits it on every INSERT/UPDATE. The original migration
-- 014 only created created_at, so every link insert blew up with
-- SQLSTATE 42703 and we silently failed to bind social identities
-- after both /complete-signup and /confirm-link.
ALTER TABLE federation_links
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- +goose Down
ALTER TABLE federation_links
    DROP COLUMN IF EXISTS updated_at;
