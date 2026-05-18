-- +goose Up

ALTER TABLE users
    ADD COLUMN deleted_at           TIMESTAMPTZ,
    ADD COLUMN deletion_token       VARCHAR(255),
    ADD COLUMN deletion_purge_after TIMESTAMPTZ;

CREATE INDEX idx_users_deletion_purge_after ON users (deletion_purge_after) WHERE deletion_purge_after IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_users_deletion_purge_after;
ALTER TABLE users
    DROP COLUMN IF EXISTS deletion_purge_after,
    DROP COLUMN IF EXISTS deletion_token,
    DROP COLUMN IF EXISTS deleted_at;
