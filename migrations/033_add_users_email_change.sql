-- +goose Up

ALTER TABLE users
    ADD COLUMN email_change_new        VARCHAR(255),
    ADD COLUMN email_change_token      VARCHAR(255),
    ADD COLUMN email_change_expires_at TIMESTAMPTZ;

CREATE INDEX idx_users_email_change_token ON users (email_change_token) WHERE email_change_token IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_users_email_change_token;
ALTER TABLE users
    DROP COLUMN IF EXISTS email_change_expires_at,
    DROP COLUMN IF EXISTS email_change_token,
    DROP COLUMN IF EXISTS email_change_new;
