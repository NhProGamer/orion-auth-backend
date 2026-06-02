-- +goose Up
ALTER TABLE mfa_methods ADD COLUMN last_used_totp_step BIGINT DEFAULT 0 NOT NULL;

-- +goose Down
ALTER TABLE mfa_methods DROP COLUMN IF EXISTS last_used_totp_step;
