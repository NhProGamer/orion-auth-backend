-- +goose Up
ALTER TABLE oauth_clients ADD COLUMN registration_access_token_expires_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS registration_access_token_expires_at;
