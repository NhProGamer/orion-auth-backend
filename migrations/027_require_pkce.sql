-- +goose Up
ALTER TABLE oauth_clients ADD COLUMN require_pkce BOOLEAN NOT NULL DEFAULT TRUE;

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS require_pkce;
