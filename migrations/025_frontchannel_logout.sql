-- +goose Up
ALTER TABLE oauth_clients ADD COLUMN frontchannel_logout_uri VARCHAR(512);
ALTER TABLE oauth_clients ADD COLUMN frontchannel_logout_session_required BOOLEAN DEFAULT FALSE;

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS frontchannel_logout_uri;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS frontchannel_logout_session_required;
