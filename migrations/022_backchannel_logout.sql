-- +goose Up

ALTER TABLE oauth_clients
    ADD COLUMN backchannel_logout_uri VARCHAR(512),
    ADD COLUMN backchannel_logout_session_required BOOLEAN DEFAULT FALSE;

-- +goose Down

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS backchannel_logout_uri,
    DROP COLUMN IF EXISTS backchannel_logout_session_required;
