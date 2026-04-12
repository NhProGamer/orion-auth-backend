-- +goose Up
CREATE TABLE consents (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes     TEXT[] DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_consents_user_client_active ON consents (user_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_consents_user_id ON consents (user_id);

-- +goose Down
DROP TABLE IF EXISTS consents;
