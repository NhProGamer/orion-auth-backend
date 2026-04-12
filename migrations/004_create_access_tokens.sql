-- +goose Up
CREATE TABLE access_tokens (
    id               VARCHAR(64) PRIMARY KEY,
    client_id        UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id          UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id       UUID REFERENCES sessions(id) ON DELETE CASCADE,
    refresh_token_id VARCHAR(64),
    scopes           TEXT[] DEFAULT '{}',
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_tokens_client_id ON access_tokens (client_id);
CREATE INDEX idx_access_tokens_user_id ON access_tokens (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_access_tokens_session_id ON access_tokens (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_access_tokens_refresh_token_id ON access_tokens (refresh_token_id) WHERE refresh_token_id IS NOT NULL;
CREATE INDEX idx_access_tokens_expires_at ON access_tokens (expires_at);

-- +goose Down
DROP TABLE IF EXISTS access_tokens;
