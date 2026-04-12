-- +goose Up
CREATE TABLE refresh_tokens (
    id         VARCHAR(64) PRIMARY KEY,
    client_id  UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    scopes     TEXT[] DEFAULT '{}',
    family_id  UUID NOT NULL,
    parent_id  VARCHAR(64),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    rotated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens (client_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Add FK from access_tokens to refresh_tokens now that the table exists
ALTER TABLE access_tokens
    ADD CONSTRAINT fk_access_tokens_refresh_token
    FOREIGN KEY (refresh_token_id) REFERENCES refresh_tokens(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE access_tokens DROP CONSTRAINT IF EXISTS fk_access_tokens_refresh_token;
DROP TABLE IF EXISTS refresh_tokens;
