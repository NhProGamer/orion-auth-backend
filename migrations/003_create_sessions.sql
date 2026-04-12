-- +goose Up
CREATE TABLE sessions (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address       INET,
    user_agent       VARCHAR(512),
    device_info      VARCHAR(255),
    last_active_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked          BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at       TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX idx_sessions_active ON sessions (user_id, revoked) WHERE revoked = FALSE;

-- +goose Down
DROP TABLE IF EXISTS sessions;
