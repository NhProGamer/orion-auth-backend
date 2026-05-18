-- +goose Up

CREATE TABLE reauth_tokens (
    id          VARCHAR(64) PRIMARY KEY,                                   -- SHA-256 hash of raw token
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    method      VARCHAR(20) NOT NULL,                                       -- password | totp | passkey | backup_code
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    used_at     TIMESTAMPTZ,
    consumed_by VARCHAR(100),                                                -- audit: which action consumed this token
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reauth_tokens_user_id    ON reauth_tokens (user_id);
CREATE INDEX idx_reauth_tokens_session_id ON reauth_tokens (session_id);
CREATE INDEX idx_reauth_tokens_expires_at ON reauth_tokens (expires_at) WHERE used = FALSE;

-- +goose Down
DROP TABLE IF EXISTS reauth_tokens;
