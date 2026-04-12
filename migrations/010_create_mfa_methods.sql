-- +goose Up
CREATE TABLE mfa_methods (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type         VARCHAR(20) NOT NULL DEFAULT 'totp',
    secret       VARCHAR(255) NOT NULL,
    verified     BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes TEXT[] DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_methods_user_id ON mfa_methods (user_id);
CREATE UNIQUE INDEX idx_mfa_methods_user_type ON mfa_methods (user_id, type) WHERE verified = TRUE;

-- +goose Down
DROP TABLE IF EXISTS mfa_methods;
