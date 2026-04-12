-- +goose Up
CREATE TABLE audit_logs (
    id         UUID PRIMARY KEY,
    user_id    UUID,
    client_id  UUID,
    action     VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent VARCHAR(512),
    metadata   JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON audit_logs (action);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
