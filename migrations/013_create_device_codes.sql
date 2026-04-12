-- +goose Up
CREATE TABLE device_codes (
    device_code_hash VARCHAR(64) PRIMARY KEY,
    user_code        VARCHAR(9) NOT NULL,
    client_id        UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes           TEXT[] DEFAULT '{}',
    user_id          UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id       UUID REFERENCES sessions(id) ON DELETE CASCADE,
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    interval_secs    INT NOT NULL DEFAULT 5,
    expires_at       TIMESTAMPTZ NOT NULL,
    last_polled_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_device_codes_user_code ON device_codes (user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes (expires_at);

-- +goose Down
DROP TABLE IF EXISTS device_codes;
