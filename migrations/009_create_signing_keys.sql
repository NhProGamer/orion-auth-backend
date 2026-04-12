-- +goose Up
CREATE TABLE signing_keys (
    id              UUID PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    algorithm       VARCHAR(10) NOT NULL DEFAULT 'RS256',
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signing_keys_active ON signing_keys (active) WHERE active = TRUE;

-- +goose Down
DROP TABLE IF EXISTS signing_keys;
