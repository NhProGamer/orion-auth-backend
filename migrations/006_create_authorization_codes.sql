-- +goose Up
CREATE TABLE authorization_codes (
    code_hash             VARCHAR(64) PRIMARY KEY,
    client_id             UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          VARCHAR(512) NOT NULL,
    scopes                TEXT[] DEFAULT '{}',
    code_challenge        VARCHAR(128),
    code_challenge_method VARCHAR(10),
    nonce                 VARCHAR(128),
    session_id            UUID REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at            TIMESTAMPTZ NOT NULL,
    used                  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_client_id ON authorization_codes (client_id);
CREATE INDEX idx_auth_codes_expires_at ON authorization_codes (expires_at);

-- +goose Down
DROP TABLE IF EXISTS authorization_codes;
