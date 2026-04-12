-- +goose Up
CREATE TABLE authorization_requests (
    id                    UUID PRIMARY KEY,
    client_id             UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri          VARCHAR(512) NOT NULL,
    response_type         VARCHAR(50) NOT NULL,
    scopes                TEXT[] DEFAULT '{}',
    state                 VARCHAR(255),
    nonce                 VARCHAR(128),
    code_challenge        VARCHAR(128),
    code_challenge_method VARCHAR(10),
    user_id               UUID REFERENCES users(id) ON DELETE CASCADE,
    authenticated         BOOLEAN NOT NULL DEFAULT FALSE,
    consent_given         BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_requests_expires_at ON authorization_requests (expires_at);

-- +goose Down
DROP TABLE IF EXISTS authorization_requests;
