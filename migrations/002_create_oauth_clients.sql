-- +goose Up
CREATE TABLE oauth_clients (
    id                UUID PRIMARY KEY,
    secret_hash       VARCHAR(255),
    name              VARCHAR(255) NOT NULL,
    description       TEXT,
    redirect_uris     TEXT[] DEFAULT '{}',
    grant_types       TEXT[] DEFAULT '{}',
    response_types    TEXT[] DEFAULT '{}',
    scopes            TEXT[] DEFAULT '{}',
    token_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
    is_public         BOOLEAN NOT NULL DEFAULT FALSE,
    is_first_party    BOOLEAN NOT NULL DEFAULT FALSE,
    jwks_uri          VARCHAR(512),
    access_token_ttl  INT NOT NULL DEFAULT 3600,
    refresh_token_ttl INT NOT NULL DEFAULT 86400,
    id_token_ttl      INT NOT NULL DEFAULT 3600,
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_active ON oauth_clients (active) WHERE active = TRUE;

-- +goose Down
DROP TABLE IF EXISTS oauth_clients;
