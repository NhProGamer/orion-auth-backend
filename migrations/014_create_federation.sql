-- +goose Up
CREATE TABLE federation_providers (
    id                UUID PRIMARY KEY,
    name              VARCHAR(100) NOT NULL,
    display_name      VARCHAR(255),
    type              VARCHAR(20) NOT NULL DEFAULT 'oidc',
    client_id         VARCHAR(255) NOT NULL,
    client_secret     VARCHAR(255) NOT NULL,
    issuer_url        VARCHAR(512),
    authorization_url VARCHAR(512),
    token_url         VARCHAR(512),
    userinfo_url      VARCHAR(512),
    scopes            TEXT[] DEFAULT '{}',
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_federation_providers_name ON federation_providers (name);

CREATE TABLE federation_links (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    email       VARCHAR(255),
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_federation_links_provider_external ON federation_links (provider_id, external_id);
CREATE INDEX idx_federation_links_user_id ON federation_links (user_id);

-- +goose Down
DROP TABLE IF EXISTS federation_links;
DROP TABLE IF EXISTS federation_providers;
