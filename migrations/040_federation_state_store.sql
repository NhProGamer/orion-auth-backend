-- +goose Up
-- Ephemeral one-time state store for federation auth requests. Each row
-- carries the CSRF state, PKCE verifier, and OIDC nonce that the backend
-- generated before redirecting the user to an external provider, plus the
-- continuation context (return_to, oauth_request_id, invitation_token) so
-- the callback can resume where the user left off.
CREATE TABLE federation_auth_requests (
    state             VARCHAR(128) PRIMARY KEY,
    provider_id       UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,
    code_verifier     VARCHAR(128) NOT NULL,
    nonce             VARCHAR(128) NOT NULL,
    return_to         VARCHAR(2048),
    oauth_request_id  UUID,
    invitation_token  VARCHAR(255),
    ip_address        INET,
    user_agent        VARCHAR(512),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_federation_auth_requests_expires_at ON federation_auth_requests (expires_at);

-- Pending link confirmations: when an external identity matches an existing
-- local account by email, the backend stages a one-shot token; the user
-- must then prove control of the existing account by supplying its local
-- password to finalize the link. Token stored as SHA-256 hash.
CREATE TABLE federation_pending_links (
    token_hash       VARCHAR(64) PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id      UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,
    external_id      VARCHAR(255) NOT NULL,
    email            VARCHAR(255),
    raw_claims       JSONB NOT NULL DEFAULT '{}',
    oauth_request_id UUID,
    return_to        VARCHAR(2048),
    ip_address       INET,
    user_agent       VARCHAR(512),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_federation_pending_links_expires_at ON federation_pending_links (expires_at);

-- +goose Down
DROP TABLE IF EXISTS federation_pending_links;
DROP TABLE IF EXISTS federation_auth_requests;
