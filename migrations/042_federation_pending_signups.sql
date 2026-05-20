-- +goose Up
-- Pending federation signups: stages the validated claims of an external
-- identity that did NOT match any existing local account. The actual User
-- and FederationLink rows are only created once the user has completed
-- onboarding (chosen a local password) via POST /api/v1/auth/federation/
-- complete-signup. If the user abandons the flow, the row expires and no
-- orphan account is left behind.
CREATE TABLE federation_pending_signups (
    token_hash       VARCHAR(64) PRIMARY KEY,
    provider_id      UUID NOT NULL REFERENCES federation_providers(id) ON DELETE CASCADE,
    external_id      VARCHAR(255) NOT NULL,
    email            VARCHAR(255) NOT NULL,
    email_verified   BOOLEAN NOT NULL DEFAULT FALSE,
    display_name     VARCHAR(255),
    avatar_url       VARCHAR(512),
    raw_claims       JSONB NOT NULL DEFAULT '{}',
    oauth_request_id UUID,
    return_to        VARCHAR(2048),
    invitation_token VARCHAR(255),
    ip_address       INET,
    user_agent       VARCHAR(512),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_federation_pending_signups_expires_at ON federation_pending_signups (expires_at);

-- +goose Down
DROP TABLE IF EXISTS federation_pending_signups;
