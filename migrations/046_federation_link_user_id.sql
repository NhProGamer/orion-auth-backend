-- +goose Up
-- Authenticated link flow: when a logged-in user explicitly initiates a
-- federation link from their account UI, the backend stamps the auth
-- request with the bound user_id. The callback short-circuits on that
-- column: instead of provisioning or logging in, it creates the
-- federation_link for that user and returns to the AuthUI.
ALTER TABLE federation_auth_requests
    ADD COLUMN link_user_id UUID REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_federation_auth_requests_link_user_id
    ON federation_auth_requests (link_user_id)
    WHERE link_user_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_federation_auth_requests_link_user_id;
ALTER TABLE federation_auth_requests DROP COLUMN IF EXISTS link_user_id;
