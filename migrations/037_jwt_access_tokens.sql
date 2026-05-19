-- +goose Up
-- Token format discriminator for API resources. 'opaque' keeps the current
-- behaviour (random 32B token, SHA-256 hashed in DB). 'jwt' emits a signed
-- JWT access token per RFC 9068 so resource servers can validate offline
-- against /.well-known/jwks.json.
ALTER TABLE api_resources ADD COLUMN token_format VARCHAR(10) DEFAULT 'opaque' NOT NULL;

-- JTI denylist for revoked JWT access tokens. An entry lives until the
-- token's natural expiry; a daily cleanup job (or any maintenance task)
-- can DELETE WHERE expires_at < NOW().
CREATE TABLE revoked_jtis (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_revoked_jtis_expires_at ON revoked_jtis(expires_at);

-- Optional JTI on access_tokens. NULL for opaque tokens (the row keeps its
-- primary key = sha256(raw)). Populated for JWT tokens so /revoke can find
-- and denylist them without re-parsing the JWT.
ALTER TABLE access_tokens ADD COLUMN jti VARCHAR(255);
CREATE INDEX idx_access_tokens_jti ON access_tokens(jti);

-- +goose Down
ALTER TABLE access_tokens DROP COLUMN IF EXISTS jti;
DROP TABLE IF EXISTS revoked_jtis;
ALTER TABLE api_resources DROP COLUMN IF EXISTS token_format;
