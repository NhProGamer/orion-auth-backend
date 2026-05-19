-- +goose Up
-- OIDC Core §10.2 + §5.3.2: per-client JWE encryption parameters for
-- ID tokens and UserInfo responses. NULL means the client does not opt in
-- and the existing JWS (or JSON) response is returned unchanged.
ALTER TABLE oauth_clients
    ADD COLUMN id_token_encrypted_response_alg   VARCHAR(50),
    ADD COLUMN id_token_encrypted_response_enc   VARCHAR(50),
    ADD COLUMN userinfo_encrypted_response_alg   VARCHAR(50),
    ADD COLUMN userinfo_encrypted_response_enc   VARCHAR(50);

-- +goose Down
ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS id_token_encrypted_response_alg,
    DROP COLUMN IF EXISTS id_token_encrypted_response_enc,
    DROP COLUMN IF EXISTS userinfo_encrypted_response_alg,
    DROP COLUMN IF EXISTS userinfo_encrypted_response_enc;
