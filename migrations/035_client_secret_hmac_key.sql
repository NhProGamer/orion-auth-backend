-- +goose Up
-- Adds an HMAC key per client used to verify client_secret_jwt assertions
-- (RFC 7523). Stored ENCRYPTED with the server-side
-- auth.hmac_secret_encryption_key (AES-GCM). NULL means the client does not
-- support client_secret_jwt.
ALTER TABLE oauth_clients ADD COLUMN secret_hmac_key BYTEA;

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS secret_hmac_key;
