-- +goose Up
ALTER TABLE oauth_clients ADD COLUMN subject_type VARCHAR(20) DEFAULT 'public';
ALTER TABLE oauth_clients ADD COLUMN sector_identifier_uri VARCHAR(512);
ALTER TABLE oauth_clients ADD COLUMN userinfo_signed_response_alg VARCHAR(10);
ALTER TABLE oauth_clients ADD COLUMN registration_access_token_hash VARCHAR(64);

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS subject_type;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS sector_identifier_uri;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS userinfo_signed_response_alg;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS registration_access_token_hash;
