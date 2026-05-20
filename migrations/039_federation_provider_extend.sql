-- +goose Up
-- Federation providers: encrypt client_secret at rest and add provisioning
-- knobs (attribute mapper, sync-on-login, link confirmation, explicit JWKS).
ALTER TABLE federation_providers
    ADD COLUMN client_secret_encrypted BYTEA,
    ADD COLUMN attribute_mapper        JSONB   NOT NULL DEFAULT '{}',
    ADD COLUMN sync_on_login           BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN allow_link_confirmation BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN jwks_uri                VARCHAR(512);

-- The legacy plaintext column becomes optional. New writes go through
-- client_secret_encrypted; existing rows (if any) keep their plaintext until
-- an UpdateProvider call re-seals them. The feature was non-functional in
-- prior releases so no production federation_providers rows exist.
ALTER TABLE federation_providers
    ALTER COLUMN client_secret DROP NOT NULL;

-- +goose Down
ALTER TABLE federation_providers
    ALTER COLUMN client_secret SET NOT NULL,
    DROP COLUMN IF EXISTS jwks_uri,
    DROP COLUMN IF EXISTS allow_link_confirmation,
    DROP COLUMN IF EXISTS sync_on_login,
    DROP COLUMN IF EXISTS attribute_mapper,
    DROP COLUMN IF EXISTS client_secret_encrypted;
