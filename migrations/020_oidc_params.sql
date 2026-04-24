-- +goose Up

ALTER TABLE authorization_requests
    ADD COLUMN prompt         VARCHAR(50),
    ADD COLUMN max_age        INT,
    ADD COLUMN display        VARCHAR(20),
    ADD COLUMN ui_locales     VARCHAR(255),
    ADD COLUMN claims_locales VARCHAR(255),
    ADD COLUMN acr_values     VARCHAR(512),
    ADD COLUMN login_hint     VARCHAR(255),
    ADD COLUMN claims_param   JSONB,
    ADD COLUMN id_token_hint  TEXT,
    ADD COLUMN auth_time      TIMESTAMPTZ;

ALTER TABLE authorization_codes
    ADD COLUMN claims_param JSONB,
    ADD COLUMN auth_time    TIMESTAMPTZ;

ALTER TABLE oauth_clients
    ADD COLUMN post_logout_redirect_uris TEXT[] DEFAULT '{}';

-- +goose Down

ALTER TABLE authorization_requests
    DROP COLUMN IF EXISTS prompt,
    DROP COLUMN IF EXISTS max_age,
    DROP COLUMN IF EXISTS display,
    DROP COLUMN IF EXISTS ui_locales,
    DROP COLUMN IF EXISTS claims_locales,
    DROP COLUMN IF EXISTS acr_values,
    DROP COLUMN IF EXISTS login_hint,
    DROP COLUMN IF EXISTS claims_param,
    DROP COLUMN IF EXISTS id_token_hint,
    DROP COLUMN IF EXISTS auth_time;

ALTER TABLE authorization_codes
    DROP COLUMN IF EXISTS claims_param,
    DROP COLUMN IF EXISTS auth_time;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS post_logout_redirect_uris;
