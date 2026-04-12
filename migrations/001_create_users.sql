-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                        UUID PRIMARY KEY,
    email                     VARCHAR(255) NOT NULL,
    email_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    email_verify_token        VARCHAR(255),
    email_verify_expires_at   TIMESTAMPTZ,
    password_hash             VARCHAR(255) NOT NULL,
    password_reset_token      VARCHAR(255),
    password_reset_expires_at TIMESTAMPTZ,
    display_name              VARCHAR(255),
    avatar_url                VARCHAR(512),
    phone                     VARCHAR(50),
    locked_until              TIMESTAMPTZ,
    failed_login_attempts     INT NOT NULL DEFAULT 0,
    active                    BOOLEAN NOT NULL DEFAULT TRUE,
    metadata                  JSONB DEFAULT '{}',
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_active ON users (active) WHERE active = TRUE;

-- +goose Down
DROP TABLE IF EXISTS users;
