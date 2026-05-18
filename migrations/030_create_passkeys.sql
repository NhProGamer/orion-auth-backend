-- +goose Up

CREATE TABLE passkeys (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id      BYTEA NOT NULL,
    public_key         BYTEA NOT NULL,
    attestation_type   VARCHAR(50) NOT NULL DEFAULT '',
    aaguid             BYTEA,
    sign_count         BIGINT NOT NULL DEFAULT 0,
    transports         TEXT[] NOT NULL DEFAULT '{}',
    flags              INT NOT NULL DEFAULT 0,                                 -- raw ProtocolValue (uint8 stored as int)
    clone_warning      BOOLEAN NOT NULL DEFAULT FALSE,
    name               VARCHAR(100) NOT NULL DEFAULT 'Passkey',
    last_used_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_passkeys_credential_id ON passkeys (credential_id);
CREATE INDEX        idx_passkeys_user_id        ON passkeys (user_id);

CREATE TABLE passkey_challenges (
    id           UUID PRIMARY KEY,
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,                  -- nullable: usernameless login
    purpose      VARCHAR(20) NOT NULL,                                          -- registration | login | reauth
    session_data BYTEA NOT NULL,                                                -- gob-encoded webauthn.SessionData
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges (expires_at);
CREATE INDEX idx_passkey_challenges_user_id    ON passkey_challenges (user_id) WHERE user_id IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS passkey_challenges;
DROP TABLE IF EXISTS passkeys;
