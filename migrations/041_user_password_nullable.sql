-- +goose Up
-- A federated user signs in for the first time without ever picking a
-- local password. To support that flow we relax the NOT NULL constraint
-- on users.password_hash and add a flag that forces the user through the
-- "complete account" onboarding step before any password-protected
-- operation is accepted.
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL,
    ADD COLUMN must_set_password BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS must_set_password,
    ALTER COLUMN password_hash SET NOT NULL;
