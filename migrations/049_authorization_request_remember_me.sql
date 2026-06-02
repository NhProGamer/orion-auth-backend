-- +goose Up
ALTER TABLE authorization_requests ADD COLUMN remember_me BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE authorization_requests DROP COLUMN IF EXISTS remember_me;
