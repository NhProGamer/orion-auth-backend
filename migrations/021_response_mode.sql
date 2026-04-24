-- +goose Up

ALTER TABLE authorization_requests ADD COLUMN response_mode VARCHAR(20);

-- +goose Down

ALTER TABLE authorization_requests DROP COLUMN IF EXISTS response_mode;
