-- +goose Up
ALTER TABLE authorization_requests ADD COLUMN auth_methods TEXT[] DEFAULT '{}';
ALTER TABLE authorization_codes ADD COLUMN auth_methods TEXT[] DEFAULT '{}';

-- +goose Down
ALTER TABLE authorization_requests DROP COLUMN IF EXISTS auth_methods;
ALTER TABLE authorization_codes DROP COLUMN IF EXISTS auth_methods;
