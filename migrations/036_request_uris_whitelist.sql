-- +goose Up
-- RFC 7591 §2: optional whitelist of request_uri values pre-registered by
-- the client. Required when /authorize accepts a request_uri pointing to a
-- JWT Request Object hosted at an arbitrary HTTP URL (RFC 9101 §5.2.2).
ALTER TABLE oauth_clients ADD COLUMN request_uris TEXT[] DEFAULT '{}';

-- +goose Down
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS request_uris;
