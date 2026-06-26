-- +goose Up
ALTER TABLE sessions ADD COLUMN cookie_token_hash VARCHAR(64);
ALTER TABLE sessions ADD COLUMN extended BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX idx_sessions_cookie_token_hash ON sessions (cookie_token_hash);

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_cookie_token_hash;
ALTER TABLE sessions DROP COLUMN IF EXISTS extended;
ALTER TABLE sessions DROP COLUMN IF EXISTS cookie_token_hash;
