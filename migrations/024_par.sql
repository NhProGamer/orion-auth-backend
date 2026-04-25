-- +goose Up
CREATE TABLE pushed_authorization_requests (
    request_uri VARCHAR(128) PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES oauth_clients(id),
    params JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_par_expires ON pushed_authorization_requests(expires_at);

-- +goose Down
DROP TABLE IF EXISTS pushed_authorization_requests;
