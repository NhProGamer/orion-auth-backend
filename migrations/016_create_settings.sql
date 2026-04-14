-- +goose Up
CREATE TABLE settings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES ('registration_enabled', 'true');

-- +goose Down
DROP TABLE IF EXISTS settings;
