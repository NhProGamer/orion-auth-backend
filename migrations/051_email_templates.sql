-- +goose Up
CREATE TABLE email_templates (
    name        VARCHAR(64) PRIMARY KEY,
    subject     TEXT NOT NULL,
    body_html   TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Nullable so existing rows (or system-driven Upserts in future jobs)
    -- can be recorded without a user actor. ON DELETE SET NULL keeps the
    -- override alive after the editor account is purged.
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

-- +goose Down
DROP TABLE IF EXISTS email_templates;
