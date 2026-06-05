-- +goose Up
CREATE TABLE outbound_emails (
    id            UUID PRIMARY KEY,
    recipient     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    body_html     TEXT NOT NULL,
    status        VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    max_attempts  INTEGER NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at       TIMESTAMPTZ
);

-- Partial index: the worker polls `pending` rows that are due. Filtering
-- the index by status keeps it tiny once `sent` rows accumulate (we keep
-- them for audit/forensics, see retention policy in the runbook).
CREATE INDEX idx_outbound_emails_due
    ON outbound_emails (next_retry_at)
    WHERE status = 'pending';

-- +goose Down
DROP INDEX IF EXISTS idx_outbound_emails_due;
DROP TABLE IF EXISTS outbound_emails;
