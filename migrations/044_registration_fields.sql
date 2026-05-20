-- +goose Up
-- Operator-configurable registration form. Each row describes one field
-- the AuthUI must render on /register or /complete-account; the order
-- and which contexts the field applies to are admin-managed.
CREATE TABLE registration_fields (
    id              UUID PRIMARY KEY,
    field_key       VARCHAR(64)  NOT NULL,
    label           VARCHAR(255) NOT NULL,
    description     VARCHAR(512),
    placeholder     VARCHAR(255),
    kind            VARCHAR(16)  NOT NULL,                              -- "standard" | "custom"
    standard_target VARCHAR(64),                                        -- whitelist enforced server-side
    type            VARCHAR(16)  NOT NULL,                              -- text|textarea|email|url|tel|number|date|select|multiselect|checkbox|radio
    required        BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    display_order   INTEGER      NOT NULL DEFAULT 0,
    options         JSONB        NOT NULL DEFAULT '[]'::jsonb,           -- [{value, label}, ...] for select/radio/multiselect
    validation      JSONB        NOT NULL DEFAULT '{}'::jsonb,           -- {min, max, pattern, ...}
    applies_to      TEXT[]       NOT NULL DEFAULT '{register,federation}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_registration_fields_field_key ON registration_fields (field_key);
CREATE INDEX idx_registration_fields_order ON registration_fields (display_order);

-- Seed defaults so the AuthUI keeps rendering the historical fields
-- (display name optional input, phone as an optional tel input) the
-- moment the feature ships, with no admin action required.
INSERT INTO registration_fields (id, field_key, label, kind, standard_target, type, required, enabled, display_order, applies_to)
VALUES
    (gen_random_uuid(), 'display_name', 'Display name', 'standard', 'display_name', 'text', FALSE, TRUE, 0, '{register,federation}'),
    (gen_random_uuid(), 'phone',        'Phone',        'standard', 'phone',        'tel',  FALSE, TRUE, 1, '{register,federation}');

-- +goose Down
DROP TABLE IF EXISTS registration_fields;
