-- +goose Up
CREATE TABLE policies (
    id          UUID PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    type        VARCHAR(50) NOT NULL,
    rego        TEXT NOT NULL,
    version     INT NOT NULL DEFAULT 1,
    active      BOOLEAN NOT NULL DEFAULT true,
    priority    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_policies_name ON policies (name);
CREATE INDEX idx_policies_type_active ON policies (type, active);

-- Seed policies permissions
INSERT INTO permissions (id, name, description) VALUES
    ('00000000-0000-0000-0000-00000000001b', 'policies:read', 'Read authorization policies'),
    ('00000000-0000-0000-0000-00000000001c', 'policies:write', 'Create/update/delete authorization policies');

-- Grant to admin role
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000001b'),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000001c');

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN ('00000000-0000-0000-0000-00000000001b', '00000000-0000-0000-0000-00000000001c');
DELETE FROM permissions WHERE id IN ('00000000-0000-0000-0000-00000000001b', '00000000-0000-0000-0000-00000000001c');
DROP TABLE IF EXISTS policies;
