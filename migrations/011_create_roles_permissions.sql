-- +goose Up
CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_roles_name ON roles (name);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_permissions_name ON permissions (name);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles (user_id);

-- Seed default admin role and permissions
INSERT INTO roles (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin', 'Full administrative access');

INSERT INTO permissions (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000010', 'clients:read', 'Read OAuth2 clients'),
    ('00000000-0000-0000-0000-000000000011', 'clients:write', 'Create/update/delete OAuth2 clients'),
    ('00000000-0000-0000-0000-000000000012', 'users:read', 'Read users'),
    ('00000000-0000-0000-0000-000000000013', 'users:write', 'Create/update/delete users'),
    ('00000000-0000-0000-0000-000000000014', 'roles:read', 'Read roles and permissions'),
    ('00000000-0000-0000-0000-000000000015', 'roles:write', 'Create/update/delete roles'),
    ('00000000-0000-0000-0000-000000000016', 'audit:read', 'Read audit logs'),
    ('00000000-0000-0000-0000-000000000017', 'keys:read', 'Read signing keys'),
    ('00000000-0000-0000-0000-000000000018', 'keys:write', 'Rotate signing keys'),
    ('00000000-0000-0000-0000-000000000019', 'federation:read', 'Read federation providers'),
    ('00000000-0000-0000-0000-00000000001a', 'federation:write', 'Manage federation providers');

-- Grant all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions;

-- +goose Down
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
