-- +goose Up
CREATE TABLE role_resource_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES resource_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_resource_perms_role ON role_resource_permissions (role_id);

-- +goose Down
DROP TABLE IF EXISTS role_resource_permissions;
