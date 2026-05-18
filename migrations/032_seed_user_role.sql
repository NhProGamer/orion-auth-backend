-- +goose Up

-- Default 'user' role: gets all self-service permissions. New registrations
-- are auto-assigned via the user.Service.Register hook.
INSERT INTO roles (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000004', 'user', 'Default end-user role with full account self-service');

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004', id
FROM permissions
WHERE name LIKE 'account:%';

-- Backfill: every existing user without any role gets the new 'user' role.
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, '00000000-0000-0000-0000-000000000004'
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id);

-- +goose Down

DELETE FROM user_roles WHERE role_id = '00000000-0000-0000-0000-000000000004';
DELETE FROM role_permissions WHERE role_id = '00000000-0000-0000-0000-000000000004';
DELETE FROM roles WHERE id = '00000000-0000-0000-0000-000000000004';
