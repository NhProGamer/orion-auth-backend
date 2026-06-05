-- +goose Up
INSERT INTO permissions (id, name, description) VALUES
    ('00000000-0000-0000-0000-0000000000b5', 'email_templates:read',  'Read transactional email template overrides'),
    ('00000000-0000-0000-0000-0000000000b6', 'email_templates:write', 'Create/update/delete email template overrides');

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000000000b5'),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000000000b6');

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '00000000-0000-0000-0000-0000000000b5',
    '00000000-0000-0000-0000-0000000000b6'
);
DELETE FROM permissions WHERE id IN (
    '00000000-0000-0000-0000-0000000000b5',
    '00000000-0000-0000-0000-0000000000b6'
);
