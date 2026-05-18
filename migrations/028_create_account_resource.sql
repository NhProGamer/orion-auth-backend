-- +goose Up

-- Seed the orion-account API resource (used to model the User Account API).
INSERT INTO api_resources (id, name, identifier, description, signing_alg, access_token_ttl, active)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    'Orion Account',
    'urn:orion:account',
    'User account self-service API (profile, password, email, MFA, passkeys, sessions, deletion)',
    'RS256',
    3600,
    true
);

-- Account permissions (resource-scoped, used by AdminUI for fine-grained role wiring).
INSERT INTO resource_permissions (id, resource_id, name, description) VALUES
    ('00000000-0000-0000-0000-0000000000a0', '00000000-0000-0000-0000-000000000003', 'account:read_profile',           'Read own profile, sessions, linked accounts, MFA status, passkeys'),
    ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-000000000003', 'account:update_profile',         'Update own display name, avatar, phone, OIDC profile metadata'),
    ('00000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-000000000003', 'account:change_email',           'Initiate and confirm own email address change'),
    ('00000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-000000000003', 'account:change_password',        'Change own password'),
    ('00000000-0000-0000-0000-0000000000a4', '00000000-0000-0000-0000-000000000003', 'account:manage_sessions',        'Revoke own sessions'),
    ('00000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-000000000003', 'account:manage_mfa',             'Enroll/disable own MFA, regenerate backup codes'),
    ('00000000-0000-0000-0000-0000000000a6', '00000000-0000-0000-0000-000000000003', 'account:manage_passkeys',        'Register/rename/delete own passkeys'),
    ('00000000-0000-0000-0000-0000000000a7', '00000000-0000-0000-0000-000000000003', 'account:manage_linked_accounts', 'Unlink own federation accounts'),
    ('00000000-0000-0000-0000-0000000000a8', '00000000-0000-0000-0000-000000000003', 'account:delete_account',         'Request own account deletion');

-- Mirror into RBAC permissions so the existing RequirePermission middleware works as-is.
-- AdminUI wires these via Resources screen; the RBAC table is the runtime source of truth.
INSERT INTO permissions (id, name, description) VALUES
    ('00000000-0000-0000-0000-0000000000a0', 'account:read_profile',           'Read own profile, sessions, linked accounts, MFA status, passkeys'),
    ('00000000-0000-0000-0000-0000000000a1', 'account:update_profile',         'Update own display name, avatar, phone, OIDC profile metadata'),
    ('00000000-0000-0000-0000-0000000000a2', 'account:change_email',           'Initiate and confirm own email address change'),
    ('00000000-0000-0000-0000-0000000000a3', 'account:change_password',        'Change own password'),
    ('00000000-0000-0000-0000-0000000000a4', 'account:manage_sessions',        'Revoke own sessions'),
    ('00000000-0000-0000-0000-0000000000a5', 'account:manage_mfa',             'Enroll/disable own MFA, regenerate backup codes'),
    ('00000000-0000-0000-0000-0000000000a6', 'account:manage_passkeys',        'Register/rename/delete own passkeys'),
    ('00000000-0000-0000-0000-0000000000a7', 'account:manage_linked_accounts', 'Unlink own federation accounts'),
    ('00000000-0000-0000-0000-0000000000a8', 'account:delete_account',         'Request own account deletion');

-- Grant all account permissions to admin role (admin gets everything by default).
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id
FROM permissions
WHERE name LIKE 'account:%';

-- +goose Down

DELETE FROM role_permissions
WHERE permission_id IN (
    '00000000-0000-0000-0000-0000000000a0','00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000a2',
    '00000000-0000-0000-0000-0000000000a3','00000000-0000-0000-0000-0000000000a4','00000000-0000-0000-0000-0000000000a5',
    '00000000-0000-0000-0000-0000000000a6','00000000-0000-0000-0000-0000000000a7','00000000-0000-0000-0000-0000000000a8'
);
DELETE FROM permissions WHERE id IN (
    '00000000-0000-0000-0000-0000000000a0','00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000a2',
    '00000000-0000-0000-0000-0000000000a3','00000000-0000-0000-0000-0000000000a4','00000000-0000-0000-0000-0000000000a5',
    '00000000-0000-0000-0000-0000000000a6','00000000-0000-0000-0000-0000000000a7','00000000-0000-0000-0000-0000000000a8'
);
DELETE FROM resource_permissions WHERE resource_id = '00000000-0000-0000-0000-000000000003';
DELETE FROM api_resources WHERE id = '00000000-0000-0000-0000-000000000003';
