-- +goose Up

-- Seed the orion-m2m API resource. Services authenticate via OAuth2
-- client_credentials with audience=urn:orion:m2m and one or more of the
-- m2m:users:* scopes below to call /api/v1/m2m/users/*.
INSERT INTO api_resources (id, name, identifier, description, signing_alg, access_token_ttl, active)
VALUES (
    '00000000-0000-0000-0000-000000000005',
    'Orion M2M',
    'urn:orion:m2m',
    'Machine-to-machine admin API for programmatic user management (parallel to /api/v1/admin/users/* but consumed by services with client_credentials tokens)',
    'RS256',
    3600,
    true
);

-- Five permissions, deliberately coarse enough to stay manageable while
-- separating destructive (delete) and auth-affecting (manage_auth) verbs so
-- least-privilege grants are easy.
INSERT INTO resource_permissions (id, resource_id, name, description) VALUES
    ('00000000-0000-0000-0000-0000000000b0', '00000000-0000-0000-0000-000000000005', 'm2m:users:read',         'Read users, sessions, roles, passkeys, linked accounts'),
    ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-000000000005', 'm2m:users:write',        'Create users and update any user field (except id)'),
    ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-000000000005', 'm2m:users:delete',       'Hard-delete users'),
    ('00000000-0000-0000-0000-0000000000b3', '00000000-0000-0000-0000-000000000005', 'm2m:users:manage_auth',  'Set password, unlock account, reset MFA, revoke sessions/passkeys/linked-accounts'),
    ('00000000-0000-0000-0000-0000000000b4', '00000000-0000-0000-0000-000000000005', 'm2m:users:manage_roles', 'Assign and remove user roles');

-- No RBAC mirror — m2m:* permissions are exclusively granted to OAuth
-- clients via client_resource_permissions. They never appear on user roles.
-- No default client grant either — the admin must explicitly opt-in any
-- client to call the M2M API via POST /admin/clients/:id/resource-permissions.

-- +goose Down

DELETE FROM client_resource_permissions
WHERE permission_id IN (
    '00000000-0000-0000-0000-0000000000b0','00000000-0000-0000-0000-0000000000b1',
    '00000000-0000-0000-0000-0000000000b2','00000000-0000-0000-0000-0000000000b3',
    '00000000-0000-0000-0000-0000000000b4'
);
DELETE FROM resource_permissions WHERE resource_id = '00000000-0000-0000-0000-000000000005';
DELETE FROM api_resources WHERE id = '00000000-0000-0000-0000-000000000005';
