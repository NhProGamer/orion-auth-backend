-- +goose Up

CREATE TABLE api_resources (
    id               UUID PRIMARY KEY,
    name             VARCHAR(255) NOT NULL,
    identifier       VARCHAR(512) NOT NULL,
    description      TEXT,
    signing_alg      VARCHAR(10) NOT NULL DEFAULT 'RS256',
    access_token_ttl INT NOT NULL DEFAULT 3600,
    active           BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_api_resources_identifier ON api_resources (identifier);

CREATE TABLE resource_permissions (
    id          UUID PRIMARY KEY,
    resource_id UUID NOT NULL REFERENCES api_resources(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_resource_permissions_resource_name ON resource_permissions (resource_id, name);
CREATE INDEX idx_resource_permissions_resource_id ON resource_permissions (resource_id);

CREATE TABLE client_resource_permissions (
    client_id     UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES resource_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, permission_id)
);

CREATE INDEX idx_client_resource_perms_client ON client_resource_permissions (client_id);

-- Add audience to tokens and requests
ALTER TABLE access_tokens ADD COLUMN audience VARCHAR(512);
ALTER TABLE refresh_tokens ADD COLUMN audience VARCHAR(512);
ALTER TABLE authorization_codes ADD COLUMN audience VARCHAR(512);
ALTER TABLE authorization_requests ADD COLUMN audience VARCHAR(512);
ALTER TABLE device_codes ADD COLUMN audience VARCHAR(512);
ALTER TABLE consents ADD COLUMN resource_id UUID REFERENCES api_resources(id) ON DELETE SET NULL;

CREATE INDEX idx_access_tokens_audience ON access_tokens (audience) WHERE audience IS NOT NULL;
CREATE INDEX idx_refresh_tokens_audience ON refresh_tokens (audience) WHERE audience IS NOT NULL;

-- Seed admin permissions for resources
INSERT INTO permissions (id, name, description) VALUES
    ('00000000-0000-0000-0000-00000000001d', 'resources:read', 'Read API resources'),
    ('00000000-0000-0000-0000-00000000001e', 'resources:write', 'Create/update/delete API resources');

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000001d'),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000001e');

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN ('00000000-0000-0000-0000-00000000001d', '00000000-0000-0000-0000-00000000001e');
DELETE FROM permissions WHERE id IN ('00000000-0000-0000-0000-00000000001d', '00000000-0000-0000-0000-00000000001e');

ALTER TABLE consents DROP COLUMN IF EXISTS resource_id;
ALTER TABLE device_codes DROP COLUMN IF EXISTS audience;
ALTER TABLE authorization_requests DROP COLUMN IF EXISTS audience;
ALTER TABLE authorization_codes DROP COLUMN IF EXISTS audience;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS audience;
ALTER TABLE access_tokens DROP COLUMN IF EXISTS audience;

DROP TABLE IF EXISTS client_resource_permissions;
DROP TABLE IF EXISTS resource_permissions;
DROP TABLE IF EXISTS api_resources;
