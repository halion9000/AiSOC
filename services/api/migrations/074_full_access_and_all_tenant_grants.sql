-- Migration 074: a grant can be FULL access (read and write), and a person can be granted ALL tenants.
--
-- LEVELS. tenant_access_grants.access was only 'view' (read-only). It is now 'view' or 'full'. With 'full' the person can also WRITE in that tenant, acting with their OWN role's permissions (never more), with identity and credential administration
-- (users, roles, API keys, who has access, platform and MSSP administration) still refused whatever the level: a stolen technician login must not be able to plant a hidden administrator in every customer. Every write is recorded in the TENANT's own audit log.
--
-- ALL TENANTS. all_tenant_access_grants holds one row per person who has been granted every tenant (including ones created later), at 'view' or 'full'. It has no tenant_id (it is about the person, not one tenant) so it carries no row-level security;
-- only platform administrators can create or remove these rows (the API enforces it), because a customer's own administrators must not be able to hand out "all".
--
-- Existing grants keep their 'view' level. Idempotent.

BEGIN;

ALTER TABLE tenant_access_grants DROP CONSTRAINT IF EXISTS tenant_access_grants_access_check;
ALTER TABLE tenant_access_grants ADD CONSTRAINT tenant_access_grants_access_check CHECK (access IN ('view', 'full'));

CREATE TABLE IF NOT EXISTS all_tenant_access_grants (
    user_id          UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    access           VARCHAR(16) NOT NULL CHECK (access IN ('view', 'full')),
    granted_by       UUID        REFERENCES users (id) ON DELETE SET NULL,
    granted_by_label TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
