-- Migration 072: explicit, per-person access to specific tenants.
--
-- WHY. A person belongs to ONE tenant (users.tenant_id) but may need to look at others: an MSP's technician at a customer, a consultant at several clients. Until now the only ways to view another tenant were (a) holding the platform-wide
-- cross-tenant permission, and (b) a blanket rule that every user of an MSSP parent tenant could view ALL of its child tenants (even a `viewer`). This table replaces (b): a person may view a tenant other than their own only if they have been GRANTED it
-- (or hold the platform-wide permission, which is unchanged).
--
-- THE TABLE. One row per (person, tenant). `access` is 'view' (read-only, the same as "view as"); other values can be added later without a new table. The grant belongs to the GRANTED tenant (tenant_id), so row-level security uses the
-- standard policy on it: that tenant's own people can see who has access to their data. `granted_by_label` keeps who made the grant (an account name or email) even if their account is later deleted; the grantee's or the tenant's deletion removes the grant.
-- A grant to one's own tenant is meaningless and is refused by the API.
--
-- The blanket "children of my MSSP" rule is removed in the same release; existing deployments start with NO grants, so an MSSP's staff lose access to customers until it is granted, deliberately (the rule was a day old and is narrower now).
--
-- Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_access_grants (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id        UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    access           VARCHAR(16) NOT NULL DEFAULT 'view' CHECK (access IN ('view')),
    granted_by       UUID        REFERENCES users (id) ON DELETE SET NULL,
    granted_by_label TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_tenant_access_grants_user_tenant UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS ix_tenant_access_grants_tenant ON tenant_access_grants (tenant_id);

ALTER TABLE tenant_access_grants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_access_grants;
CREATE POLICY tenant_isolation ON tenant_access_grants
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
