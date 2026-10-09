-- Migration 068: marketplace installs move from a per-process Python dict to a table.
--
-- WHAT WAS WRONG. POST /marketplace/install recorded the install in a module-level dict. It was lost whenever the API restarted, and with more than one worker or replica each held its own, so a tenant's "installed" list
-- changed depending on which process answered, and an item a user had installed could vanish. An install is a per-tenant "enabled" marker (the catalogue's files are on disk for everyone); nothing else reads it.
--
-- THE TABLE. One row per (tenant, item type, item id), so installing the same item twice is one row. Row-level security with the standard policy (migrations 060/061/063): under the non-superuser role a tenant context restricts to that
-- tenant, no context admits the row; the endpoints also filter by tenant explicitly. A tenant's rows go with the tenant (ON DELETE CASCADE). Existing deployments start with an empty table: the dict never survived a restart, so there is
-- nothing to carry over.
--
-- Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS marketplace_installs (
    tenant_id      UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    item_type      VARCHAR(20)  NOT NULL CHECK (item_type IN ('detection', 'playbook', 'plugin')),
    item_id        VARCHAR(200) NOT NULL,
    name           TEXT         NOT NULL,
    version        VARCHAR(50)  NOT NULL,
    path           TEXT,
    content_sha256 VARCHAR(64)  NOT NULL,
    installed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    installed_by   TEXT         NOT NULL,
    PRIMARY KEY (tenant_id, item_type, item_id)
);

ALTER TABLE marketplace_installs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON marketplace_installs;
CREATE POLICY tenant_isolation ON marketplace_installs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
