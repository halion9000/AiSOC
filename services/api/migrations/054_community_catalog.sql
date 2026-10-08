-- Migration 054: persist the community catalog (plugins, detections, playbooks).
--
-- The community endpoints kept three module-level dictionaries, so every API restart silently discarded every submission, every approval, every install count and every rating,
-- including items an admin had already approved. They are now rows here.
--
-- This catalog is deliberately GLOBAL, not tenant-scoped: it is a marketplace shared across tenants, so there is no row-level security on it. What the API enforces instead is the
-- review workflow (an item is invisible and uninstallable until an admin approves it). submitter_tenant_id records WHO submitted an item (nullable, and SET NULL if that tenant is
-- deleted), which the in-memory version never tracked and moderation needs.
--
-- Schema:
--   kind                - 'plugin' | 'detection' | 'playbook'.
--   item_id             - the item's identifier within its kind (a plugin manifest id, a Sigma rule id, a generated uuid for playbooks); primary key with kind.
--   status              - 'pending' | 'approved' | 'rejected' (also inside data; kept as a column so it can be indexed and filtered).
--   submitter_tenant_id - the tenant that submitted it.
--   data                - the full catalog entry as the API serves it (name, description, tags, counters, rating, the Sigma YAML or playbook definition, ...).

BEGIN;

CREATE TABLE IF NOT EXISTS community_catalog_items (
    kind                 VARCHAR(20)  NOT NULL,
    item_id              VARCHAR(200) NOT NULL,
    status               VARCHAR(20)  NOT NULL,
    submitter_tenant_id  UUID REFERENCES tenants(id) ON DELETE SET NULL,
    data                 JSONB        NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, item_id),
    CONSTRAINT community_catalog_kind_check CHECK (kind IN ('plugin', 'detection', 'playbook')),
    CONSTRAINT community_catalog_status_check CHECK (status IN ('pending', 'approved', 'rejected'))
);

CREATE INDEX IF NOT EXISTS community_catalog_kind_status_idx
    ON community_catalog_items (kind, status, created_at);

COMMIT;
