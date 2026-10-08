-- Migration 059: tenant-owned playbooks (custom playbooks and clones of the shared library).
--
-- Playbooks are a SHARED, READ-ONLY LIBRARY (the fixtures and the canonical packs shipped with the agents service) plus each tenant's OWN playbooks, which live here. A tenant clones a library playbook to customise it.
--
-- Before this, every playbook created or edited through the API was written to ONE global index.json on the agents container's disk (no volume: lost on every redeploy), visible to every tenant, and
-- "index.json wins over fixtures": anyone able to PUT a playbook could override a shipped playbook for EVERY tenant, or delete it. Library playbooks are no longer writable through the API at all.
--
--   id           - server-generated (a uuid), so it can never collide with a library id.
--   name/enabled - also inside `definition`; columns so they can be indexed and filtered.
--   cloned_from  - the library (or own) playbook this was copied from, for provenance.
--   definition   - the whole playbook (trigger, steps, tags, ...).

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_playbooks (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id           TEXT NOT NULL,
    name         VARCHAR(300) NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    cloned_from  TEXT,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    definition   JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS tenant_playbooks_tenant_idx ON tenant_playbooks (tenant_id, created_at DESC);

ALTER TABLE tenant_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_playbooks FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_playbooks_tenant_isolation ON tenant_playbooks;
CREATE POLICY tenant_playbooks_tenant_isolation ON tenant_playbooks
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
