-- Migration 056: saved hunt SEARCHES (the raw-query bookmarks on the /hunt page), persisted and tenant-scoped.
--
-- They lived in a single module-level dict in the AGENTS service: lost on every restart, and with NO tenant scoping at all, so GET /api/v1/hunt/saved returned every tenant's saved searches to anyone
-- (queries routinely contain hostnames, usernames and IOCs). The web console reached that service through a Next.js rewrite that bypasses the API, so there was no tenant identity anywhere on the path.
-- They now live in the API, which owns tenant identity and RLS.
--
-- Distinct from aisoc_saved_hunts (040): that table stores natural-language hunts + their translation, optionally scheduled. These are plain query bookmarks: a name, a query, a language.
-- Like saved hunts they are tenant-shared (every analyst in the tenant sees them).

BEGIN;

CREATE TABLE IF NOT EXISTS saved_hunt_searches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    name        VARCHAR(200) NOT NULL,
    query       TEXT NOT NULL,
    language    VARCHAR(16) NOT NULL DEFAULT 'lucene',
    pinned      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saved_hunt_searches_language_check CHECK (language IN ('lucene', 'kql', 'sql', 'esql', 'spl'))
);

CREATE INDEX IF NOT EXISTS saved_hunt_searches_tenant_idx ON saved_hunt_searches (tenant_id, created_at DESC);

ALTER TABLE saved_hunt_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_hunt_searches FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS saved_hunt_searches_tenant_isolation ON saved_hunt_searches;
CREATE POLICY saved_hunt_searches_tenant_isolation ON saved_hunt_searches
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
