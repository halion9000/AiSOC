-- ============================================================
-- Migration 075: hunts:read, a read-only permission split out of lake:query
-- ============================================================
-- lake:query is ONE permission for everything hunting does: creating, running and deleting hunts and saved hunts, and running arbitrary queries
-- against telemetry (/nl-query/execute). That made it impossible to let anything READ what hunts exist (an integration, a read-only role) without also
-- letting it run queries. hunts:read is the read half:
--   GET /hunts, GET /hunts/{id}            hunt hypotheses: the hypothesis, the queries, the analysts' findings
--   GET /saved-hunts, GET /saved-hunts/{id}   saved hunts
--   GET /hunt/saved                        saved searches
-- NOT included: GET /hunts/{id}/runs. A run holds a sample of the event rows the query returned, so reading it is reading telemetry: it stays lake:query.
--
-- Nobody loses anything and nothing needs backfilling: lake:query IMPLIES hunts:read in app/core/security.py (permission_in), which every check goes
-- through (static roles, these database roles, API-key scopes). This migration only adds the name to the permissions catalog so a custom role can be
-- given hunts:read on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('hunts:read', 'Read hunt hypotheses, saved hunts and saved searches (not their run results, and not running a query)', 'lake')
ON CONFLICT (name) DO NOTHING;
