-- ============================================================
-- Migration 079: connectors:view, a read-only permission split out of connectors:read
-- ============================================================
-- connectors:read guards, besides listing connectors:
--   POST /federated/search                      a free-text or indicator query run across the tenant's connected SIEMs (Splunk, Elastic...) with their stored
--                                               credentials, returning the merged rows: telemetry from the customer's own systems
--   GET /federated/backends, GET /agents/tools  which connectors a search would reach, and what an agent may do with them
--   GET /inbox/templates, GET /inbox/tokens     inbound-push templates and token fingerprints
--   GET /oauth/app/{connector_type}             the registered OAuth app (without its secret)
-- so nothing that should only SEE which connectors exist and whether they are healthy (an AI agent's API key) could be given it without being able to search the
-- customer's SIEM. connectors:view is exactly the five reads that does:
--   GET /connectors, GET /connectors/catalog, GET /connectors/health, GET /connectors/{id}, GET /connectors/{id}/last_event_at
-- NOT included: everything listed above, which stays connectors:read, and everything that creates, changes or deletes a connector.
--
-- Nobody loses anything and nothing needs backfilling: connectors:read IMPLIES connectors:view in app/core/security.py (permission_in), which every check goes
-- through (static roles, these database roles, API-key scopes, and a `connectors:*` wildcard). This migration only adds the name to the permissions catalog so a
-- custom role can be given connectors:view on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('connectors:view', 'List connectors, the catalog, health and when a connector last saw an event (not searching connected systems, not the inbox or OAuth views)', 'connectors')
ON CONFLICT (name) DO NOTHING;
