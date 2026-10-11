-- ============================================================
-- Migration 076: intel:read, a read-only permission split out of threat_intel:read
-- ============================================================
-- threat_intel:read guards, besides reading the tenant's stored threat intelligence:
--   GET /threat-intel/feeds                  the feed list (a feed's free-form `config` can hold credentials)
--   GET /enrichment/lookup, POST /enrichment/bulk   they send an indicator to outside providers
--   GET /threatintel/stix/taxii/collections, GET /threatintel/stix/misp/health
-- so nothing that should only READ intelligence (an integration, an AI agent's key) could be given it without those. intel:read is the read half:
--   GET /threat-intel/iocs, GET /threat-intel/iocs/{id}      indicators of compromise
--   GET /threat-intel/actors                                 threat actor profiles
--   GET /threatintel/stix/indicators, GET /threatintel/stix/bundles   what this tenant has published
-- NOT included: the feed list, enrichment, TAXII and MISP health: they stay threat_intel:read.
--
-- Nobody loses anything and nothing needs backfilling: threat_intel:read IMPLIES intel:read in app/core/security.py (permission_in), which every check goes
-- through (static roles, database roles, API-key scopes, and a `threat_intel:*` wildcard). This migration only adds the name to the permissions catalog so a custom role
-- can be given intel:read on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('intel:read', 'Read stored threat intelligence: indicators, threat actor profiles and published STIX (not the feed list, not enrichment, which sends indicators to outside providers)', 'threat_intel')
ON CONFLICT (name) DO NOTHING;
