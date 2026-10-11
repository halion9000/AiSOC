-- ============================================================
-- Migration 078: rules:view, a read-only permission split out of rules:read
-- ============================================================
-- rules:read guards 18 routes: 13 plain reads and 5 that COMPUTE:
--   POST /rules/hunt, POST /rules/{id}/execute, POST /detection/test   run rules over events the CALLER sends
--   POST /translation/translate                                         translate a rule between formats
--   POST /rules/{id}/backtest                                           run a rule over up to 365 days of the tenant's REAL events in the data lake and return
--                                                                       sample_matches, the matching event rows: that is reading telemetry, the thing lake:query gates
-- so nothing that should only READ the rules (an AI agent's API key) could be given it without being able to read lake telemetry. rules:view is the read half:
--   GET /rules, GET /rules/{id}, GET /detection/rules, GET /detection/rules/{id}
--   GET /detection/coverage, /detection/drift, /detection/confidence, /detection/tuning, /detection/tuning/summary
--   GET /detection-proposals, /detection-proposals/baselines, /detection-proposals/{id}
--   GET /translation/formats
-- NOT included: the five computing routes above: they stay rules:read.
--
-- Nobody loses anything and nothing needs backfilling: rules:read IMPLIES rules:view in app/core/security.py (permission_in), which every check goes through
-- (static roles, these database roles, API-key scopes, and a `rules:*` wildcard). This migration only adds the name to the permissions catalog so a custom role
-- can be given rules:view on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('rules:view', 'Read detection rules, coverage, drift, confidence, tuning and proposals (not running, testing, translating or backtesting a rule: a backtest reads lake telemetry)', 'detections')
ON CONFLICT (name) DO NOTHING;
