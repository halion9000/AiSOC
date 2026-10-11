-- ============================================================
-- Migration 077: alerts:triage, a narrow permission split out of alerts:write
-- ============================================================
-- alerts:write guards 29 routes: besides claiming, escalating and snoozing an alert it covers submitting and patching alerts, creating assets, adding cloud
-- posture findings, creating identity graph nodes, adding insider-threat indicators and changing an employee profile's watchlist, graph entities, honeytokens,
-- feedback and phishing re-triage. So an integration that only needs to TRIAGE alerts (CORE's agent claims, escalates and snoozes them) could not be given it
-- without all of that. alerts:triage is exactly three routes:
--   POST /alerts/{id}/claim        POST /alerts/{id}/escalate        POST /alerts/{id}/snooze
-- NOT included: POST /alerts/submit and PATCH /alerts/{id}, and every other alerts:write route: they stay alerts:write.
--
-- Nobody loses anything and nothing needs backfilling: alerts:write IMPLIES alerts:triage in app/core/security.py (permission_in), which every check goes
-- through (static roles, these database roles, API-key scopes, and an `alerts:*` wildcard). This migration only adds the name to the permissions catalog so a
-- custom role can be given alerts:triage on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('alerts:triage', 'Claim, escalate and snooze alerts (not submitting or patching an alert, and nothing else that alerts:write covers)', 'alerts')
ON CONFLICT (name) DO NOTHING;
