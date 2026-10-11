-- ============================================================
-- Migration 080: cases:work, a narrow permission split out of cases:write
-- ============================================================
-- cases:write guards 14 routes: besides working on an existing case it covers creating cases, attaching alerts, notes, observables and tasks, raising and DECIDING
-- agent approvals (the human sign-off for destructive actions), and publishing or unpublishing investigation replays. So an integration that only needs to work on cases
-- it is pointed at (CORE's agent updates a case, comments on it, launches an investigation from it and closes one) could not be given it without all of that.
-- cases:work is exactly four routes:
--   PATCH /cases/{id}      POST /cases/{id}/comments      POST /cases/{id}/investigate      POST /investigations/{id}/close
-- NOT included: every other cases:write route (create case, attach alerts, notes, observables, tasks, approvals, replays): they stay cases:write.
--
-- Nobody loses anything and nothing needs backfilling: cases:write IMPLIES cases:work in app/core/security.py (permission_in), which every check goes through
-- (static roles, these database roles, API-key scopes, and a `cases:*` wildcard). This migration only adds the name to the permissions catalog so a custom role can
-- be given cases:work on its own. It is idempotent.
-- ============================================================

INSERT INTO permissions (name, description, category) VALUES
    ('cases:work', 'Update a case, comment on it, launch an investigation from it and close an investigation (not creating cases, notes, tasks, approvals or replays)', 'cases')
ON CONFLICT (name) DO NOTHING;
