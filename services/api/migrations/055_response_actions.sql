-- Migration 055: persist response actions (services/actions).
--
-- The actions service kept every submitted response action, its approval state and its result in a process-local dict, so a restart lost pending approvals, broke ChatOps approval links, and
-- erased the record of what had run. They are now rows here. The table is created by the API's migrations (which run on deploy); services/actions reads and writes it over its DATABASE_URL.
--
-- Schema:
--   id                   - the action id (from the request).
--   tenant_id            - owning tenant. Deliberately NO foreign key: this is an audit trail, and a tenant's lifecycle must neither block recording an action nor delete the record of what ran.
--   incident_id          - the incident the action belongs to.
--   action_type, target  - what was done to what.
--   status               - pending | awaiting_approval | approved | rejected | running | completed | failed | rolled_back. Kept as a column because the atomic claim that makes an action
--                          run at most once is a conditional UPDATE on it (UPDATE ... WHERE id = $1 AND status = 'awaiting_approval'), which holds across processes and replicas.
--   blast_radius, gate_reason, rationale, requested_by_user_id, approved_by_user_id - the gate's decision and who asked / approved.
--   request              - the COMPLETE original request as submitted (parameters, principal, auto_rollback, ...). Immutable. Approval rebuilds the request from THIS: it used to be rebuilt from a
--                          record that had dropped the parameters, so every action that needed approval executed without them.
--   result               - the outcome (output, rollback_data, error, ChatOps choice, ...).
--   chatops_responded_at - set once, atomically, by the first ChatOps response (dedupes a replayed or double-clicked link, even across restarts).
--
-- A row left in 'running' means the service stopped between claiming the action and recording its outcome: it may or may not have executed, so it is NEVER re-run automatically.

BEGIN;

CREATE TABLE IF NOT EXISTS response_actions (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL,
    incident_id           UUID NOT NULL,
    action_type           VARCHAR(60) NOT NULL,
    target                TEXT NOT NULL,
    status                VARCHAR(30) NOT NULL,
    blast_radius          VARCHAR(20) NOT NULL,
    gate_reason           TEXT NOT NULL DEFAULT '',
    rationale             TEXT NOT NULL DEFAULT '',
    requested_by_user_id  TEXT,
    approved_by_user_id   TEXT,
    request               JSONB NOT NULL,
    result                JSONB NOT NULL DEFAULT '{}'::jsonb,
    chatops_responded_at  TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT response_actions_status_check CHECK (
        status IN ('pending', 'awaiting_approval', 'approved', 'rejected', 'running', 'completed', 'failed', 'rolled_back')
    )
);

CREATE INDEX IF NOT EXISTS response_actions_tenant_status_idx ON response_actions (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS response_actions_incident_idx ON response_actions (incident_id);

ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_actions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS response_actions_tenant_isolation ON response_actions;
CREATE POLICY response_actions_tenant_isolation ON response_actions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
