-- Migration 058: persist detection-loop suggestions (LLM-drafted Sigma fixes for false-positive alerts).
--
-- POST /detection-loop/suggest kept each suggestion in a process-wide dict, so a restart emptied GET /detection-loop/suggestions even though the draft proposals it had created were still in
-- detection_rule_proposals. That proposal row does not carry the alert id or the suggestion id, so a suggestion cannot be rebuilt from it. They are rows here now.
-- Its proposal insert was also wrapped in `except Exception: proposal_id = None`, silently swallowing every database error; that is now logged (and isolated in a savepoint).
--
--   alert_id     - the false-positive alert that prompted it. Deliberately NO foreign key: this is history, and an alert being pruned must not delete what was learned from it.
--   base_rule_id - the rule that fired, if known.   proposal_id - the draft proposal created alongside, if its insert succeeded.
--   created_by   - the analyst who asked.

BEGIN;

CREATE TABLE IF NOT EXISTS detection_suggestions (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    alert_id          UUID NOT NULL,
    base_rule_id      UUID,
    draft_rule_name   VARCHAR(300) NOT NULL,
    draft_sigma_yaml  TEXT NOT NULL,
    rationale         TEXT NOT NULL DEFAULT '',
    proposal_id       UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS detection_suggestions_tenant_idx ON detection_suggestions (tenant_id, created_at DESC);

ALTER TABLE detection_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_suggestions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS detection_suggestions_tenant_isolation ON detection_suggestions;
CREATE POLICY detection_suggestions_tenant_isolation ON detection_suggestions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
