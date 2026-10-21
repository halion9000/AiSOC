-- Migration 094: each client's Microsoft Secure Score, read through CIPP.
--
-- identity_secure_scores: ONE row per client and source, replaced by each daily report. It holds the latest score and its maximum, Microsoft's all-tenant average, up to 90 daily points for the trend
-- (history) and the controls still missing the most points (improvements), both as small JSON lists. COLLECT AND SHOW ONLY: nothing here raises an alert or changes a tenant.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS identity_secure_scores (
    tenant_id      UUID           NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source         VARCHAR(40)    NOT NULL,
    taken_at       TIMESTAMPTZ    NOT NULL,
    current_score  NUMERIC(8, 2)  NOT NULL,
    max_score      NUMERIC(8, 2)  NOT NULL,
    average_score  NUMERIC(8, 2),
    active_users   INTEGER,
    licensed_users INTEGER,
    history        JSONB          NOT NULL DEFAULT '[]'::jsonb,
    improvements   JSONB          NOT NULL DEFAULT '[]'::jsonb,
    refreshed_at   TIMESTAMPTZ    NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

ALTER TABLE identity_secure_scores ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON identity_secure_scores;
CREATE POLICY tenant_isolation ON identity_secure_scores
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
