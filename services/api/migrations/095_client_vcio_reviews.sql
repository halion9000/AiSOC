-- Migration 095: each client's vCIO Toolbox recommendations and risks, summarised by CORE once a day.
--
-- client_vcio_reviews: ONE row per client and source, replaced by each daily report. `recommendations` holds the counts by adoption state and the pending ones that matter most, `risks` the client's
-- risks, both as small JSON documents. Only read here; what a person approves is sent by CORE (migration 096).
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_vcio_reviews (
    tenant_id       UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source          VARCHAR(40)  NOT NULL,
    recommendations JSONB        NOT NULL DEFAULT '{}'::jsonb,
    risks           JSONB        NOT NULL DEFAULT '[]'::jsonb,
    refreshed_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

ALTER TABLE client_vcio_reviews ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_vcio_reviews;
CREATE POLICY tenant_isolation ON client_vcio_reviews
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
