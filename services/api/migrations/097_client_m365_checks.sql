-- Migration 097: each client's Microsoft 365 baseline checks, read through CIPP by CORE once a day.
--
-- client_m365_checks: ONE row per client and source, replaced by each daily report. `checks` is a small JSON list of {key, status, evidence} (status: met, partly or not_met). Only checks CIPP could
-- actually answer are stored; a question with no check is shown as "needs a person". Read on the client review page; nothing here is sent anywhere.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_m365_checks (
    tenant_id    UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    source       VARCHAR(40)  NOT NULL,
    checks       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    refreshed_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

ALTER TABLE client_m365_checks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_m365_checks;
CREATE POLICY tenant_isolation ON client_m365_checks
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
