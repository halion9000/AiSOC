-- Migration 086: connector run log, the history behind the one-line message a connector card shows.
--
-- A connector row keeps only its latest message (connector_config.last_error), so an operator who sees "Warning" cannot tell when it started or what it said before. CORE's status
-- reports (inbox_core_feed) now also write one row here, but ONLY when a source's status or message differs from the last logged entry, so a healthy connector that reports "ok" every
-- five minutes adds nothing. The API keeps the newest 200 rows per connector.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS connector_run_log (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    connector_id UUID        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    status       VARCHAR(10) NOT NULL CHECK (status IN ('ok', 'warning', 'error')),
    message      TEXT,
    fetched      INTEGER     NOT NULL DEFAULT 0,
    sent         INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_connector_run_log_connector ON connector_run_log (connector_id, at DESC);

ALTER TABLE connector_run_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON connector_run_log;
CREATE POLICY tenant_isolation ON connector_run_log
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
