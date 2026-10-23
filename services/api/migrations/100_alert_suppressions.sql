-- Migration 100: hide an alert type (for one device, one client, or everyone), for a number of days or without end.
--
-- alert_suppressions: one row per "hide this alert type" decision, owned by the tenant that made it (the MSSP). `scope` is device, client or all; `client_tenant_id` names the client for the first two;
-- `device_key` is the lower-cased first label of the machine name for a device rule. `signature` is the alert type: `rule:<rule id>` when the alert carries a rule, else `title:<title>`; `source` is the
-- tool that raised it. `expires_at` NULL means hidden without end. `revoked_at` is set when the rule is lifted by a person or runs out.
--
-- alerts gets two columns so a hidden alert can be put back as it was: the status it had, and the rule that hid it. A hidden alert has status 'suppressed'.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS alert_suppressions (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    scope            VARCHAR(10)  NOT NULL CHECK (scope IN ('device', 'client', 'all')),
    client_tenant_id UUID         REFERENCES tenants (id) ON DELETE CASCADE,
    device_key       VARCHAR(255),
    source           VARCHAR(100),
    signature        TEXT         NOT NULL,
    title            TEXT         NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ,
    created_by       UUID,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at       TIMESTAMPTZ,
    revoked_reason   VARCHAR(20)
);

CREATE INDEX IF NOT EXISTS idx_alert_suppressions_tenant_active ON alert_suppressions (tenant_id) WHERE revoked_at IS NULL;

ALTER TABLE alert_suppressions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_suppressions;
CREATE POLICY tenant_isolation ON alert_suppressions
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status_before_suppression VARCHAR(30);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS suppression_id UUID;
CREATE INDEX IF NOT EXISTS idx_alerts_suppression ON alerts (suppression_id) WHERE suppression_id IS NOT NULL;

COMMIT;
