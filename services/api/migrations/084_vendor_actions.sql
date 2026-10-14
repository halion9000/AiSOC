-- Migration 084: vendor actions, the queue between an analyst's click in AiSOC and CORE, which holds the vendor credentials.
--
-- AiSOC never holds a vendor key. When an analyst approves or rejects a Huntress remediation plan, or resolves the incident, AiSOC writes one row here (status 'pending'). CORE collects pending rows on its
-- regular poll (claiming marks them 'claimed' so none runs twice), makes the call to the vendor, and reports 'done' or 'failed' with a short message. A row nobody collected within 30 minutes is treated as
-- expired by the API, so an approval clicked while CORE was off cannot fire hours later.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS vendor_actions (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    alert_id      UUID         NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    vendor        VARCHAR(40)  NOT NULL,
    incident_uid  VARCHAR(200) NOT NULL,
    action        VARCHAR(20)  NOT NULL CHECK (action IN ('approve', 'reject', 'resolve')),
    params        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status        VARCHAR(12)  NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'done', 'failed')),
    requested_by  UUID,
    result_message TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    claimed_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_vendor_actions_alert ON vendor_actions (alert_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_vendor_actions_pending ON vendor_actions (tenant_id, vendor, status);

ALTER TABLE vendor_actions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vendor_actions;
CREATE POLICY tenant_isolation ON vendor_actions
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
