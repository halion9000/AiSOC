-- Migration 090: hide a device until it checks back in.
--
-- An offline device (a laptop in a drawer, a retired machine) can sit in the Devices list for weeks. "Hide until back online" writes a row here. The API treats a device as hidden while a row
-- exists AND no tool has seen the device online since snoozed_at; the moment a tool reports it online again it shows up on its own (the row is then ignored, and replaced the next time it is hidden).
--
-- One row per device. Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS device_snoozes (
    device_id  UUID        PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    tenant_id  UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    snoozed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID
);

CREATE INDEX IF NOT EXISTS ix_device_snoozes_tenant ON device_snoozes (tenant_id);

ALTER TABLE device_snoozes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_snoozes;
CREATE POLICY tenant_isolation ON device_snoozes
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
