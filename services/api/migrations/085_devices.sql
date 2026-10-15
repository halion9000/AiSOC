-- Migration 085: devices, one row per physical machine per client, with one feed row per tool that reports it.
--
-- WHY NOT `assets`. assets is one flat row per thing with no serial number and no record of which tool said what. Devices need both: the same laptop is in NinjaOne, Addigy and Huntress, and
-- it must be ONE device that shows all three feeding it.
--
-- devices: one per machine per client tenant. serial_number is the NORMALIZED serial (upper-case, no spaces, placeholder values like "To Be Filled By O.E.M." dropped), NULL when no tool gave a usable one.
-- Two devices in one client never share a serial (partial unique index); that is what makes the serial the match key across tools. Devices with no serial are never merged automatically.
-- device_sources: one per (tenant, vendor, the vendor's id for the device): what that tool reported (its name, last seen, a few fields) and which device it belongs to.
-- device_merge_dismissals: a "possible duplicate" the person said is NOT a duplicate, so it stops being suggested. Stored with the lower id first.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS devices (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    serial_number VARCHAR(100),
    hostname      VARCHAR(255) NOT NULL,
    os            VARCHAR(100),
    os_version    VARCHAR(100),
    manufacturer  VARCHAR(100),
    model         VARCHAR(100),
    ip_addresses  TEXT[],
    last_seen     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    first_seen    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_devices_tenant_serial ON devices (tenant_id, serial_number) WHERE serial_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_devices_tenant_hostname ON devices (tenant_id, lower(hostname));

CREATE TABLE IF NOT EXISTS device_sources (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    device_id   UUID         NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    vendor      VARCHAR(40)  NOT NULL,
    external_id VARCHAR(200) NOT NULL,
    name        VARCHAR(255),
    details     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    last_seen   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, vendor, external_id)
);

CREATE INDEX IF NOT EXISTS ix_device_sources_device ON device_sources (device_id);

CREATE TABLE IF NOT EXISTS device_merge_dismissals (
    tenant_id UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    device_a  UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    device_b  UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_a, device_b),
    CHECK (device_a < device_b)
);

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON devices;
CREATE POLICY tenant_isolation ON devices
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

ALTER TABLE device_sources ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_sources;
CREATE POLICY tenant_isolation ON device_sources
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

ALTER TABLE device_merge_dismissals ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_merge_dismissals;
CREATE POLICY tenant_isolation ON device_merge_dismissals
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
