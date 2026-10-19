-- Migration 092: device names seen for a tool's clients that are not mapped yet, to suggest which AiSOC client they belong to.
--
-- Devices of an unmapped tool client are not stored (they wait for the mapping). But the machine names are the strongest hint there is: if most of "Pirkey Barber" in AutoElevate are machines
-- that NinjaOne and Huntress already report under the Pirkey Barber client here, that is the match. So the first few hundred lower-cased machine names of each unmapped client are kept
-- (nothing else about them), compared with the devices under each client, and forgotten two weeks after they were last reported.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_device_hints (
    tenant_id        UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    vendor           VARCHAR(40)  NOT NULL,
    vendor_client_id VARCHAR(200) NOT NULL,
    hostname_key     VARCHAR(255) NOT NULL,
    seen_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, vendor, vendor_client_id, hostname_key)
);

CREATE INDEX IF NOT EXISTS ix_client_device_hints_seen ON client_device_hints (tenant_id, seen_at);

ALTER TABLE client_device_hints ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_device_hints;
CREATE POLICY tenant_isolation ON client_device_hints
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
