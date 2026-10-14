-- Migration 083: client aliases, so a customer that has a different name in every tool lands on ONE AiSOC tenant.
--
-- THE PROBLEM. "Acme Dental, LLC" in Petra, "Acme Dental" in Huntress and "ACME" in NinjaOne are the same customer. Forwarded records carry the vendor's own client name and id; something has to say which AiSOC tenant each one belongs to.
--
-- THE TABLE. One row per (owning tenant, vendor, vendor client id): the vendor's name for the client, and the AiSOC child tenant it is linked to. child_tenant_id is NULL while the client is unmapped (it shows in an "Unmapped" list rather than being dropped), and
-- `ignored` marks a client the person decided not to map. match_source records whether a person chose the link ('manual', never overwritten by a suggestion) or accepted a suggestion ('suggested'). Suggestions themselves are computed on demand, not stored.
-- Row-level security with the standard policy (migrations 060/061/063).
--
-- Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS client_aliases (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    vendor             VARCHAR(40)  NOT NULL,
    vendor_client_id   VARCHAR(200) NOT NULL,
    vendor_client_name TEXT         NOT NULL,
    normalized_name    TEXT         NOT NULL,
    child_tenant_id    UUID         REFERENCES tenants (id) ON DELETE SET NULL,
    ignored            BOOLEAN      NOT NULL DEFAULT FALSE,
    match_source       VARCHAR(16)  NOT NULL DEFAULT 'suggested' CHECK (match_source IN ('manual', 'suggested')),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, vendor, vendor_client_id)
);

CREATE INDEX IF NOT EXISTS ix_client_aliases_child ON client_aliases (child_tenant_id);

ALTER TABLE client_aliases ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON client_aliases;
CREATE POLICY tenant_isolation ON client_aliases
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
