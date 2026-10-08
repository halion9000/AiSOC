-- Migration 053: persist published STIX indicators and bundles, per tenant.
--
-- POST /threatintel/stix/indicators and /bundles used to keep what a tenant published in process memory, so every API restart silently discarded published threat
-- intelligence. Each published STIX object is now stored as the JSON document that was published (the API never inspects it beyond what it needs to list it).
--
-- Schema:
--   id         - row id.
--   tenant_id  - owner tenant; isolation is enforced by RLS and by an explicit tenant filter in the API.
--   kind       - 'indicator' | 'bundle'.
--   stix_id    - the STIX identifier, e.g. indicator--<uuid>; unique per tenant.
--   document   - the full STIX object as published.
--   created_at - publish time; listing is in publish order.

BEGIN;

CREATE TABLE IF NOT EXISTS stix_objects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        VARCHAR(20) NOT NULL,
    stix_id     VARCHAR(120) NOT NULL,
    document    JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT stix_objects_kind_check CHECK (kind IN ('indicator', 'bundle')),
    CONSTRAINT stix_objects_unique_stix_id UNIQUE (tenant_id, stix_id)
);

CREATE INDEX IF NOT EXISTS stix_objects_tenant_kind_idx
    ON stix_objects (tenant_id, kind, created_at);

ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_objects FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS stix_objects_tenant_isolation ON stix_objects;
CREATE POLICY stix_objects_tenant_isolation ON stix_objects
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
