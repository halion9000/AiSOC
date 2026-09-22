-- Migration 051: Business Context Rule Sets persistence (T3.5-followup).
--
-- Replaces the in-process _rule_store dict in business_context.py with a
-- durable, versioned JSONB store. Each save bumps the version integer so
-- the engine can cache snapshots keyed on (tenant_id, version) and swap
-- atomically on hot-reload.
--
-- Tenant isolation via RLS (same pattern as aisoc_shifts / aisoc_cases).

BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_business_context_rule_sets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    yaml_text   TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Only one active rule set per tenant; the version column tracks
    -- revisions for audit/cache-invalidation purposes.
    CONSTRAINT uq_business_context_rule_sets_tenant UNIQUE (tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_bcrs_tenant ON aisoc_business_context_rule_sets (tenant_id);

-- Auto-update updated_at trigger.
CREATE OR REPLACE FUNCTION aisoc_bcrs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_aisoc_bcrs_updated_at ON aisoc_business_context_rule_sets;
CREATE TRIGGER trg_aisoc_bcrs_updated_at
    BEFORE UPDATE ON aisoc_business_context_rule_sets
    FOR EACH ROW
    EXECUTE FUNCTION aisoc_bcrs_updated_at();

-- RLS: tenant-scoped reads/writes.
ALTER TABLE aisoc_business_context_rule_sets ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE policyname = 'aisoc_bcrs_tenant_isolation'
          AND tablename = 'aisoc_business_context_rule_sets'
    ) THEN
        CREATE POLICY aisoc_bcrs_tenant_isolation
            ON aisoc_business_context_rule_sets
            USING (tenant_id = COALESCE(
                current_setting('app.current_tenant_id', true)::uuid,
                '00000000-0000-0000-0000-000000000000'::uuid
            ))
            WITH CHECK (tenant_id = COALESCE(
                current_setting('app.current_tenant_id', true)::uuid,
                '00000000-0000-0000-0000-000000000000'::uuid
            ));
    END IF;
END
$$;

COMMIT;