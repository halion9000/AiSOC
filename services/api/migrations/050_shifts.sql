-- Migration 050: Real shift tracking
--
-- Replaces the in-memory _MOCK_SHIFTS / _MOCK_ANALYSTS surface in
-- services/api/app/api/v1/endpoints/shifts.py with a persistent,
-- tenant-scoped table. Shifts record who was on duty, when, and what
-- happened — the handoff notes that carry context between shifts are
-- stored inline (no separate table needed at current volume).
--
-- RLS follows the same pattern as aisoc_cases (migration 012): every
-- query is scoped to app.current_tenant_id so analysts can only see
-- their own tenant's shift history.

CREATE TABLE IF NOT EXISTS aisoc_shifts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'completed', 'cancelled')),
    lead_id         TEXT,
    lead_name       TEXT,
    lead_role       TEXT,
    analyst_ids     TEXT[] DEFAULT ARRAY[]::TEXT[],
    analyst_count   INTEGER NOT NULL DEFAULT 1,
    alerts_handled  INTEGER NOT NULL DEFAULT 0,
    escalations     INTEGER NOT NULL DEFAULT 0,
    handoff_notes   TEXT,
    pending_items   TEXT[] DEFAULT ARRAY[]::TEXT[],
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aisoc_shifts_tenant   ON aisoc_shifts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_aisoc_shifts_status   ON aisoc_shifts (status);
CREATE INDEX IF NOT EXISTS idx_aisoc_shifts_started  ON aisoc_shifts (started_at DESC);

-- Tenant isolation via RLS (mirrors aisoc_cases pattern from 002_rls.sql).
ALTER TABLE aisoc_shifts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE policyname = 'aisoc_shifts_tenant_isolation' AND tablename = 'aisoc_shifts'
    ) THEN
        CREATE POLICY aisoc_shifts_tenant_isolation
            ON aisoc_shifts
            USING (tenant_id = COALESCE(current_setting('app.current_tenant_id', true)::uuid, '00000000-0000-0000-0000-000000000000'::uuid))
            WITH CHECK (tenant_id = COALESCE(current_setting('app.current_tenant_id', true)::uuid, '00000000-0000-0000-0000-000000000000'::uuid));
    END IF;
END
$$;

-- Auto-update updated_at trigger (same pattern as other tables).
CREATE OR REPLACE FUNCTION aisoc_shifts_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_aisoc_shifts_updated_at ON aisoc_shifts;
CREATE TRIGGER trg_aisoc_shifts_updated_at
    BEFORE UPDATE ON aisoc_shifts
    FOR EACH ROW
    EXECUTE FUNCTION aisoc_shifts_updated_at();