-- Migration 089: a log of device merges, so a merge can be undone.
--
-- Merging two "possible duplicate" devices deletes the removed device and moves its feeds onto the kept one. That is a one-way door unless what was removed is written down first.
-- Each merge now leaves a row here: a snapshot of the removed device, which feed rows moved, and what was filled in on the kept device from the removed one. Undoing recreates the removed device
-- with its own id, moves those feed rows back and puts the blanks back. A merge older than the retention the API applies, or one already undone, cannot be undone again.
--
-- kept_device_id has no foreign key on purpose: the kept device may itself be merged away later, and the log row should simply become un-undoable, not block that.
--
-- Row-level security with the standard policy, honouring the fail-closed switch (migration 081). Idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS device_merge_log (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kept_device_id   UUID        NOT NULL,
    removed          JSONB       NOT NULL,
    moved_source_ids JSONB       NOT NULL DEFAULT '[]'::jsonb,
    filled           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    undone_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_device_merge_log_tenant_created ON device_merge_log (tenant_id, created_at DESC);

ALTER TABLE device_merge_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_merge_log;
CREATE POLICY tenant_isolation ON device_merge_log
    USING ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))))
    WITH CHECK ((tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed()))));

COMMIT;
