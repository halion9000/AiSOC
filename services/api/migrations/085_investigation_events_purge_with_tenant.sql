-- investigation_events stay append-only: no UPDATE, and no DELETE of a row whose tenant still exists.
--
-- The one thing that may remove them is deleting the TENANT that owns them (the foreign key cascades). That is what "Remove client" does in MSSP Client mapping: the AI
-- triage had opened investigations for every alert routed to a client tenant, and the tenant could not be removed at all while the ledger refused every delete.
-- Inside that cascade the tenant row is already gone, so `NOT EXISTS (tenants)` is true only there; a direct `DELETE FROM investigation_events` (a bug, or someone tampering
-- with the record) still finds the tenant and is still refused. audit_log is NOT changed: audit records of a tenant can never be deleted.
--
-- Approved by the project owner (Hal) on 2026-10-14 for this purpose.

CREATE OR REPLACE FUNCTION inv_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'investigation_events rows are immutable (attempted %)' , TG_OP;
END;
$$;
