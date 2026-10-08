-- Migration 062: the `aisoc_app` role must not be able to TRUNCATE (or add triggers to, or reference) the tables.
--
-- Migration 002 created `aisoc_app` and ran `GRANT ALL ON ALL TABLES` plus default privileges, in every database. ALL includes TRUNCATE, and TRUNCATE ignores BOTH row-level security and row-level triggers. The append-only
-- audit_log is protected only by a ROW trigger on DELETE/UPDATE (004), so as aisoc_app:
--     DELETE FROM audit_log;   -> refused ("audit_log rows are immutable")
--     TRUNCATE audit_log;      -> SUCCEEDS and erases the whole audit trail
-- Verified on a real database. Nothing in the services issues TRUNCATE, so revoking it removes no working behaviour. The same goes for REFERENCES and TRIGGER, which nothing uses and which let a role attach code to tables.
-- The role keeps SELECT, INSERT, UPDATE and DELETE (and sequence use), which is all the services do. Existing tables and tables created later are both covered. Idempotent; does nothing if the role does not exist.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM aisoc_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLES FROM aisoc_app;
    END IF;
END
$$;
