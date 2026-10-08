-- Give the non-superuser application role `aisoc_app` a real password and least privilege.
--
-- WHY: row-level security (RLS) only constrains a NON-superuser. The default compose connects every service as the bootstrap superuser, which bypasses it. Migration 002 creates `aisoc_app` for this purpose but with a
-- password that is published in the repository ('changeme'); this script replaces it.
--
-- USAGE (run as the database OWNER, e.g. the `aisoc` role; idempotent, safe to run on every start):
--     AISOC_APP_DB_PASSWORD=<generated secret> psql -v ON_ERROR_STOP=1 -f scripts/provision_app_role.sql
-- The password is read from the ENVIRONMENT with \getenv (psql 15+), so it never appears on a command line or in this file. Use a generated hex or base64url secret: it is also placed in a connection URL.
-- docker-compose.rls.yml runs this as the one-shot `db-roles` service.

\set ON_ERROR_STOP on
\getenv app_pw AISOC_APP_DB_PASSWORD

\if :{?app_pw}
\else
    DO $$ BEGIN RAISE EXCEPTION 'AISOC_APP_DB_PASSWORD is not set'; END $$;
\endif
SELECT (length(:'app_pw') >= 16 AND :'app_pw' NOT IN ('changeme', 'aisoc_dev_secret')) AS pw_ok \gset
\if :pw_ok
\else
    DO $$ BEGIN RAISE EXCEPTION 'AISOC_APP_DB_PASSWORD must be at least 16 characters and not a published default'; END $$;
\endif

-- Create the role if the migrations have not (they normally have), then pin its attributes: it must never be able to bypass RLS.
SELECT 'CREATE ROLE aisoc_app' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') \gexec
ALTER ROLE aisoc_app WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_pw';

-- Least privilege: data access only. NOT TRUNCATE (it ignores RLS and row triggers, so it can erase the append-only audit_log), NOT REFERENCES/TRIGGER, and no schema changes (the role has no CREATE on the schema).
GRANT USAGE ON SCHEMA public TO aisoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aisoc_app;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM aisoc_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO aisoc_app;
REVOKE CREATE ON SCHEMA public FROM aisoc_app;

-- Tables created LATER by the owner (the migrations) get the same, not ALL (which is what 002's defaults grant).
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM aisoc_app', current_user) \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aisoc_app', current_user) \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO aisoc_app', current_user) \gexec

-- A summary for the logs (never the password).
SELECT rolname AS role, rolsuper AS superuser, rolbypassrls AS bypassrls, rolcanlogin AS can_login FROM pg_roles WHERE rolname = 'aisoc_app';
