-- Migration 060: make four tables' RLS policies read the SAME tenant setting as every other table.
--
-- The standard policy reads current_tenant_id(), which reads the setting `app.current_tenant_id` and ADMITS "no context" (the plain session used by many endpoints sets none; they filter by tenant in the query).
-- Four tables used other names that NOTHING sets:
--   * tenant_sla_config, alert_sla_events (007)            read `app.tenant_id`
--   * retention_policies, custom_parsers (049)             read `app.current_tenant`
-- and had no "no context" branch. Under a non-superuser role (the intended `aisoc_app`) those policies compared tenant_id to NULL, so those tables showed NO rows and rejected every INSERT: SLA tracking, the retention
-- settings (and so the retention sweeper's per-tenant windows) and custom parsers were broken. For a superuser, which bypasses RLS, nothing changes. This makes them consistent with the rest of the schema.

BEGIN;

DROP POLICY IF EXISTS tenant_isolation ON tenant_sla_config;
CREATE POLICY tenant_isolation ON tenant_sla_config
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS tenant_isolation ON alert_sla_events;
CREATE POLICY tenant_isolation ON alert_sla_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS retention_policies_tenant ON retention_policies;
CREATE POLICY retention_policies_tenant ON retention_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS custom_parsers_tenant ON custom_parsers;
CREATE POLICY custom_parsers_tenant ON custom_parsers
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
