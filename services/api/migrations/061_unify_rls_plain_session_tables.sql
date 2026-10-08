-- Migration 061: four more tables whose RLS policy cannot work for the plain database session.
--
-- 060 fixed tables whose policies read setting names nothing sets. These four read the RIGHT setting, but in a STRICT form that only works when the code sets a tenant context first, and their endpoints use the
-- plain session (get_db: no tenant context; the query filters by tenant itself), the same as most of the API. Under a non-superuser role (the intended `aisoc_app`):
--   * external_assets, external_asset_drift (024)        call current_setting('app.current_tenant_id') WITHOUT the missing-ok flag, so even `SELECT count(*)` RAISES
--                                                        "unrecognized configuration parameter" until something has set it on that connection (and then fails on '' -> uuid).
--   * aisoc_business_context_rule_sets (051)             maps "no context" to the all-zero UUID, so the table looks EMPTY and every INSERT is refused.
--   * compliance_evidence                                reads the setting with missing-ok and compares to NULL, with the same effect: empty and read-only.
-- For a superuser, which bypasses RLS, nothing changes. This gives them the standard policy used everywhere else: a tenant context, when one is set, restricts to that tenant; no context admits the row (the endpoints
-- filter by tenant in the query).
-- NOT changed: aisoc_shifts (050). Its endpoints DO set a tenant context, so its stricter policy works as designed.

BEGIN;

DROP POLICY IF EXISTS easm_tenant_isolation ON external_assets;
CREATE POLICY easm_tenant_isolation ON external_assets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS easm_drift_tenant_isolation ON external_asset_drift;
CREATE POLICY easm_drift_tenant_isolation ON external_asset_drift
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS aisoc_bcrs_tenant_isolation ON aisoc_business_context_rule_sets;
CREATE POLICY aisoc_bcrs_tenant_isolation ON aisoc_business_context_rule_sets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS compliance_evidence_tenant_isolation ON compliance_evidence;
CREATE POLICY compliance_evidence_tenant_isolation ON compliance_evidence
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
