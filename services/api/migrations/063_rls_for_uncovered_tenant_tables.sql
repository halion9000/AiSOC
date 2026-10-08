-- Migration 063: row-level security for 36 of the 40 tenant-scoped tables that had none.
--
-- Only 38 of 79 tables with a tenant_id column had RLS. Under a non-superuser role (`aisoc_app`) a table without it is wide open to any code that sets a tenant context, because nothing restricts it. This enables RLS with the
-- STANDARD policy used everywhere else (migrations 060/061): a tenant context, when one is set, restricts to that tenant; NO context admits the row (the plain-session endpoints filter by tenant in the query).
--
-- SAFE BY CONSTRUCTION. A PostgreSQL superuser (what every service connects as in the default compose) bypasses RLS, so this changes NOTHING for any current deployment. It only takes effect once a service is moved to
-- the non-superuser role, and then only for code that sets a tenant context (which is always the AUTHENTICATED USER'S OWN tenant: app/db/rls.py get_tenant_db). ENABLE only, not FORCE: the owner is not constrained.
--
--   A. 27 tables with a NOT NULL uuid tenant_id: the standard policy.
--   B.  9 tables with a NULLABLE uuid tenant_id: the shared-rows variant (`OR tenant_id IS NULL`), the shape `hunt_hypotheses` already uses. NULL rows mean shared or legacy and are visible today; the plain standard policy
--       would make them VANISH for tenant-scoped sessions. This keeps them visible and still isolates every row that has a tenant.
--
-- DELIBERATELY NOT COVERED (each needs something this migration cannot supply):
--   users                          authentication reads it before any tenant is known (migration 002 leaves it out for the same reason).
--   mssp_tenant_metrics            a PARENT tenant reads its CHILD tenants' rows; an own-tenant-only policy would break that. Needs a parent-aware policy.
--   aisoc_autonomy_thresholds,
--   aisoc_institutional_memory,
--   aisoc_run_costs                tenant_id is TEXT (it may hold a slug such as "default", not the uuid): a uuid policy would error, or silently hide rows. Needs the code to store the canonical uuid first.
--
-- Idempotent. A table that does not exist is skipped.

DO $$
DECLARE
    t text;
BEGIN
    -- A. NOT NULL uuid tenant_id: standard policy
    FOREACH t IN ARRAY ARRAY[
        'aisoc_outcome_suppressions',
        'alert_asset_correlations', 'alert_identity_links', 'asset_vulnerabilities', 'assets',
        'case_tasks', 'case_timeline', 'case_timeline_events',
        'identity_edges', 'identity_nodes',
        'insider_indicators', 'insider_peer_groups',
        'oauth_app_credentials', 'oauth_states',
        'posture_drift_events', 'posture_findings', 'posture_scan_runs',
        'published_replays',
        'remediation_gate_log', 'remediation_maturity', 'remediation_whitelist',
        'report_artefacts', 'report_templates',
        'threat_actors', 'threat_intel_feeds', 'threat_intel_iocs',
        'user_risk_profiles'
    ] LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
            EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)', t);
        END IF;
    END LOOP;

    -- B. NULLABLE uuid tenant_id: shared-rows variant (rows with no tenant stay visible, exactly as today)
    FOREACH t IN ARRAY ARRAY[
        'aisoc_case_comments', 'aisoc_case_tasks', 'aisoc_cases', 'aisoc_compliance_evidence',
        'aisoc_hunt_runs', 'aisoc_hunts', 'aisoc_kb_documents', 'aisoc_phishing_submissions',
        'passkey_challenges'
    ] LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
            EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id() OR tenant_id IS NULL OR current_tenant_id() IS NULL)', t);
        END IF;
    END LOOP;
END
$$;
