-- 082: shared rows (tenant_id IS NULL) become READ-ONLY for tenants (step 4c of docs/security/rls-fail-closed-plan.md).
--
-- THE HOLE. Twelve tables had one `FOR ALL` policy whose USING clause ended in `OR tenant_id IS NULL`, with no WITH CHECK. PostgreSQL applies USING
-- as the check when WITH CHECK is absent, so a tenant session could:
--   * UPDATE its own row to tenant_id = NULL, which instantly published it to every tenant (it stays readable by all, because of the same clause);
--   * UPDATE or DELETE any row that already had tenant_id = NULL (the shared rows), i.e. edit or destroy other tenants' view of shared content;
--   * INSERT a row with tenant_id = NULL.
-- Reproduced as the restricted role `aisoc_app` with the fail-closed switch ON (tests/test_rls_shared_rows_postgres.py keeps it reproduced).
--
-- THE FIX. Each of the twelve `FOR ALL` policies is replaced by four per-command policies:
--   SELECT  : own rows, shared rows (tenant_id IS NULL), or the switchable no-tenant branch (unchanged from 081)
--   INSERT  : WITH CHECK own tenant only, or the switchable no-tenant branch
--   UPDATE  : USING own tenant only (shared rows are not updatable) AND WITH CHECK own tenant only (a row cannot be re-labelled NULL or to
--             another tenant)
--   DELETE  : USING own tenant only
-- "the switchable no-tenant branch" is `(current_tenant_id() IS NULL AND NOT rls_fail_closed())`. Platform sessions (switch off, no tenant) and the
-- migration owner can therefore still create and maintain shared rows; a tenant session cannot.
--
-- Every writer in services/api sets tenant_id to the caller's tenant (checked when this was written), so no tenant code path loses a capability.
--
-- Idempotent: a table that already has its `<table>_shared_select` policy is skipped.

DO $$
DECLARE
    t        text;
    p        record;
    own      constant text := '(tenant_id = current_tenant_id()) OR ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed())))';
    changed  integer := 0;
    tables   constant text[] := ARRAY[
        'aisoc_case_comments', 'aisoc_case_tasks', 'aisoc_cases', 'aisoc_compliance_evidence', 'aisoc_hunt_runs', 'aisoc_hunts',
        'aisoc_kb_documents', 'aisoc_phishing_submissions', 'detection_eval_baselines', 'detection_rule_proposals', 'hunt_hypotheses',
        'passkey_challenges'];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_shared_select') THEN
            CONTINUE;
        END IF;

        -- Drop every existing policy on the table that is a FOR ALL tenant policy (there is exactly one on each of these tables).
        FOR p IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = t AND cmd = 'ALL' LOOP
            EXECUTE format('DROP POLICY %I ON public.%I', p.policyname, t);
        END LOOP;

        EXECUTE format('CREATE POLICY %I ON public.%I FOR SELECT USING ((tenant_id IS NULL) OR %s)', t || '_shared_select', t, own);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR INSERT WITH CHECK (%s)', t || '_own_insert', t, own);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR UPDATE USING (%s) WITH CHECK (%s)', t || '_own_update', t, own, own);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR DELETE USING (%s)', t || '_own_delete', t, own);
        changed := changed + 1;
    END LOOP;

    RAISE NOTICE '082: % shared-row tables now have read-only shared rows for tenants', changed;
END
$$;
