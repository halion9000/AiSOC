-- 081: a SWITCH for fail-closed row-level security (step 4 of docs/security/rls-fail-closed-plan.md). Changes NO behaviour while the switch is off.
--
-- WHY. 77 tenant policies end in `OR current_tenant_id() IS NULL`: a session that never set a tenant sees (and, because none has a WITH CHECK,
-- can write) every row. That branch is what makes RLS fail OPEN. Making it fail closed is the point of the plan, but editing 77 policies is a
-- one-way change that can only be undone by another migration, and it cannot be deployed safely until every code path that has no signed-in
-- user has an explicit mechanism (the workers, the audit middleware, login, SSO, signup, webhook ingestion; see the plan).
--
-- WHAT THIS DOES. It rewrites each such policy ONCE so that the fail-open branch is conditional:
--     (current_tenant_id() IS NULL)   ->   ((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed())))
-- `rls_fail_closed()` reads the custom setting `app.rls_fail_closed`, which is unset by default, so today's behaviour is unchanged. Turning
-- fail-closed ON is then one reversible statement per database, and takes effect for NEW connections (a pooled connection keeps the value it
-- was opened with until it is recycled):
--     ALTER DATABASE <name> SET app.rls_fail_closed = 'on';      -- fail closed
--     ALTER DATABASE <name> RESET app.rls_fail_closed;           -- back to today's behaviour
-- The SELECT wrapper makes PostgreSQL evaluate the function once per query (an InitPlan) instead of once per row.
--
-- WHAT IT DOES NOT DO.
--  * It does not protect a connection that is a superuser or has BYPASSRLS: RLS does not apply to them at all (the default compose connects
--    as the bootstrap superuser). Only `aisoc_app` (step 5) is protected.
--  * It is not a security boundary against an attacker who can run arbitrary SQL: any session may SET a custom setting, exactly as it can
--    already set app.current_tenant_id to another tenant. RLS here is defence in depth against application bugs, not against SQL injection.
--  * It leaves the other branch of 12 policies alone (`OR tenant_id IS NULL`, shared rows): those stay visible to every tenant, and, with no
--    WITH CHECK, writable by any tenant. That is a separate, existing weakness (see the plan), not changed here.
--  * It does not touch the one policy that is already fail-closed (aisoc_shifts), nor any policy created by a later migration: the
--    pg_policies scan in tests/test_rls_fail_closed_switch_postgres.py fails if a new policy reintroduces an unswitched fail-open branch.
--
-- Idempotent: a policy that already mentions rls_fail_closed is skipped.

CREATE OR REPLACE FUNCTION rls_fail_closed() RETURNS boolean
LANGUAGE sql STABLE
AS $$ SELECT coalesce(current_setting('app.rls_fail_closed', true), '') IN ('on', 'true', '1') $$;

COMMENT ON FUNCTION rls_fail_closed() IS
  'True when fail-closed row-level security is switched on for this database (ALTER DATABASE ... SET app.rls_fail_closed = ''on''). Default off. See migration 081.';

DO $$
DECLARE
    p        record;
    old_frag constant text := '(current_tenant_id() IS NULL)';
    new_frag constant text := '((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed())))';
    rewritten integer := 0;
    leftover  integer;
BEGIN
    FOR p IN
        SELECT schemaname, tablename, policyname, qual
        FROM pg_policies
        WHERE schemaname = 'public'
          AND qual LIKE '%' || old_frag || '%'
          AND qual NOT LIKE '%rls_fail_closed%'
    LOOP
        EXECUTE format('ALTER POLICY %I ON %I.%I USING (%s)',
                       p.policyname, p.schemaname, p.tablename, replace(p.qual, old_frag, new_frag));
        rewritten := rewritten + 1;
    END LOOP;

    -- Nothing may be left with an UNSWITCHED fail-open branch (a shape this rewrite did not recognise would otherwise stay open unnoticed).
    SELECT count(*) INTO leftover
    FROM pg_policies
    WHERE schemaname = 'public'
      AND qual LIKE '%current_tenant_id() IS NULL%'
      AND qual NOT LIKE '%rls_fail_closed%';
    IF leftover > 0 THEN
        RAISE EXCEPTION '081: % policy(ies) still have an unswitched fail-open branch; refusing to continue', leftover;
    END IF;

    RAISE NOTICE '081: % policies now honour app.rls_fail_closed (default off: behaviour unchanged)', rewritten;
END
$$;
