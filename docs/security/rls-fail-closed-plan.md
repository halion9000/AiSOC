# Making row-level security fail-closed: what was measured, what breaks, and the order to do it in

Status: **a plan with measurements, not a change.** Nothing here has been deployed. Every number below was measured on a scratch PostgreSQL as the restricted role `aisoc_app`, using the repository's own isolation flows (`python -m app.scripts.tenant_flows run`, 435 steps over two tenants), unless it says otherwise.

## Where things stand

- **77 policies are fail-open.** Their `USING` expression ends in `OR current_tenant_id() IS NULL`, so a session that never set a tenant sees every row. Three shapes: 63 of `tenant_id = current_tenant_id() OR current_tenant_id() IS NULL`; 12 that also allow `OR tenant_id IS NULL` (shared rows); 2 that go through a `role_id` subquery.
- **One policy is already fail-closed** (it coalesces an unset tenant to the all-zero UUID and has a `WITH CHECK`). It is the in-house template for the change.
- 33 RLS tables use `FORCE ROW LEVEL SECURITY`, 45 do not (so the owner bypasses them).
- **RLS only protects a connection that is not a superuser.** The default compose connects every service as the bootstrap superuser `aisoc`, which bypasses all of it. `docker-compose.rls.yml` moves only `actions` and `agents` to `aisoc_app`; it says the API "is deliberately NOT switched yet", but the API can already be run that way (`DATABASE_URL` = `aisoc_app`, `MIGRATION_DATABASE_URL` = the owner), which is how the flows below were run. Making the policies fail-closed changes nothing for a deployment that connects as the superuser.
- Of the other services' tables, only `response_actions` is in the API's RLS-covered schema (and `actions` already runs as `aisoc_app`). The tables of `osquery-tls`, `honeytokens`, `ueba` and `purple-team` do not exist in that schema.

## What was measured

| Experiment | Result |
| --- | --- |
| Flip all 77 policies to fail-closed, nothing else | **251 of 404** flow steps fail. Writes fail with `new row violates row-level security policy` (a 503); reads return empty lists with a 200. |
| Same, plus a central hook (below) | **0 of 435** fail |
| The hook alone, on today's policies | **0 of 435** fail |

**Why the first one breaks.** A plain `get_db` session never sets a tenant. `get_tenant_db` sets one with `SET LOCAL`, which lasts for the first transaction only: after a handler's `commit()` the next statement runs with no tenant (for example `Could not refresh instance` after a create).

**The hook.** `get_current_user` and `get_tenant_db` tag the session with the caller's tenant (`session.info`), and a SQLAlchemy `after_begin` listener re-applies `set_config('app.current_tenant_id', …, true)` at the start of **every** transaction, so it survives a mid-request commit.

## The finding that stops the hook from going out alone

The flows have two ordinary tenants. They have no managed (parent/child) tenant, so they cannot see **cross-tenant reads on a `get_db` session, which depend on the fail-open behaviour**.

`app/services/mssp_rule_resolver.py` builds a managed tenant's effective rules, including rules owned by the **parent** and assigned through packs. It is reached from at least `POST /rules/hunt` (`detection_rules.hunt`, which uses `get_db`) and `GET /mssp/children/{id}/effective-rules` (`get_db`); the sibling `GET /mssp/children/{id}/effective-rules/count` was not examined. Measured by creating a parent, a child, a parent-owned rule, a pack and an assignment, then calling the real resolver as `aisoc_app`:

| Session state | Effective rules returned for the child |
| --- | --- |
| No tenant set (what a `get_db` session is today) | the parent's pack rule |
| Tenant set to the **child** (what the hook does when a child calls `/rules/hunt`) | **nothing** |
| Tenant set to the **parent** (what the hook does for the MSSP route) | the pack rule (the child's own rules would be hidden) |

So the hook alone would make a managed tenant's hunt **silently run without the rules its MSSP parent assigned**. The same applies to fail-closed policies.

Not affected: the tables the MSSP overview routes aggregate across children (`mssp_tenant_metrics`, `mssp_rule_overrides`, `tenants`) have **no RLS**.

Not verified, and must be checked before the hook goes out: `app/api/v1/endpoints/nl_query.py`, `app/services/view_as.py` and any other reader of another tenant's RLS-covered rows on a `get_db` session.

**A correction to my own prediction.** I expected platform built-in rules (`tenant_id IS NULL AND is_builtin`) to disappear too. They cannot: `detection_rules.tenant_id` is `NOT NULL`, so that layer of the resolver matches nothing.

## Code paths with no signed-in user (they need an explicit mechanism)

`audit_middleware` (writes from its own session; the tenant is known from the token), the `oauth_refresh` and `weekly_digest` workers (cross-tenant sweeps), login, SSO, public signup and webhook ingestion. The hunt scheduler was the one that used `SET LOCAL row_security = off`, which fails for a non-superuser; that is fixed (`17c6f71c`), but the sweep still relies on a tenant-less session seeing every tenant, which fail-closed policies would remove.

## Proposed order

1. **A tripwire first.** Add a managed-tenant scenario (parent, child, pack, assignment, an effective-rules call as child and as parent) to the isolation flows, so that every later step fails loudly when it breaks this.
2. **An explicit, narrow cross-tenant read mechanism**: a context manager that clears (later: bypasses) the tenant for a named set of reads, used by the resolver and any other deliberate cross-tenant reader found in the check above. Today it can clear the GUC; with fail-closed policies it needs a role or setting that is granted, never default.
3. **The hook, behind a flag that defaults off**, then on, verified by the flows including step 1.
4. **Policies to fail-closed**, using the existing fail-closed policy as the template, with a bypass for workers and platform operations (step 2).
5. **Make the API connect as `aisoc_app` by default** (the overlay's stated direction). Until then, none of this protects the default deployment.

Each step is independently reversible; steps 1 and 2 change no behaviour. **Not started: it needs a decision, because it touches login, the workers and every deployment's database role.**
