# Viewing another tenant ("view as")

The console's tenant switcher used to store the chosen tenant and send it as `X-Tenant-Id`, which the API never read. An MSSP operator who "switched" to a customer kept seeing their **own** data under the customer's name. The API now honours an explicit header, for the people entitled to, **read-only**.

## The rule

Send `X-View-As-Tenant: <tenant id>` on a request made with a signed-in session (not an API key).

| Caller | May view |
| --- | --- |
| anyone | their own tenant (naming it changes nothing) |
| a holder of `platform:cross_tenant_query` (platform admin) | any tenant |
| anyone | a tenant they have been **granted** (read-only; see "Granting access") |
| anyone else | nothing else. In particular, belonging to an MSSP's parent tenant confers **nothing** over its child tenants by itself |

`GET /api/v1/tenants/viewable` lists exactly what the server will honour (the caller's tenant first, then the rest) and the caller's `home_tenant_id`. It is built from the same rule as the check, so a client can only offer what will work.

While viewing, the request acts as the caller's own role, on the viewed tenant: every query and the row-level-security context follow it. Viewing confers no power the caller lacks (an operator viewing a customer still does not hold the platform permissions).

## Refusals (the header is never silently ignored)

Each refusal carries `X-View-As-Error`:

| Status | `X-View-As-Error` | When |
| --- | --- | --- |
| 400 | `invalid` | the value is not a tenant id |
| 403 | `forbidden` | the caller may not view that tenant, **or it does not exist** (the same answer, so it cannot be used to find out which tenants exist) |
| 403 | `read_only` | any method other than GET, HEAD, OPTIONS, for a tenant the caller *may* view |
| 403 | `session_only` | an API key sent the header |

A write to a tenant the caller may not view is `forbidden`, not `read_only`, so the answer reveals nothing. An empty or whitespace-only header counts as absent.

A response that was served for a viewed tenant carries `X-Viewing-Tenant: <id>`.

**Account-level routes ignore the header** and always act as the signed-in person: `/api/v1/auth/*`, `/api/v1/push/*`, `/api/v1/passkeys/*` and `/api/v1/tenants/viewable` (a person must be able to sign out, and the tenant list must not change when they switch).

## Auditing

The audit middleware records only **writes**, under the caller's **home** tenant, so reads of a viewed tenant would otherwise leave no record anywhere, and the customer could never learn that an operator looked at their data. So a view writes a `tenant:viewed` event into the **viewed** tenant's own hash-chained audit log, naming the person, their email, their home tenant and role. It is written once per person per viewed tenant per 15 minutes (a screen makes dozens of reads); the check is a query, so it holds across workers and restarts. **If the event cannot be written, the view is not served.**

A refused write is audited by the middleware as any refused write is (status 403, in the caller's home tenant).

## Granting access

A person belongs to one tenant but may be **granted** read-only access to others (an MSP's technician at a customer, a consultant at several clients). Grants are rows in `tenant_access_grants` (migration 072), one per person and tenant, and are checked against the database on **every request**, so a revocation takes effect on the person's very next request.

| Endpoint | What |
| --- | --- |
| `GET /api/v1/tenants/{tenant_id}/access` | who has been granted access to this tenant (their account name, email if any, and the tenant they belong to) |
| `PUT /api/v1/tenants/{tenant_id}/access/{account_name}` | grant that person read-only access (idempotent) |
| `DELETE /api/v1/tenants/{tenant_id}/access/{account_name}` | revoke it (204) |

**Who may grant, revoke and list** (`may_manage_access`): a holder of the platform-wide cross-tenant permission (any tenant); or a holder of `users:write` whose **home** tenant is the tenant concerned (a customer's administrators decide who may see their data) **or its parent** (an MSP's administrators decide which of their own staff may see which customers). A child tenant's administrators cannot manage their parent, and a role that can read users but not write them (`soc_lead`) cannot grant or list. Someone who may not manage a tenant gets the **same 404 "Tenant not found"** as for a tenant that does not exist. A request made from inside a view of another tenant is a write and is refused (`read_only`), so nobody can grant while viewing.

A grant is refused (422) for a person who already belongs to that tenant, or whose account is deactivated; an unknown account name is a 404. Every grant and every revocation is written to the **target tenant's own** hash-chained audit log (`tenant:access_granted`, `tenant:access_revoked`: who, whom, and where they come from), and each view still writes `tenant:viewed` there.

**This replaced a blanket rule.** Until migration 072, every user of an MSSP parent tenant (even a `viewer`) could view **all** of its child tenants through `mssp:read`. That rule is gone. Existing deployments start with **no grants**, so an MSP's staff lose their view of customers until it is granted, deliberately. People with the platform-wide permission are unaffected.

## What this does not do

* **Live updates.** The realtime push feed still follows the person's home tenant while viewing. Not changed.
* **Pages that render on the server** (the cases page) do not follow the switcher; see "The console".
* **Reads that write.** The rule is "read-only by HTTP method". A GET handler that creates something as a side effect (for example a default row) would still do so in the viewed tenant. I did not audit the codebase for such handlers.
* **Grants are read-only.** A grant gives the same read-only view as above. Write access to another tenant is a separate, larger decision and is not built; the table has an `access` column (only `view` today) so it can be added without a new table.
* **Tokens and API keys** are unchanged: a token is for the person's own tenant, and an API key may not view another tenant.

## The console

* **One place sends the header.** `authFetch` (`apps/web/src/lib/auth-session.ts`), which already attaches the login token to every same-origin `/api/*` call, adds `X-View-As-Tenant` while a tenant is being viewed, except on the account-level routes. The state lives in `apps/web/src/lib/tenant-view.ts` (no imports, so both `authFetch` and the API client can use it). The storage key is unchanged (`aisoc.activeTenantId`), so a choice made before the upgrade is still honoured; `X-Tenant-Id` is still sent but has never been read by the API.
* **The switcher offers only what the server honours.** `TenantProvider` reads `GET /tenants/viewable` (it no longer combines `/tenants/me/identity` with `/mssp/children`). Choosing your own tenant clears the view rather than storing it.
* **A banner on every page** says "Viewing <tenant>. Read-only…" with a "Return to <your tenant>" button (`TenantViewBanner`, mounted in `AppShell`).
* **A refused write explains itself.** The API's `read_only` sentence becomes the `ApiError` message (and `ApiError.viewAsError` carries the code), instead of "API 403 Forbidden".
* **A stale choice is never kept or hidden.** If the API refuses the view (`forbidden`/`invalid`), `authFetch` clears the choice and reloads onto the person's own tenant; a read-only refusal does not (it is an error for that action, not a reason to leave the view). If the stored choice is not in the server's list, the provider does the same. If the list cannot be read at all while a view is stored, the console says "Viewing Another tenant" and offers the way back; it never claims "your own tenant" while requests still carry the view.
* **Not covered.** The cases page is a server component (it renders on the server with the build-time tenant, where neither browser storage nor the switcher exists), so it does not follow the switcher. Public and static fetches (`safeFetcher`, the benchmark and replay pages) are not tenant-scoped. Switching reloads the page, as before.

## Deploying

Deploy the API first. A console that still sends `X-Tenant-Id` keeps working exactly as before (the API ignores it); only a request that sends `X-View-As-Tenant` is affected. **Do not ship the console before the API.** A new console against an old API cannot read `/tenants/viewable` (404). With no stored choice it simply behaves as before. But a choice stored by the OLD switcher is still honoured (the storage key is unchanged on purpose): the console then shows the banner and sends `X-View-As-Tenant`, which the old API ignores, so the screen would claim a view the data does not reflect: the original bug. With the API deployed first this cannot happen. A stored choice left over from the old switcher is, after the upgrade, a real read-only view: the person lands on it with the banner and can leave it with one click. The isolation flows (`docs/security/running-isolation-flows-against-staging.md`) now include a `view_as_isolation` flow and their preflight refuses two test tenants where one may view the other.

## Verified

Unit tests against a real database with an MSSP parent, two children, an unrelated tenant and a platform tenant (every caller against every tenant: the list offers a tenant if and only if viewing it is honoured; plus the full who-may-grant matrix). On real Postgres, as the non-superuser role with row-level security enforced: an operator viewing a child reads that child's protected rows, a write is refused, an unrelated tenant and a made-up tenant get the same answer, and the audit event lands in the viewed tenant's log once, hash-chained, and not in the viewer's own log.
