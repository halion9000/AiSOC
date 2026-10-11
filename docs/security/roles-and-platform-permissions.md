# Roles and platform permissions

AiSOC separates what a person may do **inside their own tenant** from what acts on **the whole platform** (every tenant).

## The roles

| Role | What it is |
| --- | --- |
| `platform_admin` | The operator of the platform. Everything an `admin` has, **plus** the platform permissions below. |
| `admin` | A tenant's own administrator. Every tenant-level permission (the `*` wildcard) but **no platform permission**. |
| `tenant_admin` | What a newly provisioned tenant's first administrator receives. A fixed list of tenant-level permissions. |
| `soc_lead`, `soc_analyst`, `threat_hunter`, `viewer`, `api_service` | Narrower tenant-level roles. |

## Reading hunts without being able to query: `hunts:read`

`lake:query` is one permission for everything hunting does: creating, running and deleting hunts and saved hunts, and running arbitrary queries against telemetry. `hunts:read` is its read half, for exactly five routes: `GET /hunts`, `GET /hunts/{id}`, `GET /saved-hunts`, `GET /saved-hunts/{id}` and `GET /hunt/saved` (the hunt hypotheses with their queries and the analysts' findings, saved hunts, saved searches).

* **Nobody loses anything.** `lake:query` implies `hunts:read` (in `permission_in`, which every check goes through: role maps, database roles and API-key scopes, including a `lake:*` wildcard), so every role that could read hunts still can, and no role was given anything new.
* **It grants nothing else.** A principal holding only `hunts:read` can use those five routes and no others anywhere in the API (a test checks this over every route). It is what lets an integration, or a read-only custom role, see which hunts exist without being able to run a query.
* **What a hunt found stays behind `lake:query`.** `GET /hunts/{id}/runs` returns `result_sample`, event rows sampled from the data lake, so it is telemetry and not a definition.
* A key can be issued with the scope `hunts:read` (`POST /api-keys`); a custom role can be given the permission (migration `075` adds it to the catalog; it backfills nothing).


## Reading threat intelligence without the feeds or enrichment: `intel:read`

`threat_intel:read` guards more than reading the stored intelligence: the feed list (`GET /threat-intel/feeds`, whose free-form `config` can hold credentials) and the enrichment routes (`GET /enrichment/lookup`, `POST /enrichment/bulk`, which send an indicator to outside providers), plus the TAXII collection list and MISP health. So nothing that should only *read* intelligence (an AI agent's API key, an integration) could be given it without those. `intel:read` is the read half:

| Route | Needs |
| --- | --- |
| `GET /threat-intel/iocs`, `GET /threat-intel/iocs/{id}`, `GET /threat-intel/actors` | `intel:read` |
| `GET /threatintel/stix/indicators`, `GET /threatintel/stix/bundles` | `intel:read` |
| the feed list, `GET /enrichment/lookup`, `POST /enrichment/bulk`, the TAXII collections, MISP health | `threat_intel:read` |
| everything that adds, changes, deletes or publishes | `threat_intel:write` |

* **Nobody loses anything.** `threat_intel:read` implies `intel:read` (in `permission_in`, which every check goes through: role maps, database roles and API-key scopes, including a `threat_intel:*` wildcard); the implication runs one way only. All eight standard roles hold `threat_intel:read`, so all of them hold `intel:read` and still reach every route above.
* **It grants nothing else.** A principal holding only `intel:read` can use the five routes in the first two rows and no others anywhere in the API (a test checks this over every route).
* A key can be issued with the scope `intel:read` (`POST /api-keys`); a custom role can be given the permission (migration `076` adds it to the catalog; it backfills nothing). CORE's integration key holds `intel:read` and not `threat_intel:read`; the bootstrap updates an existing key in place (same secret) and logs `scopes-updated`.


## Triaging alerts without the rest of `alerts:write`: `alerts:triage`

`alerts:write` guards 29 routes: claiming, escalating and snoozing an alert, but also submitting and patching alerts, creating assets, adding cloud posture findings, creating identity graph nodes, adding insider-threat indicators and changing an employee profile's watchlist, graph entities, honeytokens, feedback and phishing re-triage. So an integration that only needs to triage (CORE's agent) could not be given it without all of that. `alerts:triage` is exactly three routes:

| Route | Needs |
| --- | --- |
| `POST /alerts/{id}/claim`, `POST /alerts/{id}/escalate`, `POST /alerts/{id}/snooze` | `alerts:triage` |
| `POST /alerts/submit`, `PATCH /alerts/{id}` and the 24 other routes listed above | `alerts:write` |

* **Nobody loses anything.** `alerts:write` implies `alerts:triage` (in `permission_in`, which every check goes through: role maps, database roles and API-key scopes, including an `alerts:*` wildcard); the implication runs one way only. Six of the eight standard roles hold `alerts:write` and so triage exactly as before; `threat_hunter` and `viewer` hold neither, as before.
* **It grants nothing else.** A principal holding only `alerts:triage` can use those three routes and no others anywhere in the API (a test checks this over every route).
* A key can be issued with the scope `alerts:triage` (`POST /api-keys`); a custom role can be given the permission (migration `077` adds it to the catalog; it backfills nothing). CORE's integration key holds `alerts:triage` and not `alerts:write`; the bootstrap updates an existing key in place (same secret) and logs `scopes-updated`, naming both the scope it adds and the one it removes.


## Reading detection rules without being able to backtest: `rules:view`

`rules:read` guards 18 routes: 13 plain reads and 5 that compute. Three of the five only evaluate events the *caller* sends (`POST /rules/hunt`, `POST /rules/{id}/execute`, `POST /detection/test`), one translates a rule (`POST /translation/translate`), and one, **`POST /rules/{id}/backtest`, runs a rule over up to 365 days of the tenant's real events in the data lake and returns `sample_matches`, the matching event rows**: that is reading telemetry, which `lake:query` gates. So nothing that should only *read* the rules (an AI agent's API key) could be given `rules:read` without being able to read lake telemetry. `rules:view` is the read half:

| Route | Needs |
| --- | --- |
| `GET /rules`, `GET /rules/{id}`, `GET /detection/rules`, `GET /detection/rules/{id}` | `rules:view` |
| `GET /detection/coverage`, `/detection/drift`, `/detection/confidence`, `/detection/tuning`, `/detection/tuning/summary` | `rules:view` |
| `GET /detection-proposals`, `/detection-proposals/baselines`, `/detection-proposals/{id}`, `GET /translation/formats` | `rules:view` |
| `POST /rules/hunt`, `/rules/{id}/execute`, `/rules/{id}/backtest`, `/detection/test`, `/translation/translate` | `rules:read` |
| everything that creates, changes or deletes a rule | `rules:write` |

* **Nobody loses anything.** `rules:read` implies `rules:view` (in `permission_in`, which every check goes through: role maps, database roles and API-key scopes, including a `rules:*` wildcard); the implication runs one way only. `admin`, `tenant_admin`, `platform_admin`, `soc_lead` and `threat_hunter` hold `rules:read` and so read rules exactly as before; `soc_analyst`, `viewer` and `api_service` hold neither, as before.
* **It grants nothing else.** A principal holding only `rules:view` can use the 13 reads and no other route anywhere in the API (a test checks this over every route).
* The GraphQL `detectionRules` field mirrors `GET /rules`, so it needs `rules:view` too (a test pins that parity).
* A key can be issued with the scope `rules:view` (`POST /api-keys`); a custom role can be given the permission (migration `078` adds it to the catalog; it backfills nothing). CORE's integration key holds `rules:view` and not `rules:read`; the bootstrap updates an existing key in place (same secret) and logs `scopes-updated`.


## Listing connectors without being able to search them: `connectors:view`

`connectors:read` guards 11 routes. Five list connectors; the other six are `POST /federated/search`, which runs a free-text or indicator query across the tenant's connected SIEMs with their stored credentials and returns the merged rows (telemetry from the customer's own systems), `GET /federated/backends`, `GET /agents/tools`, the inbox template and token lists and the OAuth app view. So nothing that should only *see* which connectors exist and whether they are healthy (an AI agent's API key) could be given `connectors:read` without being able to search the customer's SIEM. `connectors:view` is the read half:

| Route | Needs |
| --- | --- |
| `GET /connectors`, `GET /connectors/catalog`, `GET /connectors/health`, `GET /connectors/{id}`, `GET /connectors/{id}/last_event_at` | `connectors:view` |
| `POST /federated/search`, `GET /federated/backends`, `GET /agents/tools`, `GET /inbox/templates`, `GET /inbox/tokens`, `GET /oauth/app/{connector_type}` | `connectors:read` |
| everything that creates, changes or deletes a connector | `connectors:write` / `connectors:delete` |

* **Nobody loses anything.** `connectors:read` implies `connectors:view` (in `permission_in`, which every check goes through: role maps, database roles and API-key scopes, including a `connectors:*` wildcard); the implication runs one way only. `platform_admin`, `admin`, `tenant_admin`, `soc_lead` and `soc_analyst` hold `connectors:read` and list connectors exactly as before; `threat_hunter`, `viewer` and `api_service` hold neither, as before.
* **It grants nothing else.** A principal holding only `connectors:view` can use those five reads and no other route anywhere in the API (a test checks this over every route).
* The GraphQL `connectors` field mirrors `GET /connectors`, so it needs `connectors:view` too (a test pins that parity).
* A key can be issued with the scope `connectors:view` (`POST /api-keys`); a custom role can be given the permission (migration `079` adds it to the catalog; it backfills nothing). CORE's integration key holds `connectors:view` and not `connectors:read`; the bootstrap updates an existing key in place (same secret) and logs `scopes-updated`.

## Platform permissions

These act on every tenant, so neither the `*` wildcard nor a resource wildcard such as `plugins:*` grants them. A principal holds one only if it is **named exactly**: in a role (only `platform_admin` lists them), in an API key's scopes, or in a database role.

| Permission | What it allows |
| --- | --- |
| `plugins:admin` | Enable, disable, reload, unload and discover plugins in the shared plugin registry, and approve or reject community plugin submissions. (Installing a community plugin into your own tenant needs only `settings:write`.) |
| `mssp:onboard` | Onboard a new tenant, including reading and updating the platform's waitlist of prospects (`GET`/`PATCH /waitlist/entries`) and promoting an entry into a live managed tenant (`POST /admin/tenants/provision`). |
| `platform:cross_tenant_query` | See across tenants: list every tenant (`GET /admin/tenants`) and, reserved for it, search across tenants. |

## Who holds platform power by default

The **original primary administrator**, and nobody else:

* a new install: `bootstrap_production` creates the primary administrator as `platform_admin`;
* an existing install: migration `067` promotes the earliest-created **active** `admin` user, and only if no `platform_admin` exists yet (it skips a disabled account, such as the seeded `admin@aisoc.local` that bootstrap disables, and never overrides a deliberate choice).

Everyone else stays as they were. Nobody gains power they did not already have in practice, because `admin` used to hold `*`.

## Giving it to someone, or taking it away

From the command line, with database access:

```bash
python -m app.scripts.platform_admin list
python -m app.scripts.platform_admin grant  --name hal.liveoak            # the account name they sign in with (or --email person@example.com)
python -m app.scripts.platform_admin revoke --name hal.liveoak [--to-role tenant_admin] [--force]
```

Revoking the **last active** `platform_admin` is refused unless you pass `--force`, because nobody could then administer the platform.

From inside the product, an existing `platform_admin` can set a user's role to `platform_admin` with `PATCH /api/v1/tenants/me/users/{id}` (users of their own tenant).

## Rules the API enforces

* **Nobody can grant more power than they hold.** A role can be assigned only if the assigner holds every permission in it; an API key can carry only scopes its creator holds (a wildcard key needs a wildcard; a platform scope needs that exact permission, and a wildcard key never carries platform permissions); a database role can contain, and be assigned with, only permissions the caller holds.
* **Nobody changes their own role**, and nobody edits a user whose role grants more than their own.
* An unknown role name is refused.

## After you upgrade: checklist

1. Apply migrations through `067` (the API does this on start).
2. Run `python -m app.scripts.platform_admin list` and confirm the right person holds platform power. If migration 067 chose someone else, `grant` the right person and `revoke` the other.
3. A person's session reflects a role change on their next request.
4. Until step 2 is right, plugin management and tenant onboarding are unavailable to everyone but the listed platform administrators.

### Check for past abuse

Before this release, any user holding `users:write` (including a `tenant_admin`, and any API key with that scope) could create a `platform_admin` or `admin` user, or promote themselves, and could mint API keys with scopes they did not hold. Review who holds the powerful roles and whether you recognise each of them:

```sql
SELECT email, role, tenant_id, created_at FROM users WHERE role IN ('platform_admin', 'admin') ORDER BY created_at;
SELECT name, user_id, scopes, created_at FROM api_keys WHERE scopes ?| ARRAY['*', 'plugins:admin'] ORDER BY created_at;
```
