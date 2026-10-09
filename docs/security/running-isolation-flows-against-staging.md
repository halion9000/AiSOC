# Running the tenant-isolation flows against a deployed environment

`python -m app.scripts.tenant_flows run-url` runs the two-tenant isolation flows against an API you deploy, over HTTP. It logs in as an admin of each of two tenants. Tenant A creates and changes things, tenant B probes them (B must get `404` or `403`, and B's lists must exclude A's objects), and a final sweep has B call every `GET` endpoint looking for ids A created that B never mentioned. About 375 steps in the default mode.

It checks **tenant isolation of the endpoints the flows cover**. It is not a penetration test, and a service that is not deployed or not reachable from the API is not tested through it.

## Use disposable tenants

The flows write real data into **both** tenants. Use two test tenants, not tenants with customer data.

**What it creates** (all by tenant A or B, in their own tenants): cases, alerts, saved views and hunts, API keys, assets, IOCs, feeds, report templates, remediation whitelist entries, identity-graph nodes, posture findings, detection rules, connectors, compliance evidence, knowledge-base documents, RBAC roles, parsers, phishing submissions, and users named `flow-*-<tag>@example.com`. `<tag>` is a random six-character tag generated for each run, which is why a second run does not collide with the first.

**What it removes afterwards:** the objects of the final `fresh` flow that have a delete route (cleanup runs *after* the leak sweep). Everything else stays; clean the two tenants up yourself if you need them pristine. `--no-cleanup` leaves even those.

**What it does not touch in the default mode.** The flows act on objects they created, with three exceptions that *replace or remove* configuration: the **whole business-context rule set**, the **whole tenant settings**, and a **marketplace install** of the catalogue's first item (the flow installs it and uninstalls it again, so a tenant that had installed that item for real would end up without it). Those three flows (`business_context_rules`, `tenant_settings`, `marketplace_installs`) are **skipped unless you pass `--include-destructive`**, which you should do only on tenants whose rules, settings and installs you can lose. The OAuth flow registers an app for a connector type named for the run (`flowtest-<tag>`), and the inbox flow acts only on tokens it minted and revokes them, so neither touches a real one.
*Checked on a live server:* with both tenants pre-populated with a rule set, settings, a `github` OAuth app and an inbox token, two default runs left all of it intact; `--include-destructive` replaced the rule set and settings, as intended. That covers those four kinds of configuration, not every resource type. (The marketplace flow is new and was verified in-process only, under both database roles.)

## Before you start

* **Two users who are plain tenant admins of two different tenants.** Not a `platform_admin`: with platform power the "cannot name another tenant" steps would fail for the wrong reason. The tool checks this, and checks that both hold the permissions the flows use, **before it writes anything**, and stops with a specific message otherwise.
* Tenant A must not already have a remediation whitelist entry for `isolate_host` at `low` blast radius, or the IOC `198.51.100.7`: their values are fixed by the API's enums and formats, so they cannot be made unique per run. If it does, you get a false `409` on that step, not data loss.
* The API's OpenAPI schema is served at `/api/openapi.json` outside production. If your deployment switches it off, generate it from the same commit and pass `--spec-file`:
  `python -c "import json; from app.main import app; print(json.dumps(app.openapi()))" > spec.json`
* Run it from `services/api` with the API's Python dependencies installed. It needs network access to the deployment only: no database settings, no `ENVIRONMENT`.

## Running it

```bash
export TENANT_FLOWS_PASSWORD_A='...'   # or one TENANT_FLOWS_PASSWORD for both
export TENANT_FLOWS_PASSWORD_B='...'
python -m app.scripts.tenant_flows run-url \
  --base-url https://staging.example.com --confirm-host staging.example.com \
  --email-a admin-a@staging.example --email-b admin-b@staging.example \
  --label staging1 --yes-write-test-data
```

Guards, all checked before any request: `--yes-write-test-data` is required; `--confirm-host` must repeat the host of `--base-url` (so a pasted wrong URL is refused); plain `http` is refused for a host that is not local unless `--allow-insecure-http`; the passwords must be set.

| Option | Meaning |
| --- | --- |
| `--include-destructive` | also run the three flows that replace or remove existing configuration (rule set, settings, a marketplace install) |
| `--no-cleanup` | leave the objects the `fresh` flow created |
| `--no-sweep` | skip the sweep that calls every `GET` endpoint as B |
| `--concurrency N` | parallel requests in the sweep (default 3) |
| `--timeout S` | seconds per request (default 30) |
| `--spec-file F` | the OpenAPI document, if the deployment does not serve it |
| `--out F` | result file (default `tenant_flows_<label>.json`) |

A request answered with `429` is waited out (using `Retry-After`, at most 30 seconds, otherwise 1, 2, 4 seconds) before it is judged. Any other status, `5xx` included, is judged as it is.

## Reading the result

| Exit code | Meaning |
| --- | --- |
| `0` | every step was as expected |
| `1` | at least one step was not as expected: **read it**, it may be a leak |
| `2` | a setup problem (a guard, the preflight, a login); nothing was written |

Each row not as expected shows the flow, the step, the user, the status and the start of the response. A step reported `SKIP` needs an id an earlier step did not produce: look at the *first* failure of that flow, the skips are its consequence. `SWEEP` lists any id of A's that B's `GET` calls returned. `CLEANUP` rows are the deletions at the end. Compare two runs with `python -m app.scripts.tenant_flows compare a.json b.json`.

**If a step fails on staging but not on a scratch database, check these first** (none of them is an isolation failure):
* a precondition above (the whitelist entry, the IOC);
* a service the API proxies to that is running there but was not where the flows were calibrated: some own-tenant steps accept `503` (upstream not configured) *or* `200`, others expect one;
* rate limiting beyond what `429` handling absorbs (lower `--concurrency`);
* a role or permission that the preflight could not see.

## How it was verified

Against a live server over real HTTP: the 386 steps matched the in-process run step for step; every guard refused before a request; each preflight defect (same tenant, platform admin, viewer, wrong password) stopped with nothing written; three consecutive runs against one environment each passed in full; cleanup deleted the `fresh` objects; the pre-existing-configuration check above. The `429` handling and the failure paths are covered by unit tests only, since the test server never rate-limits. It has **not** been run against a remote host over `https` or against a deployment with the optional services running.
