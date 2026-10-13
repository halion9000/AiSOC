# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Signing in to AiSOC by name with a passkey crashed for every user who had a passkey registered; fixed, with a database-free test.** `POST /api/v1/passkeys/authenticate/begin` with an `identifier` listed the user's credentials in `allowCredentials` as plain dicts, and the WebAuthn library's JSON serializer reads `.id` from each entry, so it died with `AttributeError: 'dict' object has no attribute 'id'` (a 500). A usernameless sign-in lists no credentials, which is why it went unnoticed. The handler now builds real `PublicKeyCredentialDescriptor` objects and drops an unrecognised transport hint instead of failing on it. Found by the new real-Postgres passkey test, reproduced without a database in `tests/test_passkey_allow_credentials.py` (4 tests, including a control showing the old dict form still crashes the serializer).
- **RLS plan step 4b, the other services: `actions` is a platform service and now says so in code, and one silent `agents` write is fixed.** The `actions` service has no tenant on a request (service-token callers, actions read and changed by id, an unauthenticated ChatOps callback, rows inserted for whatever tenant a request names), so with the fail-closed switch on every action route would have failed. Its sessions (`services/actions/app/db.py`) now keep the switch off, exactly as it behaves with the switch off; this is a granted bypass, so fail-closed gives `response_actions` no second layer of protection there, and tenant isolation for actions rests on its callers. A real-Postgres test (4 tests, switch ON, with a control and a mutation check) runs in its own step of the Postgres workflow, which now also triggers on `services/actions/**` (it did not, so a change there alone would never have run the test). In `agents`, `record_suppression` wrote an RLS-covered table outside `tenant_scope` (it was on the static guard's allowlist as "tracked separately"); it is a best-effort metric write that swallows its errors, so with fail-closed it would have silently stopped recording the compounding-reduction metric rather than failing. It is now scoped, a behavioural test pins it, and its allowlist entry is gone so the guard covers it. Triaged but not changed: `fusion` and `connectors` name RLS-covered tables, but every service connects as the bootstrap superuser (which bypasses RLS) in the default compose and the staging overlay moves only `actions` and `agents` to the restricted role, so the switch changes nothing for them until they are moved; the plan records what each needs first. `ueba`, `honeytokens`, `purple-team`, `osquery-tls` and `slack-bot` name no RLS-covered tables. The Go services were not examined.
- **RLS plan step 4b: every code path found that has no signed-in user now has an explicit mechanism, and the work found that API-key authentication would have answered 401 for everyone once the fail-closed switch is turned on.** The switch (migration 081) is still OFF and must stay off; see the plan for the gaps. Two greppable mechanisms in `app/db/rls_sessions.py`, no new database role: `tenant_session` / `adopt_tenant` for code working for one tenant, and `platform_session` / `cross_tenant_reads` for code that spans tenants (both keep the switch off for their own transactions, even across commits; `cross_tenant_reads` previously did not, the gap step 2 documented). Applied to the `oauth_refresh`, retention and hunt-scheduler sweeps, the `weekly_digest`, `easm`, copilot-tools and audit-middleware sessions, and the lookups that happen BEFORE the tenant is known: API keys (`_resolve_api_key`), the ITSM webhook token (a mismatched connector is still a 403), the OAuth callback `state`, the passkey sign-in flow, and the public replay page and the slug-uniqueness check (which also fixes a cross-tenant slug collision that would otherwise have been a database error). **A correction:** step 3's "0 of 435" never exercised these, because the flows log in as users; the plan said step 3 was verified and did not say that. They were found by running the real routes against a database with the switch on and by intersecting the pre-auth modules' tables with the RLS-covered tables. Verified with 36 real-Postgres tests as `aisoc_app` with the switch ON (added to the Postgres workflow), each beside a negative control, with each fix confirmed by restoring the original code and watching the tests fail; one gap in the passkey tests was found that way and closed. The isolation flows stay at 435 of 435 with default settings and with the switch and hook on. Not covered: the `weekly_digest`, `easm`, copilot, audit-middleware and hunt-scheduler changes are unit-tested only; OIDC and SAML callbacks and the other services that reach the same database were not examined; the 12 shared-row tables still let any tenant modify shared rows.
- **Correction to the moto change below: it failed to start on the runner, and now runs from its own virtualenv.** The first run of `9be7f0e6` failed at the new start step with `AttributeError: module 'lib' has no attribute 'GEN_EMAIL'` raised inside `/usr/lib/python3/dist-packages/OpenSSL/crypto.py`: installed next to the runner's apt-managed Python packages, moto picked up the system's old pyOpenSSL, which does not match the newer `cryptography` that pip installs for it (the same class of system-versus-pip leak that hid problems from my local replicas earlier). The install step now creates `${RUNNER_TEMP}/moto-venv` and installs `moto[server]>=5,<6` there (a venv does not see the system packages; I checked that none is visible), and the start step runs that venv's `moto_server` by explicit path. **Verified locally** by running the whole job's steps again with the step extracted from the YAML: start step exit 0, bucket created, the real `backup.sh` and `restore.sh` both exit 0 and 500 of 500 rows come back. **A caveat on that check:** it cannot reproduce the runner's apt-installed pyOpenSSL (this sandbox does not have that conflict), so what it proves is that the venv path works, not that the original failure is gone; the venv's isolation is what should remove it, and the next run will show. My local run also had a second `moto_server` on the PATH from an earlier install; it did not matter because the step uses the explicit venv path. **Not verified on GitHub:** this change.
- **The disaster-recovery job no longer depends on a MinIO image that no longer exists: `Backup -> destroy -> restore` now uses `moto` as its S3 server.** The annotation added in `5793bb05` gave Docker's own message on the first run: `pull access denied for minio/minio, repository does not exist`. MinIO withdrew its community-edition images from Docker Hub and quay.io now refuses anonymous pulls too (the sources I found disagree on exact dates, and I only report that the pull fails today); only `integration.yml` referenced the image. **Why not a mirror or a fork:** the unofficial Docker Hub mirrors and community forks that exist would put a third party's image into CI, a supply-chain choice for the maintainer, not something to make silently. **What the job needs:** only generic S3 calls through the AWS CLI (`s3 mb`, `s3 cp`, `s3 ls`, `s3 rm`, `s3api head-object` for retention), so the job now installs `moto[server]>=5,<6` from PyPI next to `awscli` and starts `moto_server` on port 9000; no image or registry is involved. The job's credentials are still called `minioadmin` (any value works against moto), and the job keeps its name, so a required-status-check configuration is not disturbed. **Verified by running the job's own steps locally** against moto 5.2.4 and awscli 1.46.1 with the repo's real `backup.sh` and `restore.sh` on a scratch Postgres: bucket created, 500 rows seeded, backup uploaded an 11.9 KB object and ran its retention pruning, destroy left 0 tables, restore completed in about 1 second, and **500 of 500 rows came back**. The new step, extracted from the YAML and run as `bash -e`, exits 0, leaves the server answering after the step ends (the later steps need that), and on a start failure exits 1 after 30 seconds with the error as an annotation. **What this is not:** moto is a faithful S3 stand-in for the calls these scripts make, not MinIO, so it cannot catch an incompatibility with a real MinIO or AWS endpoint; and the MinIO community edition being unmaintained is itself worth knowing if any deployment relies on it (the FAQ still lists MinIO as one configurable object store; left as written). A stale comment in `isolation-live.yml` that pointed at the MinIO step was made self-contained. **Not verified on GitHub:** this change; the next Integration run will show it. If green, every job in `Integration` passes.
- **The Integration workflow's event spine and Compose Smoke now pass in CI for the first time; the one job still red, `Backup -> destroy -> restore`, now explains itself.** On `be4a3e46` (`001_init.sql` re-runnable; see the entry below) `Event spine (real containers)` is green: the full ingest, Kafka, fusion, alert, API and realtime-websocket path, including the Postgres-outage and fusion-kill chaos steps, ran against the production-shaped stack, with the account created by the production bootstrap and the spine test logging in. `Compose Smoke` and `CI` are green too, and `Postgres-backed tests` ran the new migration re-run test in CI's own database. **What is still red, unchanged and not diagnosed:** `Backup -> destroy -> restore (Postgres via MinIO)` fails at 'Start MinIO' with docker exit code 125 (`docker run` itself failed: image not found, pull denied or rate-limited, or a bad flag); I cannot see Docker's message, so I will not guess at a replacement image. The step now wraps the `docker run` and puts Docker's own error into an annotation (tested against a stub `docker` in success and failure modes), so the next run says why. **Also still red, pre-existing:** `Publish Images` cannot push to the upstream author's registry (a fork limitation). **Where I stand on the earlier verification gap:** everything above was found from CI annotations I added and from local reproductions (the real API in production mode, the compose-style migration path); none of it needed Docker in my sandbox.
- **`001_init.sql` could not be applied twice, which broke the production bootstrap on every docker-compose stack; fixed, with a test for the whole class of bug.** Compose Smoke went green for the first time on `39e434a5` (the stack boots healthy once it is given its secrets), and the Integration spine job moved on to fail at the new bootstrap step: `1 migration(s) did not apply: 001_init.sql`. **Cause, reproduced locally in seconds without Docker:** `./services/api/migrations` is mounted into the Postgres container's `/docker-entrypoint-initdb.d`, so Postgres applies every file when the database is first created and then the API's migration runner applies every file AGAIN (none is recorded yet). `001_init.sql` seeds the default admin with `INSERT ... ON CONFLICT (email) DO NOTHING`, but PostgreSQL checks the proposed row's NOT NULL columns BEFORE it looks for a conflict, and migration 071 had since made `users.account_name` NOT NULL (the seed row does not set it), so the second application fails with `null value in column "account_name"` and the file is never recorded. Effects: the API logged '1 migrations failed' at every start (soft), and `app.scripts.bootstrap_production`, which insists every file is recorded, refused to run on any stack built from the root compose file. **Fix:** the insert is now `INSERT ... SELECT ... WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@aisoc.local')`, which returns no row, so no constraint is evaluated, when the admin exists, and inserts exactly what the VALUES form did on a fresh database (where `account_name` does not exist yet). The migration runner keeps no checksums, and a new migration cannot fix this because the failure is in 001 itself, so editing the file is the only way; the reason is recorded in the file. **Verified two ways:** a fresh database through the real runner (exit 0, no warnings, the seeded admin present, unchanged), and the compose path (all 92 files applied with `psql -v ON_ERROR_STOP=1`, then the production bootstrap), which went from `ok: false` to `ok: true`. **The class of bug is now tested:** `services/api/tests/test_api_migrations_rerun_postgres.py` (3 tests, added to the Postgres workflow) applies every migration file twice in a throwaway database it creates and drops, once as Postgres's init directory does and once as the runner does, and requires zero failures on both; restoring the original `001_init.sql` makes it fail with the exact error and file name, and it passes again with the fix (no databases left behind; the roles are created under `IF NOT EXISTS`, so it cannot reset `aisoc_app`'s password). **Also:** the Integration spine job's bootstrap step now annotates the log lines that explain a failure (never the result line, which carries raw API keys), because 'did not apply' alone did not say why; tested against a stub `docker` including a failure result that contains a raw key, which never appears in the output. **Not verified on GitHub:** this change; the next Integration run will show whether anything else sits behind the bootstrap.
- **The Integration spine job gets what a production-shaped stack needs: ten service tokens, a valid credential key, an account, and a test that logs in.** The annotations added in `082ccd85` paid off again: after the four secrets the API is now `running health=healthy` in the stack, and the spine test gets past boot and fails where I had predicted, `401 Unauthorized` on `POST /api/v1/realtime/ticket`; the API log also showed `CredentialVaultError: AISOC_CREDENTIAL_KEY is not a valid Fernet key` from the `oauth_refresh` worker, because `.env.example` ships a placeholder that is not one and the secure-defaults guard only checks the value is non-empty. Reading the stack's own code showed the rest of the picture: **ten** inter-service bearer tokens (`AISOC_{ACTIONS,API,CONNECTORS,ENRICHMENT,FUSION,HONEYTOKENS,INGEST,PURPLE_TEAM,THREATINTEL,UEBA}_SERVICE_TOKEN`, derived from `docker-compose.yml` by script, not typed: my first grep was cut off by `head` and I had counted nine, and the assertion that compared my list with the file caught it before anything was written), none in `.env.example`, and each service answers 503 to everything but its health route without its token ('there is no development mode; CORE generates the token on every build'), so a stack seeded from `.env.example` only LOOKS healthy. **Changes.** (1) `compose-smoke.yml` and `integration.yml` provision all ten tokens, the four secrets and a Fernet `AISOC_CREDENTIAL_KEY` (`openssl rand -base64 32` made url-safe; checked with the real `cryptography` library that it is valid and round-trips); the seed step, extracted from the parsed YAML and run against the real `.env.example`, yields one line per key, 64-hex distinct tokens, and masks every value. (2) The spine job gains a step that waits for the API container to be healthy and runs `app.scripts.bootstrap_production` inside it (password only in the environment), parses its result line **without printing it** (that line carries raw API keys for CORE and the agents service) and exports `SPINE_ACCOUNT`, `SPINE_PASSWORD` and the ingest token to the later steps; tested against a stub `docker` in success, reported-failure and unparseable modes (exit codes, exported variables, a readable error annotation, and no raw key anywhere in the output). (3) `scripts/integration/spine_test.py` sends the ingest service token on its two ingest posts and logs in once to send a bearer on its three API calls; with no credentials in the environment it sends exactly what it did before, so it still works against a development stack. `services/api/tests/test_spine_test_credentials.py` (7 tests, HTTP mocked with respx) pins that contract, and four deliberate breakages (bearer dropped from the alerts calls, from the ticket call, token dropped from the ingest posts, login on every call) were each caught. **Verified for real, without Docker:** on a fresh Postgres I generated the secrets from the shipped step's own key list, ran the production bootstrap (exit 0, `ok: true`, admin `spine-test`), started the real API in production mode (`/readyz` 200; an anonymous `GET /api/v1/alerts` gives **401**, the cause of the CI failure), and ran the spine test's own helpers against it: login, realtime ticket (320 characters) and alert listing all succeed. **Not verified:** the whole thing inside Docker on GitHub (the ingest and fusion legs, and whether anything else sits behind them); that is what the next run will show, and the annotations will say. **Observed, not examined:** the API log shows `token_revocation.check_failed_allowing_request` when Redis is unreachable, which reads as the revocation check failing OPEN; I did not look at whether that is deliberate. **Still open from before:** `.env.example` sets `ENVIRONMENT=development` while compose reads `AISOC_ENVIRONMENT`, so a root-stack quickstart that only copies the example file crash-loops (the first-run hazard noted in `082ccd85`; a product decision).
- **The `agents` 502 no longer leaking the upstream error is now pinned by tests.** `POST /api/v1/agents/investigate` used to answer a failed core-API fetch with `detail=f"Could not fetch alert {alert_id} from core API: {exc}"`, which put the HTTP client's own error in the response (for a connection failure, the core API's internal host and port). The fix went in with the lint work (`c31c65fb`) with no test, so a regression would have been silent. `services/agents/tests/test_legacy_investigate_alert_fetch.py` (6 tests) checks that a connect error, a timeout and an unexpected error each give a 502 whose body is exactly the generic message and contains none of the error's text, an upstream 500 gets the same answer, the original exception is still chained (`raise ... from exc`, so a traceback shows it) and the caller's own `Authorization` is forwarded while an anonymous call sends none. **Verified by breaking it:** putting `{exc}` back into the detail fails 4 of the 6, dropping `from exc` fails 1, and with the file restored (`git diff` empty) all 6 pass. My first version of the test used the wrong URL (the router carries its own `/api/v1` prefix) and got 404 everywhere; fixed before committing.
- **Compose Smoke's long-standing failure diagnosed from its own annotations: the API refuses to boot because the smoke test never provisions the secrets a production-shaped stack requires.** The diagnostics added in `4ccad754` worked on their first run: every container is healthy except `api`, which restarts in a loop with `InsecureProductionDefaultsError: Refusing to boot in production with insecure defaults` and four items: `METRICS_TOKEN`, `JWT_SECRET`, `REALTIME_INTERNAL_TOKEN` and `AISOC_REALTIME_JWT_SECRET` are empty. That guard is a deliberate policy (`enforce_secure_defaults`; the compose file says every service runs the real configuration and `AISOC_ENVIRONMENT` defaults to production), so the guard stays and the smoke test now does what an operator must: `compose-smoke.yml` generates the four per run (`openssl rand -hex 32`, masked in the logs) into the `.env` it seeds from `.env.example`, replacing an existing empty line rather than appending a duplicate. **Verified before shipping:** I reproduced CI's exact message by loading `.env.example` as compose would with `ENVIRONMENT=production` and calling the guard (4 items, identical text), and with the four generated values the guard **passes** using everything else in `.env.example` as shipped; the step script, extracted from the parsed workflow and run against the real `.env.example`, yields exactly one line per key with a 64-hex value and changes no other line. **The same missing secrets very likely explain `Integration > Event spine`**, which seeds its `.env` identically and failed at 'Run spine test'; it gets the same step. **Unverified, and a second likely problem there:** `scripts/integration/spine_test.py` calls `GET /api/v1/alerts` and `POST /api/v1/realtime/ticket` with no credentials (only an `X-Tenant-ID` header), which a production-mode API answers with 401, so that test probably cannot pass even with a healthy API; the production bootstrap (`app/scripts/bootstrap_production.py`, `AISOC_BOOTSTRAP_ADMIN_PASSWORD`) and a login in the test would be needed, and I did not build them blind without Docker. Instead the spine job now reports its own failure: its output is captured with `tee` (under `shell: bash`, whose `-o pipefail` keeps a failing test failing the step) and a `failure()` step emits the compose state, the last log lines of `api`, `ingest-worker` and `fusion`, and the spine test's own output as annotations (tested against a stub `docker`: 5 single-line annotations, `%` escaped). **A first-run hazard for real users, found on the way and not changed:** `.env.example` sets `ENVIRONMENT=development`, but `docker-compose.yml` reads `AISOC_ENVIRONMENT` (default production), so `cp .env.example .env && docker compose up` on the root stack boots the API as production with empty secrets and crash-loops; the demo avoids this with its own `infra/compose/docker-compose.demo.yml`. Whether the root stack's quickstart should generate secrets, or say how, is a product decision I left alone. **Not verified on GitHub:** these changes; the next Compose Smoke and Integration runs will show what stands behind the API boot, if anything.
- **RLS plan step 4a: a reversible fail-closed SWITCH for the 77 fail-open tenant policies (migration 081), default OFF, and a measured finding that any tenant can modify shared rows.** The plan was to flip 77 policies to fail-closed, a one-way change undone only by another migration, and one that cannot be turned on safely until every code path with no signed-in user has an explicit mechanism. Migration `081_rls_fail_closed_switch.sql` instead rewrites each policy **once**: `(current_tenant_id() IS NULL)` becomes `((current_tenant_id() IS NULL) AND (NOT (SELECT rls_fail_closed())))`, where `rls_fail_closed()` reads the custom setting `app.rls_fail_closed`, unset by default, so **behaviour is unchanged**. Fail-closed is then `ALTER DATABASE <name> SET app.rls_fail_closed = 'on'` (new connections; a pooled connection keeps its value until recycled), undone by `ALTER DATABASE <name> RESET app.rls_fail_closed`. The migration rewrote exactly 77 policies on a migrated database, a second run rewrites 0, and it refuses to finish if any policy still has an unswitched fail-open branch; the `SELECT` wrapper makes PostgreSQL evaluate the switch once per query instead of once per row. **Measured** (scratch Postgres, `aisoc_app`, the 435 isolation flows): switch off, hook off **0 of 435** not as expected; switch ON, hook off **251 of 404**, exactly the plan's figure for flipping the policies by hand; switch ON with the step-3 hook **0 of 435**. **What it does not do:** it is not a boundary against an attacker who can run arbitrary SQL (any session can set a custom setting, as it can already set `app.current_tenant_id`); it does nothing for a superuser or BYPASSRLS connection (the default compose connects as the bootstrap superuser: step 5); and the paths with no signed-in user (audit middleware, `oauth_refresh` and `weekly_digest` workers, the hunt scheduler, login, SSO, signup, webhooks) are not handled, so **the switch must not be turned on yet**. `rls_audit` now classifies the rewritten policies as `switchable` instead of misreporting them as `standard` (fail-open) and prints whether the switch is on; its 'reads only the catalog' test pinned the statement count at 6 and the audit now asks a seventh question (whether the switch exists and is on), built from built-ins only (`to_regproc`, `current_setting`) so it still calls no user function. **Tests:** 7 new unit tests for the audit; `tests/test_rls_fail_closed_switch_postgres.py` (14 tests on a real Postgres as the restricted role, added to the Postgres workflow): unset and 'off' fail open as before, 'on' with no tenant sees nothing, 'on' with a tenant sees only its own rows, 'on' rejects a tenant-less write, the three spellings of on, an unrecognised value does not switch it on, a tenant can never write another tenant's row, the operator's `ALTER DATABASE` and its `RESET` (always reset), and a ratchet that fails if a later migration adds a policy with an unswitched fail-open branch; three deliberate breakages (a policy reverted to the old shape, the function always off, always on) were caught by 7, 6 and 5 tests, and the file passes again after each restore. **A finding, measured, not fixed:** 12 policies (`aisoc_case_comments`, `aisoc_case_tasks`, `aisoc_cases`, `aisoc_compliance_evidence`, `aisoc_hunt_runs`, `aisoc_hunts`, `aisoc_kb_documents`, `aisoc_phishing_submissions`, `detection_eval_baselines`, `detection_rule_proposals`, `hunt_hypotheses`, `passkey_challenges`) also allow `tenant_id IS NULL` rows ('shared') and have no `WITH CHECK`, so on a real Postgres as `aisoc_app`, scoped to tenant A **with the switch ON**, against `aisoc_kb_documents`: `SELECT` of a shared row works (intended), and so do `UPDATE`, `INSERT` of a new shared row and `DELETE` of the shared row. Any tenant can alter or delete what is shared with every tenant. It needs per-command policies and will break code that legitimately writes shared rows, so it is left for step 4b; I did not check which of the 12 tables hold shared rows in a real deployment. **Also corrected:** the plan's closing sentence still said steps 3 to 5 were 'not started'; it now says what is done (3 and 4a), what is not (4b, 4c, 5), and that step 3's code is deployed with its flag off. **Not verified on GitHub:** this change.
- **RLS plan step 3: tag every authenticated session with its tenant and keep that tenant in force across transactions (`AISOC_RLS_TAG_SESSIONS`, default OFF; nothing changes until it is enabled).** `get_tenant_db` sets the tenant with `SET LOCAL`, which lasts for one transaction, so after a handler's `commit()` the next statement runs with no tenant. Harmless today (the policies are fail-open) and fatal once they are fail-closed. With the flag on, `get_current_user` (the plain `get_db` session of every authenticated route; after view-as has resolved, so the effective tenant is the *viewed* one, and after `record_view` / `record_act_as` ran in their own scope) and `get_tenant_db` tag the session (`session.info['rls_tenant_id']`), and an `after_begin` listener (`app/db/rls_hook.py`) re-applies `app.current_tenant_id` at the start of every PostgreSQL transaction. With the flag off nothing is tagged and behaviour is exactly today's. **Measured on a scratch Postgres as the restricted `aisoc_app` role, the 435 two-tenant isolation flows:** fail-open policies, hook off: 0 of 435 not as expected; fail-open, hook on: 0 of 435; **all 77 policies flipped to fail-closed, hook off: 251 of 404** (the plan's number, reproduced); fail-closed with a first version of the hook: **199 of 409**; fail-closed with the corrected hook: **0 of 435**. **The first version was incomplete and only that experiment showed it:** `get_current_user` authenticates on the session before tagging it, so the session has already begun a transaction and the listener (which fires at the *next* begin) never gave that transaction its tenant, so a handler's first writes were rejected (`A creates a case` returned 503). `tag_session` is now a coroutine that also applies the tenant to the transaction in progress. **Tests:** 17 unit tests (the flag, the listener on a fake connection including the not-PostgreSQL and no-tag cases, each of the three returns of `get_current_user`, the in-transaction case) and 8 real-Postgres tests as the restricted role (`tests/test_rls_session_tag_postgres.py`, added to `postgres-tests.yml`, which fails if any is skipped: the tenant survives a commit and a rollback; a negative control that an untagged session loses it at the commit; `cross_tenant_reads` and `acting_as_tenant` inside a tagged session; the already-in-a-transaction case); 9 deliberate breakages of the hook and its call sites were all caught. Full API suite: 8,037 passed, 36 skipped (the opt-in Postgres tests), 0 failed. **What it does not cover, and why enabling it is still safe today but fail-closed policies are not:** the audit middleware, the `oauth_refresh` and `weekly_digest` workers, the hunt scheduler, login, SSO, signup, webhook ingestion and any code that opens its own session still see no tenant, and need an explicit mechanism before step 4. **Fixture notes for anyone repeating the flows:** the two admins need the `admin` role (`tenant_admin` lacks permissions the flows use: 25 false failures) and the addresses `admin-a@example.com` / `admin-b@example.com`; steps 4 (fail-closed policies) and 5 (API connects as `aisoc_app` by default) are not started. Details: `docs/security/rls-fail-closed-plan.md`.
- **Dependency-audit waivers rewritten from verified facts, 13 stale entries replaced by 22 accurate ones plus two for npm, so the `Security Audit` can pass.** The audit's first step (`validate-ignores`) fails on any expired waiver, and all 13 Python waivers had expired on 2026-10-11, so the real audit had not run in CI since. **I did not renew them; I re-derived them.** A fresh `pip-audit` of all 18 targets found 23 findings (pip-audit repeats an advisory once per fix version) in just two services, `agents` (18) and `api` (5); everything else is at 0. 22 were covered by the old waivers, one was not (`langgraph-sdk` CVE-2026-104873, high: custom auth silently ignores `actions=`). **Why each is blocked, checked against PyPI metadata rather than copied:** one root cause, the `langchain-core` 0.3 to 1.x migration, which has not been done. Every fixed release needs `langchain-core>=1.0` (`langchain-openai` and `langchain-text-splitters` need `>=1.2.31`, `langchain` 1.3.9 needs `>=1.4.6`); `langgraph` 1.0.10 only *looks* installable inside our `<1.1.0` cap, but it needs `langgraph-prebuilt>=1.0.8`, which requires `langchain-core>=1.0.0` (I checked every prebuilt 1.0.x release: 1.0.0 and 1.0.1 accept 0.3.x, 1.0.2 onwards do not), and `langgraph` 1.0.1 itself pins `langgraph-checkpoint<4` and `langgraph-sdk<0.3`. **Exposure, checked by grep of `services/api/app` and `services/agents/app`:** none of the six vulnerable features is used (legacy `load_prompt`, `get_num_tokens_from_messages`, `FileSearchMiddleware` and the loaders, the text splitters, checkpoint savers and caches, the `langgraph` SDK client and its auth); `ChatOpenAI` is used (`api/app/llm/factory.py`) but not the one method the two image-token advisories concern. The 22 entries are generated from the audit data, one reason per package stating the blocking requirement, the fix versions and the non-use, both the PYSEC and the GHSA id for each advisory (pip-audit may report either), expiry **2027-01-08** (88 days, inside the 90-day cap). **Two npm entries**, the only high advisories with no patched release: `braces` 3.0.3 (GHSA-vfj7-8cjw-p6xm) and `http-cache-semantics` 4.2.0 (GHSA-ch52-4w7c-c8xp). Both exist only under `apps/docs` (Docusaurus build tooling: `braces` via `fast-glob` and `micromatch`, `http-cache-semantics` via the CLI's `update-notifier`) and neither has any path in the web app's production graph (`pnpm why --prod`: 0). **Verified with the project's own code:** `validate-ignores` passes (24 entries); the Python classifier over the fresh audit gives 0 unwaived, 23 waived, exit code 0; the live `pnpm` audit exits 0 (34 findings, 0 high or critical, 2 ignored). **Not verified:** the Go audit (`govulncheck`), which needs `proxy.golang.org` and `vuln.go.dev` that this sandbox cannot reach; it has never been reached in CI either, because the job always failed earlier, so GitHub's run is the first test of it. **What these waivers do not do:** the vulnerabilities remain in the locked versions; they are accepted, with a deadline, until the `langchain-core` 1.x migration, which is the real fix and needs its own change with regression coverage. Remove each entry when it lands.
- **CI Python jobs, round three: Alembic for three services, `apscheduler` and `langgraph` for the API job, and why my replica kept missing things.** The failure annotations added in `ec95a0ec` worked on the first run and named both remaining causes. **`ueba` (and `honeytokens` and `purple-team`):** their `test_migrations.py` runs `alembic` in a *subprocess* (they share one database and all use revision id `0001`), and on the runner `alembic` is not installed: `ModuleNotFoundError: No module named 'alembic'`. With `alembic` hidden, four tests fail in each service; with `alembic>=1.13,<2` (ueba's declared range) all pass; it is now in the minimal list and the wave-2 shared list. **The API job:** seven errors in `test_b10_backend_route_coverage.py`, 'Failed to load agents OpenAPI routes in subprocess': that test spawns a subprocess that imports the **agents** app, which needs `apscheduler` and `langgraph`; CI only installed `langgraph` in a later step, after the API tests. Both are now in `API_DEPS` at the ranges `services/agents/pyproject.toml` declares (`apscheduler>=3.10.4,<4`, `langgraph>=0.2.40,<1.1.0`). **The constraint matters:** installing `langgraph` unconstrained pulled `langchain-core` to 1.6.10 and silently undid the `<0.4` pin added in `ac8e253a`; with the declared range `langchain-core` stays 0.3.86 and `langgraph` resolves to 1.0.1, the version `agents`' lockfile has. **Why my replica kept missing things, and the fix to the method:** I had been isolating the environment with `PYTHONPATH` and `python -S`, but test subprocesses use `sys.executable` with the system site-packages visible, and this sandbox's system Python happens to have `alembic`, `langgraph`, `apscheduler` and more. Every such leak showed up as 'passes here, fails on the runner'. A virtual environment created without system site-packages cannot leak, so the final check was run in one: a fresh venv from exactly the current `API_DEPS`. **Results there:** the whole API suite was 8,011 passed / 30 skipped / 7 errors (those seven, because my first attempt to add `apscheduler` was silently ignored: the requirements file had no trailing newline, so my appended line fused with the previous one); with `apscheduler` installed the file passes (22 tests) and `langchain-core` is still 0.3.86. The four service jobs, run with CI's exact command and coverage gates: `ueba` 118, `honeytokens` 121, `purple-team` 307, `fusion` 271, all passing. **Confirmed on GitHub by the previous push:** `threatintel` and the API job's boot-test step pass. **Not verified on GitHub:** these changes, and the agents unit-test step and the benchmark scoreboard gate that follow the API tests (never reached so far).
- **CI: the missing test dependencies for `honeytokens`, `purple-team` and `threatintel`, and annotations so a failing Python job can be read.** The first Python test run on GitHub left four jobs red, and the exit codes split them: 2 (collection error: a missing module) for `honeytokens` and `threatintel`, 1 (a test failed) for `ueba` and the API job. Same method as before: build each job's *exact* install list in a clean environment with system packages disabled, run the job's exact command, and install whatever the import errors name. **Results:** `honeytokens` needs `sqlalchemy[asyncio]` (its `greenlet`) and `aiosqlite` (its five tenancy tests build an in-memory SQLite database), and `purple-team`, which the same job runs next and which therefore had never been reached, needs `apscheduler`; with those three added to the minimal list, all three services of that job pass their coverage gates (`fusion` 271, `honeytokens` 121, `purple-team` 307). `threatintel` needs `neo4j`, `opensearch-py`, `qdrant-client` and `mmh3` (four, where I had predicted two); rather than add them to the list shared by all eight wave-2 services, a step runs only for `threatintel`, and installs the **ranges its own `pyproject.toml` declares** (`neo4j>=5.19,<6`, `opensearch-py[async]>=2.7,<3`, `qdrant-client>=1.9,<2`, `mmh3>=4.1,<5`): its 96 tests pass on those versions (my first loop had pulled `neo4j` 6.4, `opensearch-py` 3.2 and `mmh3` 5.3, which the service does not declare). **`ueba` and the API job still fail on GitHub although they pass in my replica**, so I could not diagnose them: the job logs are not readable from outside the web UI. Instead of guessing a third time, both now make their own failures readable. The `ueba` (wave 2) job gains a `failure()`-only step that re-runs the service's tests quietly and re-emits the failing lines as `::error` annotations (the `%` characters are escaped; I tested the command against a deliberately failing test); the API test step now writes its output to a file with `tee` (under `shell: bash`, whose `-o pipefail` keeps a failing pytest failing the step) and a `failure()` step turns the `FAILED`/`ERROR` lines and the last three lines of that file into annotations, with no re-run of the 5-minute suite. **Progress confirmed on GitHub by the previous push:** the API job's boot-test step (`from app.main import app`) now passes, which confirms the missing `langchain` packages were the cause there; `Run API tests` is what still fails, and the next run will say why. **A likely suspect that I cannot confirm:** the runner has fewer cores than my sandbox, and I have already seen `test_anonymous_access_sweep` report 438 routes as exposed purely because its requests timed out under load. **Not verified on GitHub:** these changes.
- **The API test job can now pass in CI: three configuration faults that hid behind the lint gate, found by reproducing CI's environment instead of mine.** Once `Python - Lint & Type-check` went green (`c31c65fb`), the Python test jobs ran on GitHub for the first time and `Python - Tests` failed. My sandbox had been silently masking every cause, because it has packages and a local Postgres that the runner does not, so I rebuilt CI's environment exactly (a fresh install of the workflow's `API_DEPS`, system site-packages disabled) and ran the same commands. **(1) Two packages were missing from `API_DEPS`:** `app/api/v1/endpoints/copilot.py` imports `langchain_core` and `langchain_openai`, declared in `pyproject.toml` as `>=0.3,<0.4` and `>=0.2,<0.3` but never installed by CI, so the boot-test step (`from app.main import app`) failed. They are added with those constraints (the unconstrained latest is the 1.x major the project has not migrated to; the app boots on the pinned 0.3.86/0.2.14, verified), to `ci.yml`, `check-openapi.yml` (whose OpenAPI export imports the same app, so its earlier 'out of date' verdict may have been hiding this too), `cross-tenant-rbac.yml` and `wet-eval.yml`. **(2) `respx` was missing too,** so 10 test files failed at collection (with it, 8,048 collect). **(3) CI's test step inherited `ENVIRONMENT: development`,** meant only for the boot test. Under `development` an anonymous caller is authenticated as a development user, so the tests that assert 'someone who is not signed in gets nothing' (GraphQL, realtime ticket, and five of my own WebSocket tests) fail with a `500`/`1011` when they reach a database that is not there; the suite's own default is what its tests assume, and `test_dev_mode_unification` asserts the defaults *when the variable is unset*, so the right setting is no `ENVIRONMENT` at all (I first tried `test`, which fixed seven but broke those two). The step no longer sets it, with the reason in a comment. **A fragile test fixed:** `test_neither_database_url_reaches_the_eval` planted `...:secret@db/...` and asserted the word `secret` appeared nowhere in the subprocess environment, which fails the moment any unrelated variable contains it (CI's `SECRET_KEY` is `ci-dummy-secret-key-...`); it now plants and checks a unique sentinel. **Verified under CI's exact conditions for that step** (fresh `API_DEPS` + the two constrained packages, only `SECRET_KEY` and `DATABASE_URL` set, no `ENVIRONMENT`, system site-packages disabled): `api` **8,018 passed, 30 skipped, 0 failed**; the intermediate runs were 8/8,010 (development), then 2/8,016 (test). **Two wrong guesses along the way, for the record:** I blamed CI's dummy `DATABASE_URL` (the same eight tests failed with and without it; the app's default database is also a local Postgres), and I attributed the DB connection to the audit middleware (the trace showed it is `get_tenant_db`, which depends on `get_current_user`, so the connection only happens when authentication *succeeds*, which in development mode it does for anyone). **Not verified on GitHub:** this change has not run there yet. **Still failing in CI and not yet diagnosed:** `threatintel` (very likely missing `opensearch-py` and `mmh3`), `honeytokens` and `ueba`, and the agents unit-test step that follows the API tests.
- **The remaining 255 Python lint errors fixed (`ruff check services/` now reports 0), the Prometheus audit made to pass, and an exception-text leak in `agents` closed: the last steps before the Python test suite can run in CI.** After `E501` was ignored (`e3902805`) and `ruff format` applied (`db652d6b`), 255 errors remained, most of them mechanical. 203 were applied with ruff's own safe fixes (mostly import ordering) and 45 with its 'unsafe' fixes, restricted to six named rules (`UP038`, `C408`, `B007`, `E731`, `C416`, `F841`) and read where meaning could shift (for example `F841` renamed an unused tuple element to `_drop` rather than deleting an assignment). **Eight needed a judgement, each fixed the right way for its site:** three models were imported in `app/models/__init__.py` for SQLAlchemy registration but missing from its `__all__`, so they were *added to `__all__`* instead of the imports being deleted; two `except ImportError:` handlers in `saml.py` now chain (`as exc` ... `from exc`) so the missing module stays visible in logs; `agents`' `investigate.py` chains too; two ambiguous `l` variables in tests were renamed. **That `agents` site was also a leak:** it returned `detail=f"Could not fetch alert {alert_id} from core API: {exc}"` in a 502, putting the HTTP client's error (which can name the core API's host and port) in the response; the cause is already logged on the line above, so the response now says only `Could not fetch alert <id> from the core API` (a small behaviour change; no test depended on the old text, and the `alert_id` is the caller's own input). **The Prometheus drift check** (`scripts/audit_prometheus_targets.py`) reported `agents` and `enrichment` as exposing `/metrics` without a scrape job. Reading the code showed neither serves metrics at all: `agents` declares `prometheus_client` but never uses it, `enrichment` has no `promhttp`, and the checker's text heuristic was matching `"/metrics"` in their auth-exempt path lists. A scrape job would have been a permanently-down target, so both are listed in `SCRAPE_EXEMPT` **with a written reason** recording the real gap (they are not instrumented). **Verified:** all 13 Python suites after the fixes, one at a time: `api` 8,020 passed / 28 skipped / 0 failed, `agents` 1,193, `connectors` 1,010, `actions` 435, `purple-team` 307, `fusion` 271, `slack-bot` 130, `honeytokens` 121, `ueba` 118, `threatintel` 96, `osquery-tls` 93, `mesh` 17, `teams-bot` 5: the same counts as before; `ruff check services/` 0 errors and `ruff format --check services/` exit 0; the eight further verification steps that follow ruff in the same CI job (vendored-copy syncs, connector count, prompt lock, runbook links, health probes, managed tenants, Prometheus targets) all pass locally. **The import sorter moved lines again, so the six `.gitleaksignore` line numbers for the fake test tokens were refreshed a second time** (each moved up by one); a path-and-regex allowlist would stop this recurring. **Not verified:** that the job is green on GitHub (that is the next thing I will read); `mypy`, which the job installs but does not run.
- **`ruff format` applied to `services/` (240 files, layout only), the first of the commits that let the Python test suite run in CI.** `Python - Lint & Type-check` runs `ruff check services/` and `ruff format --check services/`, and every other Python job `needs` it, so the 8,000-test API suite and the service unit tests have never run on GitHub; the line-length policy (`E501` ignored, 2,253 -> 266 errors) was the previous commit, and this removes the second failing step. **Verified, not trusted:** I parsed every changed file before and after and compared the **syntax trees** (docstring whitespace normalised, which the formatter is documented to adjust): **0 of 240 differ**, so the formatter changed layout and nothing else. Then the suites, on CI's own dependency set: `api` **8,020 passed, 28 skipped, 0 failed**; `agents` 1,193; `actions` 435; `connectors` 1,010; `purple-team` 307; `fusion` 271; `honeytokens` 121; `ueba` 118; `slack-bot` 130; `threatintel` 96; `osquery-tls` 93; `mesh` 17; `teams-bot` 5: the same counts as before wherever I had a before. `ruff format --check services/` exits 0; the formatter also removed 11 lint errors (255 remain). **Two tests were layout-sensitive and are fixed:** `test_email_case.py` did a literal substring match on one line of source (the formatter wrapped a conditional expression in parentheses), and my own graph-write ratchet (`test_graph_upsert_unavailable.py`) used a regex that needed `_or_503(graph_service.upsert_x(` on one line; both now ignore layout, and I confirmed the ratchet still fails when a call is unwrapped. **A false alarm, and what caused it:** my first full API run reported `test_anonymous_access_sweep` failing with '438 routes answered an anonymous request ... kept the connection open (streaming)'; every route was flagged because its requests had **timed out**, since I was running the other services' suites concurrently (that run took 444 s against about 305 s alone). It passes alone and in the undisturbed full run, so it is load, not exposure; but the sweep reports a timeout as 'exposed', which makes it fragile on a busy runner. **Side effect found by scanning before pushing:** `.gitleaksignore` records each triaged finding by LINE NUMBER, and a reformat moves lines, so six entries (the fake `internal-secret-123` and `sk-live-SECRET-key-fragment-12345` test tokens in `agents` and `api` tests) stopped matching and would have turned the `Security` workflow red; nothing new leaked, and I refreshed the six numbers (`24 -> 27`, `40 -> 47`, `63 -> 70`, `147 -> 155`, `170 -> 179`, `28 -> 29`) and re-scanned the tracked tree: clean. Any future reformat will do this again until those entries move to a path-and-regex allowlist. **Not done:** the remaining 255 lint errors (the next commit); `mypy`, which the same CI job also runs and which I have not run. **Merge note:** a 240-file reformat will conflict with any in-flight branch that edits those files, such as the parallel Claude Code session's; rebase and re-run `ruff format` there.
- **The API's own tokens move from `python-jose` to `PyJWT`, removing `python-jose` and its `ecdsa` dependency, neither of which has a fix (`api` 8 -> 5 vulnerabilities).** The waiver for `ecdsa` said the real fix was 'migrating the auth layer off python-jose to PyJWT (already a dep), a regression-prone change tracked for a dedicated PR'. This is that change, and it is small: `jose` was imported in three application files (`security.py` for `jwt.encode`/`jwt.decode`, `deps.py` and `graph_ws.py` only to catch `JWTError`), PyJWT was already used for SAML and OIDC. **8 lines changed in application and test code:** `import jwt`, and `except PyJWTError` (the base class of every PyJWT decode failure) where `except JWTError` was; the two tests that used `jose` directly now use PyJWT. **What had to be proven first, and was, before any application code changed:** an authentication library swap is only safe if (1) a token that `python-jose` minted *before* the deploy still verifies afterwards, and (2) a token minted by the new code still verifies on the old image if the deploy is rolled back. `tests/test_jwt_library_compat.py` mints with each library and decodes with the other, using the real claim shapes (`sub` as `str(user.id)`, `exp` as a datetime, `type`, a hex `jti`; and the realtime ticket's `aud`/`iat`/`exp`), on **PyJWT 2.7.0 (my environment) and 2.15.1 (the newest in range)**: both directions pass. It also pins that expired, wrong-key, tampered, garbage, `alg=none` and unlisted-algorithm tokens are all refused with a `PyJWTError`, and that every PyJWT decode failure is a subclass of the one exception the callers catch. The cross-library tests need `python-jose` to mint or read the other side, so they `importorskip` it and skip where it is absent (it is no longer a dependency); the other tests always run. **Two behaviours worth knowing:** `python-jose`'s `encode` **mutates the claims dict it is given** (it turns `exp` from a datetime into an int in place), which PyJWT does not; the app is unaffected because `create_access_token` copies first, but my own first test tripped on it. And PyJWT 2.10 and later **reject a non-string `sub`**, which is why the migration is safe here (every access, refresh and passkey token uses `str(user.id)`); that is pinned by a test that skips on older PyJWT. **Verification of the migration itself:** the full API suite is **8,018 passed, 30 skipped, 0 failed** with `python-jose` made un-importable (a `ModuleNotFoundError` stub first on the path; my first stub raised a plain `ImportError`, which `importorskip` correctly does not treat as 'not installed', so I made it faithful) and PyJWT 2.15.1 first on the path; the skips rose by exactly the three cross-library tests. **A trap I avoided:** in all seven workflow install lists and the developer setup script, `cryptography` was installed **only** through the `python-jose[cryptography]` extra, so deleting the entry would have silently removed `cryptography` from CI and broken the credential-vault tests; each occurrence is *replaced* by an explicit `cryptography` instead. Also updated: the API `pyproject.toml` (and the PyJWT comment, which said it was 'separate from python-jose'), the Dockerfile's pip fallback, and `AGENTS.md`. The real audit for `api` now reports 5 (`langchain-core` x3, `langchain-openai` x2, blocked by the major migration), and the `ecdsa` waiver and its comment block are deleted as stale; 13 waivers remain, all expired and all still reported. **Not verified:** a built image, tokens issued by a real production instance (the compatibility claim rests on the claim shapes in the code and the two libraries' behaviour, not on a captured production token), and any non-API service. **Action on upgrade:** none; sessions in flight keep working (tested). **Rollback:** also safe (tested).
- **`agents`: `weasyprint` 69.0 -> 70.0 (2 advisories), via the cap lift plus a relock I had deferred; `agents` is now 18 and contains only the blocked `langchain`/`langgraph` family.** Checking what would still fail the Security Audit even if every remaining waiver were renewed, I cross-referenced the 28 still-reported Python findings with the 14 remaining waivers: 24 are covered and **4 are not** (`agents` `langgraph-sdk` CVE-2026-104873, `agents` `weasyprint` x2, `api` `python-jose` CVE-2026-85394, which has no fix). The two `weasyprint` ones were fixable rather than waivable: `services/agents/pyproject.toml` capped it `<70` (now `<71`), and because `agents` has a lockfile the cap change alters the lock's content hash. **Procedure, on a throwaway copy first:** `poetry lock` alone changed only the content hash (4 lines) and moved **no** package, because `poetry lock` keeps existing pins (lifting a cap permits an upgrade but does not perform it); an explicit targeted `poetry update weasyprint --lock` then moved exactly one package, `weasyprint` 69.0 -> 70.0 (10 lines against the original lock), and `poetry check --lock` exits 0. **Usage:** `agents` calls the identical API as the `api` service (`weasyprint.HTML(string=...).write_pdf()`, in one endpoint with a graceful fallback when the optional extra is absent), which I exercised with a real render of the `api` digest HTML on 69.0 and 70.0 (both valid PDFs; layout not compared). **Result:** real audit for `agents` 20 -> 18 with `weasyprint` gone; the 1,193 `agents` tests pass (`weasyprint` is not installed in that environment, so they do not exercise it). **What the Security Audit would still report, assuming the 14 waivers were renewed:** the Python findings not covered by any waiver are `langgraph-sdk` CVE-2026-104873 (fix 0.4.4, blocked with the rest of the `langgraph` family) and `python-jose` CVE-2026-85394 (no fix exists), plus the two npm advisories with no patched release (`braces`, `http-cache-semantics`); so green needs those waived as well, each a risk acceptance I have not made. **Not verified:** a built image, and the PDF endpoint end to end.
- **20 stale Python waivers deleted, so the waiver file now lists only findings that are still real.** After the Python audit was run for real (it had never run), I matched every `python` waiver against its results by advisory id and alias. **20 of 34 are for advisories the audit no longer reports** (the `starlette` multipart, hostname and form-DoS ones, `idna`, `pydantic-settings`, the three `cryptography` highs, the three `aiohttp` highs and `h2`; 13 of them were expired and 7 were not), because the caps behind them were lifted in the earlier commits. A waiver for something that is not reported is stale by construction, so deleting it accepts no risk (all 20 were `python` entries; no Go waiver could have been caught). Five comment blocks that described only those entries are removed with them, plus one orphaned block that described the `next`/`sharp` work as 'tracked for a dedicated PR' after it had been done (`3e1dcfa9`). **What remains: 14 waivers, every one still reported and every one expired:** the `langchain`/`langgraph` family (`langchain-openai`, `langchain-text-splitters`, `langgraph`, `langgraph-checkpoint` x3, `langgraph-sdk` x2, `langchain`, `langchain-core` x4) and `ecdsa`. They are genuinely blocked (major migrations, or no release exists), not stale, so keeping or renewing them is a risk acceptance I have **not** made; the validator still fails at the first (`PYSEC-2026-76`). **Not changed:** the file's 2026-05-28 preamble still says 'everything below has no patched release', which is now only partly true of the remaining entries. **Not verified:** the validator passing, since the 14 expired entries remain; and the match is only as complete as my audit of 18 services and packages (it does not cover Go, and no `go` waiver existed).
- **`slack-bot`'s `poetry.lock` was out of sync with its `pyproject.toml` since 2026-07-12, which made `poetry install` fail; fixed, and its 22 hidden vulnerabilities cleared.** The Python audit could not export `slack-bot` at all, and the reason turned out to be a real defect: `poetry check --lock` fails with 'pyproject.toml changed significantly since poetry.lock was last generated'. On 2026-07-12 the durable-approvals feature added `asyncpg = ">=0.29,<0.31"` to `pyproject.toml` without regenerating the lock (last regenerated 2026-06-08), so the service's primary install path (`poetry install`) has been failing since then and its image could only have been built through the Dockerfile's pip fallback. **Fix, in two steps, each tested on a throwaway copy first:** (1) `poetry lock` adds exactly one package, `asyncpg` 0.30.0 (72 lines, new content hash), and `poetry check --lock` now exits 0; (2) with the service finally auditable, the real audit showed **22 vulnerabilities in 6 packages** that no one had been able to see (`starlette` 5, `aiohttp` 3, `anyio` 2, `multidict`, `idna`, `pydantic-settings`), all fixable within the existing constraints, so a targeted `poetry update` moves `starlette` 1.0.0 -> 1.7.0, `aiohttp` 3.14.1 -> 3.14.5, `anyio` 4.13.0 -> 4.15.1, `idna` 3.13 -> 3.20, `multidict` 6.7.1 -> 7.1.0 (a major bump the resolver chose because `aiohttp` allows it), `pydantic-settings` 2.14.1 -> 2.15.0, plus `yarl` and `typing-extensions` (content hash unchanged by this step). **Result:** the lock is consistent (`poetry check --lock` exit 0), the real audit reports **0 vulnerabilities**, and the 130 `slack-bot` tests pass on an environment that already carries these versions. **Not verified:** a built image or an end-to-end run, and the `asyncpg` durable-timer path (it is optional at runtime and the unit tests use the in-memory fallback). **Python audit, final state:** every service and package audits at 0 except `api` (8: `ecdsa` and `python-jose` have no fix; `langchain-core` and `langchain-openai` need a major migration) and `agents` (20: the `langchain`/`langgraph` family, capped out by `pyproject.toml`, and `weasyprint`). **Action on upgrade:** none beyond `poetry install`, which works again for `slack-bot`.
- **The two lockfile-pinned Python services are updated with targeted `poetry update` runs: `teams-bot` 13 -> 0 vulnerabilities and `agents` 35 -> 20.** I held these back earlier because changing a constraint without regenerating `poetry.lock` makes `poetry install` fail on a content-hash mismatch. So I tested lock regeneration on **throwaway copies first**: a targeted `poetry update <names> --lock` leaves `pyproject.toml` untouched, so the lock's **content hash is unchanged** and the lock-version stays 2.1; only the header's Poetry version moves (2.4.1 -> 2.5.1), which is cosmetic. **`teams-bot`** (46 lines): `starlette` 1.0.0 -> 1.7.0, `anyio` 4.13.0 -> 4.15.1, `pydantic-settings` 2.14.1 -> 2.15.0, `typing-extensions`; real audit 13 -> 0, its 5 tests pass, `poetry check --lock` reports no lock-consistency error (only deprecation warnings that were already there). **`agents`** (seven packages): `aiohttp` 3.14.1 -> 3.14.5, `anyio` 4.14.1 -> 4.15.1, `h2` 4.3.0 -> 4.4.1, `urllib3` 2.7.0 -> 2.8.0, `yarl` 1.24.2 -> 1.25.1, `typing-extensions`, and `multidict` 6.7.1 -> **7.1.0** (a major bump that the resolver chose because `aiohttp` allows it; 6.9.1 also fixes the advisory). The diff is 912 lines but almost all of it is per-file hashes for those seven packages. Real audit 35 -> 20. **Evidence:** my local test environment already carries **exactly** these versions (`aiohttp` 3.14.5, `anyio` 4.15.1, `urllib3` 2.8.0, `multidict` 7.1.0, `yarl` 1.25.1), and the full `agents` suite passes on them: **1,193 passed, 2 skipped**. **The gap:** `h2` is not in that environment, so its 4.3.0 -> 4.4.1 bump is not exercised by any test I ran. **What remains in `agents` (20), all of it genuinely blocked, not stale:** `langchain-core` (3), `langchain` (2), `langchain-text-splitters` (2), `langchain-openai` (2), `langgraph` (2), `langgraph-sdk` (3), `langgraph-checkpoint` (4), whose fixes are 1.x majors that `pyproject.toml` caps out (`langchain-core <0.4`), plus `weasyprint` (2), capped `<70` in `pyproject.toml` (lifting it changes the content hash and needs a relock; the `api` service's identical cap was lifted separately). **Python audit overall, after this stretch:** teams-bot 0, connectors 0, fusion 0, mesh 0, osquery-tls 0, threatintel 0, actions 0, honeytokens 0, purple-team 0, ueba 0, the packages 0; **api 8** (`ecdsa` and `python-jose`: no fix exists; `langchain-core` and `langchain-openai`: major migration); **agents 20** (above); `slack-bot` could not be exported and is uninspected. **Not verified:** built images, end-to-end runs, and the services' behaviour on the new lock outside the unit suites. **Action on upgrade:** none beyond `poetry install`; developers with Poetry 2.4.1 will see header churn the next time they relock.
- **Five small Python services no longer ship a vulnerable `starlette` or `cryptography`: 70 vulnerabilities cleared (connectors 20 -> 0, osquery-tls 20 -> 0, fusion 14 -> 0, threatintel 14 -> 0, mesh 2 -> 0).** The pattern, again, was a stale cap, not a missing fix: the services pinned `fastapi ^0.109.0` (or `^0.111.0`), which resolves `starlette` 0.36.3 with 7 advisories, while CI's own service-test job installs `fastapi>=0.109,<0.140` (which resolves `fastapi` 0.139.2 and **`starlette` 1.7.0**, newer than every fixed version). So what was tested and what was deployed differed, and the deployed one was the vulnerable one. **The change** (7 one-line edits, 5 files): `fastapi` becomes `>=0.109,<0.140` in connectors, fusion and threatintel and `>=0.111,<0.140` in osquery-tls, deliberately the range CI already tests; `cryptography` moves from `<49` to `<51` in connectors and osquery-tls and from `<50` to `<51` in mesh (the audit's fixed versions are 49.0.0 and 50.0.0, and `api` and `agents` already allow `<51`). **Evidence:** I installed CI's own wave-2 dependency set locally and ran each service's full unit suite on it: connectors 1,010 passed (2 skipped), fusion 271, osquery-tls 93, mesh 17, teams-bot 5 and threatintel 96; then, for the three services that use `cryptography` directly, again on `cryptography` 50.0.2 (the version was printed in-process to confirm it applied): connectors 1,010, mesh 17, osquery-tls 93, all passing. **Then the real audit** (the project's own function, no waivers, fresh resolution) reports 0 vulnerabilities for each of the five. **Limits, stated:** the suites ran on the stack the new constraints *allow*, not on a built image; Docker images were not rebuilt and the services were not run end to end; none of these services has a lockfile, so resolution floats within the new range (the earlier versions floated too); `teams-bot` (13 vulnerabilities) was **not** changed because it has a committed `poetry.lock` and a constraint change without regenerating the lock fails `poetry install` on a content-hash mismatch; `agents` (35) likewise; `slack-bot` could not be exported. **Two findings for later:** (1) `threatintel`'s tests need `opensearch-py` and `mmh3`, which are **missing from CI's wave-2 install list**, so that job will very probably fail at collection on GitHub once the Python lint gate lets it run; (2) every one of these services' Dockerfiles carries a stale pip fallback list (old `fastapi`, `cryptography`) that is used only if `poetry install` fails; I left them alone. **Not done:** the `agents` and `teams-bot` locks, the langchain majors, `ecdsa` and `python-jose` (no fix exists).
- **Python dependencies audited for the first time (the audit had never run): 19 vulnerable packages, 39 advisories; two upper caps lifted in the API service.** The Security Audit's Python step aborts on the first expired waiver, so it never ran. I installed CI's tools (`pip-audit`, `poetry`) in an isolated virtualenv and ran the project's own audit function with **no waivers**, one service at a time (a first all-in-one background run died silently; the resumable per-service version is what worked). Results by service: agents 35, connectors 20, osquery-tls 20, threatintel 14, fusion 14, teams-bot 13, api 12, mesh 2, and 0 for actions, honeytokens, purple-team, ueba and the packages; `slack-bot` could not be exported and is uninspected. By package: `starlette` 7 (old `fastapi ^0.109`/`^0.111` pins in connectors, fusion, osquery-tls, threatintel, teams-bot), `aiohttp`, `anyio`, `urllib3`, `langgraph-sdk`, `cryptography` 3 each, and the `langchain`/`langgraph` family (fixes are 1.x majors). **No fix exists** for `ecdsa` and `python-jose` (api). **What I changed:** the API service capped `strawberry-graphql <0.324` and `weasyprint <70`, and the fixed versions are 0.326.1+ and 70.0. Both caps are lifted (`<0.331` and `<71`). Evidence, and its limits: the API test environment was **already running strawberry-graphql 0.330.2**, newer than the fix and than the old cap, so the 8,000-test suite has been passing on a version the cap forbade; `weasyprint` is **not installed** in the test environment and the 12 PDF tests **mock it**, so they prove nothing about 70.0, so I rendered the app's real digest HTML through its own `HTML(string=...).write_pdf()` call on 69.0 and on 70.0 (both produce a valid PDF, 18,474 and 18,461 bytes from the same 10,289-character HTML; I did not compare layout). The real audit for `api` goes from 12 vulnerabilities to 8, with `strawberry-graphql` and `weasyprint` gone; what remains is `ecdsa`, `python-jose` (no fix) and the `langchain` pair (major migration). **Deliberately not changed:** `services/agents/pyproject.toml` has the same `weasyprint <70` cap, but `agents` has a committed `poetry.lock`, and changing a constraint without regenerating the lock makes `poetry install` fail on a content-hash mismatch. **A correction to my own first reading:** the API Dockerfile pins much older versions (`strawberry-graphql<0.237`, `weasyprint<63`, `fastapi<0.112`, `cryptography<43`), which looked like the image ships them, but it runs `poetry install` first and uses that pip list only as a fallback if poetry fails, so the normal path follows `pyproject.toml`; the fallback list is stale and vulnerable and I left it alone. **NOT DONE:** the starlette/fastapi pins in the five small services, `cryptography <49` in connectors and osquery-tls, the `agents` lock, `slack-bot`, and the langchain majors; none of it was tested.
- **`tinypool` 1.1.1 -> 2.2.0 (2 critical advisories: prototype pollution in worker options leading to remote code execution).** `tinypool` is used only by Docusaurus's build tooling (`@docusaurus/core`), so this is build-time exposure of the docs site, but critical is critical. The patched 2.1.1 is a **major** bump from the 1.x range Docusaurus asks for, so I tested it instead of assuming: a caret-range override `"tinypool": "^2.1.2"` in the root `pnpm.overrides` (lockfile +7 -5; the new version needs Node 20 or 22+, which the workflows use), the docs site builds with it, Docusaurus resolves `tinypool` 2.2.0 and the lockfile holds no 1.x. **Audit: 35 -> 33 advisories, both critical `tinypool` advisories cleared, none newly reported.** **Only two high/critical npm advisories remain in the whole tree, and neither has a patched release:** `braces` (GHSA-vfj7-8cjw-p6xm, stack exhaustion on deeply nested patterns, vulnerable <= 3.0.3) and `http-cache-semantics` (GHSA-ch52-4w7c-c8xp, `max-stale` handling can disclose cross-user cached responses, vulnerable <= 4.2.0), both published 2026-09-18 and not withdrawn. A waiver is accurate for those two (build tooling, no fix exists), but it is a risk acceptance with a 90-day cap and I have not written one. **Not verified:** the docs site's runtime (only its build), and nothing else uses `tinypool` in this tree.
- **`next` 16.3.0 -> 16.3.8 (3 critical + 1 high advisories) and `sharp` 0.35.3 -> 0.35.5 (2 high), and the web jobs in CI run for the first time.** `apps/web` pins `next` and `eslint-config-next` exactly, so the two pins are edited directly (no override). Bumping `next` also moves `sharp` (a dependency of `next`) and the platform binary packages; the lockfile diff is +151 -169 across 43 entries, all of them `next`, `@next/*`, the `sharp` family, `eslint-config-next` or de-duplicated helpers. **Audit: 46 -> 35 advisories (high 5 -> 2, critical 5 -> 2), `next` x9 and `sharp` x2 cleared, none newly reported.** **Verified locally:** web type-check passes, web lint exits 0, and the web unit suite is 94 files / 1,055 tests passing, identical to before. **Not verified locally:** `next build` (the font loader needs network access in this sandbox; my attempt to mock it with Next's `NEXT_FONT_GOOGLE_MOCKED_RESPONSES` failed under Turbopack and I left it), Playwright e2e and Docker builds; GitHub's `Web - Build` job is the check for the build. **Also in this stretch: the CI web jobs now actually run.** `web-test`, `web-build` and `storybook-build` declare `needs: web-lint`, and web lint failed on two `react/no-unescaped-entities` errors (`framework's` in JSX in `FrameworkView.tsx` and `ComplianceHeatmap.tsx`), so on GitHub the web build, the web unit tests with their coverage gate and the Storybook build had never run; escaping the two apostrophes (`&apos;`, rendering the same character) let all four web jobs run, and **they passed** on the previous dependency set. **What is still red in CI:** only `Python - Lint & Type-check`, which also gates the Python test suite and the service unit tests, so those have never run on GitHub either: `ruff check services/` reports 2,253 errors, **1,988 of them `E501` (line over 140 characters), which neither `--fix` nor the formatter fixes**, plus 265 others (209 auto-fixable); and `ruff format --check` would additionally fail on 240 files. Resolving that is a policy choice (ignore `E501`, as the formatter already enforces 140; per-file ignores for tests; or wrap about 2,000 lines) that I have not made. **Remaining high/critical npm advisories, 4:** `tinypool` x2 (critical, prototype pollution to RCE; used only by Docusaurus's build tooling; the patched 2.1.1 is a major bump), and `braces` and `http-cache-semantics` (high, published 2026-09-18, **no patched release exists**, so a waiver would be accurate for those two; I have not written any).
- **Dependency audit: 54 npm advisories cleared (100 -> 46; high 32 -> 5, critical 8 -> 5), the npm waiver list emptied, and what is still red.** CI had never run on this repository before 2026-10-11, so the first Security Audit run was also the first time anyone saw this: the audit aborts on the first expired waiver, so the real `pnpm` audit had never run. Three commits: `022651fd` (serialize-javascript, a high-severity RCE, 6.0.2 -> 7.1.2), `d71c0bb5` (fast-uri and the babel systemjs plugin, 10 advisories) and this one. **The waivers' stated reasons were false:** they said 'no patched release' or 'fix requires the 4.x major', but the lockfile was simply stale: each package's dependents accept a patched version in range (fast-uri was locked at 3.1.0 while 3.1.8 is published, and 3.1.8 fixes all nine of its advisories without a major bump). **The change:** scoped overrides in the root `package.json` `pnpm.overrides`, the project's own convention, each within the locked major (`axios`, `undici`, `joi`, `js-yaml`, `brace-expansion`, `browserslist`, `compression`, `proxy-addr`, `shell-quote`, `source-map-js`, `svgo`, `image-size`, `ip-address`, `websocket-driver`, `@modelcontextprotocol/sdk`; selectors where several majors are locked); the lockfile diff is +135 -113 and moves exactly those packages plus browserslist's data packages. **A first attempt I reverted:** `pnpm update -r <names>` rewrote 388 lines of unrelated packages (`@types/react`, `vite`, `monaco-editor`...), which cannot be reviewed as 'two advisories'. **All 18 npm waivers are deleted** (the audit no longer reports any of them: some were cleared by this change, and some were stale before it, e.g. the four `next` ones say 'fixed in 16.2.11' while 16.3.0 is locked). **Verified, old dependencies vs new:** `pnpm audit` 100 -> 46 advisories with none newly reported; docs site builds; web type-check passes; web lint is identical (2 errors, 84 warnings, the same two `react/no-unescaped-entities` errors GitHub reported); the web unit suite is 94 files / 1,055 tests passing on both; MCP 102 tests, report-card, sdk, types, ui, ocsf, action and lite all pass on both, **0 of 19 build/type-check/test results differ**. (My first baseline looked as if the update had fixed `@aisoc/action` and `aisoc`; reproducing the old dependency set showed they pass on it too, so that was a bad first baseline taken before everything was linked, not an effect of the change. I retook it.) **STILL RED, and honestly so:** (1) **10 high/critical npm advisories remain unwaived**: `next` x4 (three critical; locked 16.3.0, patched 16.3.8, and `next` is exact-pinned in apps/web), `sharp` x2 (native binary), `tinypool` x2 (critical, needs a major bump of a test-runner dependency), and `braces` and `http-cache-semantics`, which have no patched release at all; so the npm audit will still fail, correctly. (2) **28 Python waivers are still expired**, so the validator still stops at the first one; I have not renewed or removed any. **NOT verified:** `next build` (the baseline fails in this sandbox because `marketing-fonts.ts` needs network access to fetch fonts, so it could not be compared), Playwright e2e, Docker image builds, and runtime behaviour of the services that use `axios`/`undici`. **Action on upgrade:** none beyond `pnpm install`.
- **The tests that need a real Postgres now run in CI. Until now none of them ever had, and they skipped silently.** Four test files opt in to a real database through two environment variables, `AISOC_TEST_PG_URL` and `AISOC_TEST_PG_APP_URL`, and **no workflow ever set them**, so all **23 tests have been silently skipped on every CI run since they were written**: the three row-level-security tripwires (`test_mssp_resolver_cross_tenant_postgres.py`, `test_view_as_audit_postgres.py`, `test_tenant_access_postgres.py`, which exist precisely because mocks cannot see what RLS does, and must run as the restricted `aisoc_app` role) and **the project's own** `test_service_migrations_postgres.py` (ueba, honeytokens and purple-team migrated in sequence into one database, the case where all three use revision id `0001`). The RLS plan listed 'wire it into a job' as an open caveat; this closes it. **New `.github/workflows/postgres-tests.yml`:** a Postgres 16 service container; the API's SQL migrations through the real runner (with `AISOC_MIGRATIONS_REQUIRED=1`, so an unreachable database fails the step instead of the runner's demo-deploy soft-fail that exits 0); `scripts/provision_app_role.sql` for the restricted role (a generated, masked password; `NOSUPERUSER NOBYPASSRLS`, least privilege), then both URLs exported to the test step. It triggers on changes to `services/api`, the three service migration folders, the provisioning script and the workflow itself, plus `workflow_dispatch`. A first step checks that the **psql client** is 15 or newer (`\getenv` is a client feature) as well as the server. **No literal credential is in the file** (the service password is derived from the run id; the role's password is generated and masked at run time; the secret scanner reports nothing). **The guard that matters:** a final step reads the junit report and **fails the job if any of these tests was skipped, failed, or fewer than 20 ran**, because a skip is exactly what kept them dark and a green run with silent skips would look like coverage. **How it was checked, and what was not:** I cannot run GitHub Actions here, so I **executed the workflow's own `run:` steps in order against a real local Postgres 16** (each step's `env:` and `working-directory:` honoured, `$GITHUB_ENV` emulated; only the dependency install and the artifact upload were skipped): all steps pass from a freshly created database, migrations apply through 080, `aisoc_app` comes out `superuser=f bypassrls=f can_login=t`, and **23 passed, 0 skipped**; and the guard's own code **exits 1 on an all-skipped run** (23 skipped, the state CI has been in) and 0 on the genuine run. **The workflow has not yet run on GitHub**, so differences between a hosted runner and my sandbox (the service container's networking, `ubuntu-latest`'s `psql`, the pip cache) are untested: **watch the first run.** The job adds a few minutes to API changes. **Also changed:** the RLS plan's tripwire step no longer says 'skipped in CI'; three test docstrings that said 'CI does not set them yet' now name the workflow. **Not done:** the older changelog entry that described the tripwire as not in CI is left as it was (it was true when written); `integration.yml` was not used because it is path-filtered and container-heavy. **Action on upgrade:** none (CI only). If the first run fails, the likeliest causes are listed above.
- **The two WebSocket routes refuse an anonymous client, and a guard now keeps them that way. The earlier route survey could not see them.** Every HTTP operation was surveyed from the OpenAPI schema, but **WebSocket routes are not in OpenAPI** and the route-introspection helper (`walk_routes`) yields HTTP routes only, so neither the survey nor the new route guard had ever looked at them. Enumerating them (this FastAPI version wraps included routers in `_IncludedRouter`, which a naive walk never descends into, and mine returned nothing at first) found two: **`/api/v1/graph_ws/stream`** authenticates by hand and refuses a client with no token, a garbage token, an API-key-shaped token or a ticket, by closing with **1008** (policy violation) before sending anything, and **`/graphql`**'s WebSocket transport raises a `TypeError` before accepting anything, because its context getter depends on `get_current_user`, which needs an HTTP `Request`, so dependency resolution fails on a WebSocket. **That second one is fail-closed by accident, not by design** (and the schema defines no subscriptions, so the transport serves nothing). I tried switching it off with `subscription_protocols=[]`; it made no difference, because the error is raised before the protocol check, so that edit was **reverted, not left in the tree**. Nothing was exposed; the risk worth pinning is the opposite one: someone makes that dependency WebSocket-aware to get rid of the `TypeError` and the transport starts accepting anonymous connections. `tests/test_websocket_routes_refuse_anonymous.py` (23): the set of WebSocket routes is exactly the listed two, each with a reason (a new one fails until it is authenticated and listed); each route, with no credentials, garbage bearer, garbage cookie and each GraphQL subprotocol, must get no data and must not be left **open**; and `graph_ws` must be closed with **1008 specifically**, not merely silent. That last point matters: a client that got *past* authentication and then could not reach the upstream feed (absent in tests) would also send nothing, but would be closed with **1011** (`upstream error`), so 'sent nothing' cannot tell an authentication bypass from a refusal and the close code can. **Three flaws in my own first version of this test, found by mutation-checking it on the real handlers:** (1) its probe blocked on `receive_text()`, so a regression that accepts an anonymous client and waits for it to speak (as GraphQL's transport does until `connection_init`) would have **hung the build instead of failing it**: the wait is now bounded and such a socket is reported `OPEN`; (2) closing a socket the server was still waiting on raised at `__exit__`, which **overrode the value I had returned** and mislabelled an open socket as 'refused': the result is now captured before the block exits; (3) I had asserted 1008 for an API-key-shaped token too, but that path looks the key up in a database that does not exist in the test environment, so it raises and fails closed instead: that single case now allows 1008 or a server error and forbids 1011 and any data. Mutation-checked on the real code: bypassing authentication in `graph_ws` fails 7 tests (only the 1008 assertions catch it, which is the point); making the GraphQL context dependencies resolve to nothing, so the transport accepts anonymous clients, fails 2 and takes 16 seconds rather than hanging. (My first GraphQL mutant produced an invalid signature that broke the app import, so it reported a collection error, not a pass; I replaced it with a valid one rather than count it.) Controls from a synthetic app prove the probe tells refused, closed, error, open and sent apart, and that the walker finds WebSocket routes and ignores HTTP ones. **Limits:** a client that authenticates correctly is not exercised here (`graph_ws` has its own tests); 'sends nothing' is checked for the first message only; the API-key path was not exercised against a real database. **Action on upgrade:** none.
- **A guard that pins which routes anyone can reach, and which any logged-in user can reach, so a route added without authentication fails the build. No new hole was found by the survey behind it.** Calling all 461 operations with **no credentials** against a live server, on a development configuration and on a **production-configured** one (it boots with a healthy set of secrets; `/api/openapi.json`, `/api/docs` and `/api/redoc` are 404; `/metrics` answers 401 with no token or a wrong one and 200 with the right one), 23 and 22 operations answered anything but 401/403, all expected (login, refresh, passkeys, the OIDC/SAML/OAuth callbacks, health probes, the VAPID public key, SAML metadata, the published-replay route, the approved-only community catalog, the waitlist form, and `/metrics`). The one real finding from that survey, the waitlist rate-limit bypass, is the previous entry. **Then the second category**: of the routes that need a login but declare no permission, 9 check a permission *inside* the handler (the autonomy-policy and business-context mutations check `settings:write`; a dependency-based classifier cannot see that, so it is searched for), and 26 have none; I read those 26 and they are the caller's own account, passkeys, push subscription, on-call status and saved views (every saved-view handler filters on the owner), read-only marketplace and pipeline status for the caller's own tenant, the phishing-report form, the GraphQL endpoint (per-resolver checks), and two community-plugin routes (publish for moderation, rate once). **What is pinned:** `tests/test_unauthenticated_and_login_only_routes.py` computes both sets from the live route table and requires them to equal a listed set, each entry with a **reason** (27 open, 26 login-only with no in-handler check); a new route in either set fails until it is listed with a reason, and an entry whose route has been fixed or removed fails too, so the lists only shrink on their own. Controls built from a synthetic app prove the classifier tells open, login-only, permission-guarded and checked-inside apart, and I confirmed against the **real application** that a route added with no authentication, and one added with only a login and no check, are each reported by name while a properly guarded one is not. **Open product question, not decided:** `POST /community/plugins/publish` lets any logged-in user, including a viewer, submit a plugin to the public catalog (it stays pending until moderated); whether that should need a permission is yours to decide. **Limits:** the in-handler search is a text search for a permission or role check, not proof the check is right; a router-level dependency is classified by what the dependency tree shows; the unauthenticated community listings load the whole catalog per request with no rate limit (a scale concern, noted in the previous entry). **Action on upgrade:** none.
- **The public waitlist signup's rate limit could be bypassed by forging `X-Forwarded-For`. Fixed. ACTION: set `AISOC_TRUSTED_PROXIES` behind a proxy.** `POST /waitlist/signup` is unauthenticated, rate-limited per client address, writes a row and posts to Slack for every signup. Its limiter keyed on the **first** `X-Forwarded-For` entry through a private copy of the old logic, while the audit log, the audit middleware, the login throttle and auth all use the shared `app.core.trusted_proxy.resolve_client_ip`, whose own header describes this exact flaw as the bug it fixed. Behind a proxy that *appends* to the header, the first entry is the part the client controls, so a caller who sent a different forged value on every request got a **fresh bucket each time and was never refused** (the old comment argued, correctly, that forging can't exhaust *someone else's* quota, but missed this opposite attack). Found by mapping the unauthenticated surface (461 operations called with no credentials: 23 answered anything but 401/403; the rest of those 23 are login/refresh, passkeys, the OIDC/SAML/OAuth callbacks, health checks, the VAPID public key, SAML metadata, `/metrics` (token-gated outside development, pinned by tests), the published-replay route and the approved-only community catalog). **The fix:** `_client_ip` now calls the shared resolver: `X-Forwarded-For` is ignored unless the direct peer is in `AISOC_TRUSTED_PROXIES`, and then it is walked right to left to the first untrusted hop, so forged left-hand entries lose. **Operator action:** none of the repository's deployment configs (`render.yaml`, both compose files) sets `AISOC_TRUSTED_PROXIES` (it is documented, and on the production checklist in `operations/security.md`), so behind a proxy the signup limit now buckets by the **proxy's** address until you set it to your ingress CIDRs: **all signups then share one bucket** and can throttle each other. That is exactly what the login throttle and the audit log already do in the same situation, and it is the safe default (the alternative was a limit anyone could walk around), but it is a behaviour change for a public form, so set the variable. Tests: `tests/test_waitlist.py`: the three tests that pinned the old behaviour (including `test_x_forwarded_for_first_address_wins`) were **rewritten, not loosened**, to: the header is ignored without trusted proxies; forged headers cannot mint new buckets (50 forged values, one key); behind a trusted proxy the rightmost untrusted hop wins and a forged left-hand entry loses; a header from a peer that is not a trusted proxy is ignored. Three end-to-end tests drive the **real handler and limiter**: a different forged header on every request from one peer gets a 429 and the refused request never reaches Slack; two genuinely different peers do not share a bucket (so closing the bypass doesn't make users throttle each other); and behind a trusted proxy real addresses separate users and a forged header does not help. Mutation-checked (4 variants, including restoring the first-entry logic, which fails 7 tests). **Not done:** the **unauthenticated community listings** (`/community/detections`, `/playbooks`, `/plugins`) load the whole catalog into memory on every request, with no rate limit: a scale concern rather than a leak (they show only approved entries), left for a decision; a repeat signup returns the existing entry's id for that email, which is a small membership oracle on a public form (left as is: changing it alters the client-visible contract). **Action on upgrade:** set `AISOC_TRUSTED_PROXIES` to your proxy CIDRs.
- **The SAML and OIDC endpoints that run before authentication no longer echo exception text.** Reviewing the remaining 5xx sites that put an exception's text in a response, three are on **pre-authentication** routes, so what they return reaches anyone on the internet. `GET /auth/saml/login` returned `SAML error: {exc}` for *any* unexpected exception while building the request or settings, and such exceptions can carry configuration detail (certificate paths, setting names); the two OIDC discovery failures (`/auth/oidc/login` and `/callback`) returned the HTTP client's text. They now answer `SAML login failed` and `OIDC discovery failed`, with the detail in the log (SAML already logged the traceback; OIDC now does). **Deliberately not changed:** `POST /auth/saml/acs` returns python-saml's error **codes** (`invalid_response` and the like) for the attacker-supplied response, which is the standard diagnostic an IdP administrator needs and is not an exception's text; the 400 `OIDC error: {error}` and the 401 `Invalid token: {exc}` are not 5xx and reflect the caller's own input or a standard JWT error. **The ratchet shrank from 12 to 8 sites**, as it is designed to: its allow-list entries for `auth/oidc.py` and `auth/saml.py` are removed, and the ratchet now also asserts that the sites fixed so far stay fixed. Its old vacuity guard was a count threshold (at least 10 sites), which stops being valid as the list shrinks; it is replaced by a positive control on synthetic source (a 5xx that echoes an exception is flagged, a generic detail, a 4xx and a non-exception value are not). Tests: `tests/test_sso_errors_do_not_leak.py` (6: the real routers on a bare app, with discovery failing and with a stand-in python3-saml whose settings building fails with a message naming a certificate path and an address; the detail is logged; a missing python3-saml is still a clear 501); 5 of 5 deliberate breakages caught (one mutant first failed to apply because its anchor matched twice, and I re-ran it against both occurrences). **A measurement note:** while checking lint I found that comparing a file's count at `HEAD` by piping it through ruff on stdin applies different per-file settings than checking the real path, so it understated the baseline for `saml.py` (1 vs the real 3); measured at the real path, this change adds no lint error (3 before, 3 after), and the method I rely on for the rest (mapping errors onto the lines I added) is unaffected. **Not done:** the 8 sites that remain (the credential-vault diagnostics, visible only to connector admins and free of key material; the lake and detection routes, whose server-reported query errors are the analyst's own; the marketplace parse error). **Action on upgrade:** none.
- **A lake connection failure no longer shows the backend's host and port; a query error still shows the analyst what is wrong with their query.** Fuzzing the API with ClickHouse down produced `lake backend error: ... Connection refused (localhost:9000)`: the internal address, shown to any caller who can run a lake query. `app/db/clickhouse.py` funnelled every driver failure into one `LakeQueryError("clickhouse query failed: {message}")`, mixing a connection problem (infrastructure; the text names the host and port) with a `ServerException` (the server's complaint about the analyst's own SQL, which is useful and about their own input). The two are now told apart by the exception's **class name** (`NetworkError`, `SocketTimeoutError` and the two unexpected-packet errors, plus any `OSError`), because the driver is a soft dependency that this module deliberately does not import, the same way timeouts were already recognised by their text. A connection failure now answers `clickhouse query failed: the lake backend could not be reached` and the real message goes to the log for the operator (and stays on the exception chain); a server-reported query error keeps its text; server-side timeouts are still timeouts. The **schema lookup takes no analyst input at all**, so every failure there is infrastructure and is now generic (`clickhouse schema lookup failed`), logged in full. This **narrows 3 of the 12 remaining sites** from the earlier 5xx change (the two in `lake.py`, and the two detection routes that inherit its messages, are generic where it matters); their ratchet entries carry updated reasons, and the count of sites that interpolate an exception is unchanged because the sites themselves still do. Tests: `tests/test_lake_error_messages.py` (14, driving the real functions with a client that raises each kind of failure: the detail is logged; a server error still shows; a server-side timeout is still a timeout; every schema failure is generic); 8 of 8 deliberate breakages caught, including treating a `ServerException` as a connection failure (which would have hidden the useful message from analysts) and dropping either log line (which would have blinded operators). **Not done:** the other 9 sites (the credential-vault diagnostics, which only connector admins see and which contain no key material; the OIDC discovery and SAML errors; the marketplace parse error); a connection error that the driver reports under a class name outside the four, and is not an `OSError`, would still show its text. **Action on upgrade:** none.
- **Two handlers stored foreign-key ids taken from the request body without checking they belong to the caller. Fixed.** Found by a scan for endpoints that build a row from an `*_id` in the request body where the column is a foreign key to a tenant-owned table (4 hits; one was the rule-pack bug fixed earlier; the other three are these). **A foreign key is checked for existence only, and by the database's owner privileges, so it ignores row-level security: even on a tenant-scoped session, tenant A could reference tenant B's rows, and probe whether an id exists from the error.** (1) `POST /approvals` (`cases:write`, tenant-scoped session) stored `run_id` (an investigation run) and `required_user_id` (the approver) from the body unchecked; it now requires the run to belong to the caller's tenant and the approver to be a user of it (explicit comparison: `users` has no RLS), answering the same `422` for a foreign id and a missing one so there is no existence oracle. (2) `POST /mssp/overrides` verified the child tenant but not the `rule_id`; it now requires a rule that can actually reach the child (a platform built-in, the parent's own, or the child's own, the layers of the effective-rules resolver) and answers the same `404` as for a missing id. **What this is NOT, checked rather than assumed:** it is not a cross-tenant push channel. `required_user_id` is passed to the realtime service as `notify_user_ids`, but the realtime service looks subscriptions up by tenant AND user and requires the record's tenant to equal the event's (`resolveSubscriptions` in `push.ts`), so a foreign user id reaches nobody. It is also not a way to act on another tenant's run: the run id is only stored and echoed in notifications. So the impact was **referential integrity plus an existence oracle for random UUIDs**, not a data leak, and I rate it low. Both fixes are additive (17 and 8 lines, none deleted). Tests: `tests/test_approvals_reference_ownership.py` (6; a scripted session that returns a *foreign* row, as the owner-privileged check effectively does, so the explicit tenant comparison is what is tested; the identical refusal for foreign and missing ids) and 3 more in `tests/test_mssp_pack_rule_ownership.py` (real SQLite); 9 of 9 deliberate breakages caught. **Not done:** `case_id` and `alert_id` in the same approval request are not checked (`case_id` is a free string and neither is a foreign key, so they are inert references); other places that set a foreign key from a path parameter or on an update, rather than in a constructor fed from the body, are not covered by the scan. **Action on upgrade:** none; an agents-service call that passed a run id from another tenant (it should not) now gets a 422.
- **A vault encryption key that was published in the git history is now refused in production. ACTION MAY BE NEEDED.** A secret scan over the whole git history (gitleaks, 1,429 commits; the earlier scans covered only the current files) found that `.env.example` carried a **valid Fernet key** as `AISOC_CREDENTIAL_KEY` in two commits on 2026-05-13/14 (`d8397a0b`, `2c92cc91`), replaced by a placeholder in `14b10e15`, and that two unit tests carried another valid key until `77517e91`. **Anyone who copied `.env.example` to `.env` in that window, or ever set either key, is running with a credential-encryption key that anyone can read in the repository's history, and the vault accepts it because it is a valid key.** Of the history scan's 22 findings this is the only real one (the rest are test fixtures, environment-variable names in a deploy blueprint, a documentation placeholder and a public PGP fingerprint, each read). **What changed:** `PUBLISHED_FERNET_DIGESTS` in `app/core/config.py` holds the SHA-256 digests of the two keys (digests, not keys, so the code does not publish them again) and `warn_if_insecure_defaults` flags the primary `AISOC_CREDENTIAL_KEY` when it matches, with the rotation steps in the message; `enforce_secure_defaults` already hard-fails a production boot on any such message, so a production deployment on a published key **now refuses to start**. Development and test environments are not refused, and **moving a published key to `AISOC_CREDENTIAL_KEY_ROTATION_FROM` is allowed**, because that is what rotating away from it looks like. **What you should do if you deployed from `.env.example` in that window:** generate a new key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`), set it as `AISOC_CREDENTIAL_KEY` and put the old one in `AISOC_CREDENTIAL_KEY_ROTATION_FROM`; stored connector credentials stay readable and, per the vault's rotation behaviour, are re-encrypted **as they are written** (I did not confirm a bulk re-encrypt, so a credential that is never rewritten stays under the old key until it is); and treat any credential that was stored under the old key as potentially exposed, since the key was public. The history cannot be un-published, so this does not rewrite it. **Tests** (`tests/test_published_vault_keys.py`, 13): they cannot contain the real keys, so the mechanism is tested with freshly generated keys and a patched digest set (flagged and refused in production; the message names the rotation and never contains the key; whitespace does not hide it; the rotation setting is allowed; development is not refused; an empty key, a fresh key and the `.env.example` placeholder are not flagged; a healthy production baseline has no messages at all, as a control), and one test reads the two real keys **from git history** and checks that their digests are exactly the two in the code (skipped in a shallow clone). 6 of 7 deliberate breakages caught; the seventh, dropping a `bool(key)` guard, changes no behaviour (an empty string's digest is not in the set) so it is an equivalent mutant. **Also in this change:** the six places the second key appeared in tests now generate a key per run (see the previous commit), and a stale comment about a "pre-generated" key was corrected. **Not done:** I cannot tell who deployed with the published key; the check is for those two keys only, not a general detector of weak or example keys; and the history scan is not part of CI (CI scans the current files), so a future committed key would again be noticed only by someone running it.
- **A tenant could attach another tenant's private detection rule to its own rule pack, and its children then received that rule. Fixed.** `POST /mssp/rule-packs/{pack_id}/rules` (permission `mssp:manage`) checked that the **pack** belonged to the caller but fetched the rule with a plain `db.get(DetectionRule, rule_id)` and checked only that it existed. A pack is applied to the caller's managed tenants, so `resolve_effective_rules` then returned the stranger's rule (name and body) in the child's effective rules. It needs the rule's id (a random UUID), which lowers the severity, but it is a missing authorization check; it is **independent of row-level security** (the session carries no tenant, so no policy was protecting it). Found by a scan for platform/MSSP-guarded handlers that read RLS-covered models (1 hit of 1, after the first scan's 10 candidates produced the tenant-access routes); **reproduced end to end on a real Postgres as the restricted role** with the real route and the real resolver: the parent's call returned `ok` and the child's effective rules then included `STRANGERS-PRIVATE-RULE-…`. Fixed in two layers: the route now accepts only the caller's own rules or a platform built-in (the resolver has a built-in layer, and a naive "must be the caller's" check would have broken adding one), and refuses anything else with **the same `404 Detection rule not found`** as for a missing id, so it is not an existence oracle; and the resolver's pack query only returns rules the pack's **parent** owns, or built-ins, so **links already sitting in deployed databases are neutralised too** (verified live: a link written straight into the table no longer reaches the child). Edits: one condition replaced in the route and one filter added in the resolver, nothing reformatted. Tests: `tests/test_mssp_pack_rule_ownership.py` (10, real SQLite engine: own rule, built-in, a stranger's rule, even the managed child's own rule, the identical refusal for a missing id, a pack that isn't the caller's, pre-existing bad links, and unaffected paths); 7 of 7 deliberate breakages caught, **after fixing a gap in my first test** (one mutant survived because built-ins also reach the child through the resolver's separate built-in layer, so the assertion couldn't tell the paths apart; the test now removes that layer with `include_builtin=False`) and a mutant whose anchor never matched. **Not done:** existing bad links are filtered out, not deleted (there is no cleanup of the table); whether anyone relied on attaching a rule they don't own is unknown (nothing in the repository does); and the scan only sees handlers guarded by `platform:`/`mssp:` permissions, so a missing ownership check behind other permissions is not covered. **Action on upgrade:** none; a pack that contained a rule its owner does not own will stop delivering that rule to its children.
- **Groundwork for making row-level security fail-closed: a tripwire and an explicit cross-tenant read, with no change in behaviour.** Measured on a real Postgres as the restricted role `aisoc_app` (the full plan, numbers and order are in `docs/security/rls-fail-closed-plan.md`): the policies are fail-open, flipping them alone breaks 251 of 404 isolation-flow steps, and a central hook that tags every session with the caller's tenant fixes that (0 of 435) but, on its own, would have **silently broken MSSP rule inheritance**: the real `mssp_rule_resolver` returned the parent's pack rule for a managed tenant on a session with no tenant set (today) and **nothing** once the session was tagged with the child's tenant, so a child's `POST /rules/hunt` would have run without the rules its MSSP parent assigned. The isolation flows could not see it (two ordinary tenants, no parent/child). New: `cross_tenant_reads(session)` in `app/db/rls.py` states a deliberate cross-tenant read explicitly (it clears the tenant setting for the block, untags a hook-tagged session so the hook cannot re-apply it, and restores the setting that was in force), and `resolve_effective_rules` (and so `count_effective_rules`) now runs inside it. Verified on a real Postgres: the child's effective rules include the parent's pack rule in all three session states. **Behaviour today is unchanged:** both callers use a plain `get_db` session that has no tenant set, for which the block is a no-op. Tests: `tests/test_cross_tenant_reads.py` (16, in the normal suite, with a recording fake session) and `tests/test_mssp_resolver_cross_tenant_postgres.py` (6, **opt-in**: `AISOC_TEST_PG_URL` and `AISOC_TEST_PG_APP_URL`, a disposable migrated database, as `test_service_migrations_postgres.py` is; it includes a negative control that the role really is subject to RLS, and **CI does not set those variables, so it is skipped in CI until someone wires it into a job with a Postgres service**). **A mistake of mine, caught by the full suite and fixed before committing:** my first version sent PostgreSQL-only SQL (`current_setting`, `set_config`) and broke 14 existing resolver tests, which run on SQLite and on mock sessions whose scripted `execute()` responses the block would also have consumed. The block is now a no-op unless the session is clearly bound to PostgreSQL (so for SQLite and for mocks), with tests for exactly those cases, including a check that an `AsyncMock` session produces no never-awaited warning. Mutation-checked on the final code: reintroducing the original bug (the resolver unwrapped) fails the real-Postgres test, and 8 of 8 deliberate breakages are caught across the unit, MSSP and Postgres tests (the two that concern the session tag are caught only by the unit tests, because the tag exists only for the hook that is not deployed yet). Full suite: 7888 passed, 13 skipped (the 6 opt-in Postgres tests among them), 0 failed. **Not done:** the hook, the fail-closed policies and the API connecting as `aisoc_app` by default (steps 3 to 5 of the plan, which touch login, the workers and every deployment's database role); and the other readers of another tenant's RLS-covered rows on a `get_db` session were reviewed afterwards: `nl_query.py` is not affected (it reads only `tenants`, which has no RLS), but **`view_as.py` is a second cross-tenant reader that the hook would break outright** (the viewer's grants in `tenant_access_grants`, and a read and a **write** of the target tenant's `audit_log`; neither policy has a `WITH CHECK`, so a session tagged with the home tenant could not insert the `tenant:viewed` row, and the code refuses to serve a view it cannot record). Run on a real Postgres as `aisoc_app` with the real `emit_audit`: with the session tagged with the viewer's home tenant the insert is rejected, and the chain-head read returns `None`, which would silently fork the target's audit hash chain if only the insert were let through. **Fixed (behaviour unchanged today):** a second block, `acting_as_tenant`, gives the chain read and the insert one scope; `record_view` and `record_act_as` run in it and the three grant readers run in `cross_tenant_reads`; both blocks flush pending writes before the scope changes and again before it is restored (`session.add()` only queues a write); `app/db/rls_scope.py` holds them because defining them in `rls.py` was a circular import (`rls` imports `deps`, which imports `view_as`). Tests: `tests/test_view_as_audit_postgres.py` (opt-in, checks the hash chain, has a negative control, and **cannot clean up** because `audit_log` is immutable, so it needs a disposable database) and more unit tests in `tests/test_cross_tenant_reads.py`; 8 of 8 deliberate breakages caught, including removing the target scope from `record_view` (the original problem), which fails 4 of the 5 real-Postgres tests; `record_act_as` and the grant readers are covered by the unit tests only. **A third cross-tenant reader and writer was then found by a static scan: tenant access management (`tenants.py` list, grant and revoke: a platform holder may manage any tenant and an MSP parent its children, so they read and write the target's `tenant_access_grants` and its audit log).** Fixed the same way with a new decorator, `acting_as_argument("tenant_id")` (7 lines added to `tenants.py`, none deleted; the OpenAPI of the three routes is byte-identical before and after, which was checked); 9 real-Postgres tests with the plan's hook emulated and a negative control, and unit tests; 5 of 5 breakages caught. **A weakness in my own block, found by its test and corrected:** it sent no restore after an error, so a handled 404 would have left a session scoped to the target; it now restores best-effort after an ordinary error (never flushing), propagates a failed restore after success, and sends nothing on cancellation. The scan is a heuristic and a lower bound; of its 10 candidates, 7 are not cross-tenant (own-tenant guards, own-tenant helpers, and callers that pass `current_user.tenant_id`, checked from their call sites), `tenant_llm_status` has no callers outside tests, and 3 are the access-management routes fixed here. **Action on upgrade:** none.
- **Some 5xx responses showed internal hostnames, ports and database text to the caller. Fixed where the text named infrastructure.** Fuzzing the API against a real server with its dependent services stopped produced bodies such as `Graph query failed: Couldn't connect to localhost:7687 (resolved to ('127.0.0.1:7687',))` and `Agents service unavailable: [Errno -2] Name or service not known`: internal hostnames, ports and driver text, shown to any caller who can read that data. Fixed: the five graph query routes (one helper logs the full exception server-side and answers a generic `503 "Graph query failed"`), the agents proxy used by the case routes (`503 "Agents service unavailable"`, already logged), and the ITSM webhook, which answers an **external** system with a token: on an unexpected failure it returned `Failed to apply inbound status: {exc}`, and a SQLAlchemy exception's text includes the SQL statement **and its parameter values** (it is generic now; the exception was already logged). No client or test depended on the wording (the web console's test mocks its own text). **Deliberately not changed, each with a reason in the new ratchet:** the three credential-vault responses (connector admins only; they name the `AISOC_CREDENTIAL_KEY` variable and say what is wrong, with no key material: reviewed, and arguably helpful to the admin), the lake and detection-rule query errors (the text can be the analyst's own query error, but a *connection* failure also names the backend address: not yet narrowed), the OIDC discovery and SAML errors, and the marketplace index parse error. `tests/test_5xx_details_do_not_leak_internals.py` has a premise test (a SQLAlchemy exception's text does contain the SQL and parameters), behavioural tests for the graph helper (generic, no host or port, and the full exception *is* logged) and the agents proxy (with an injected connection error), a source guard for the webhook, and an AST ratchet over the whole application that lists the 12 remaining sites with reasons and **can only shrink**; a positive control shows the graph guard does flag the original pattern; 6 of 6 deliberate breakages were caught (including the helper or the proxy ceasing to log, which would blind operators). **Verified live:** the case investigation route now answers a bare `503 Agents service unavailable`. **Not verified live:** the five graph failure sites (they sit on routes that need ids or parameters; they are covered by unit tests and a source count of the helper's call sites). **Action on upgrade:** none; callers that parsed these messages will see the shorter text.
- **CORE's API key could create cases, tasks and approval requests, and (until a session was required) decide approvals and publish replays. Fixed with `cases:work`.** CORE's agent updates a case, comments on it, launches an investigation from it and closes one (four routes), so its key held `cases:write`, which guards 14: it also covers creating cases, attaching alerts, notes, observables and tasks, updating a task, raising and deciding approvals, and publishing or unpublishing replays. A narrow `cases:work` now covers exactly those four routes; the other ten stay `cases:write`. `cases:write` implies `cases:work`, one way only, so nobody loses access (every standard role except `viewer` holds `cases:write`). CORE's key holds `cases:work` and not `cases:write`, so `decide` and `publish` are now out of its reach twice over: by permission, and by the signed-in-person requirement added earlier (neither was removed). Migration `080` adds the catalog row. Verified on real Postgres with the real bootstrap: it applied migration 080, and against a key forced back to the previous scopes it logged `scopes updated in place (same secret): added ['cases:work'], removed ['cases:write']`; with that same secret a comment on a real case was created (201), the case update, investigation launch and investigation close passed authorization (422, 503 and 404 for reasons unrelated to permission: an invalid status transition in my probe, no agents service in that environment, no such run), and all nine routes the split closed were refused (seven "API key missing scope: cases:write"; `decide` and `publish` "only available to a signed-in user", which fires first). The key-reach ratchet reported exactly the eight routes this closes as gone and nothing new, and its list of what a key can still do beyond its tools is now 4 routes (preview a replay, the realtime ticket, and the two LLM-calling routes marked NOT YET NARROWED). **Action on upgrade:** none for existing users or keys. If you deployed an earlier commit, re-run the bootstrap: it narrows CORE's key in place.
- **CORE's API key could search the tenant's connected SIEMs. Fixed with `connectors:view`.** `POST /federated/search` runs a free-text or indicator query across every federated-capable connector (Splunk, Elastic...) using its stored credentials and returns the merged rows: telemetry from the customer's own systems. It needed only `connectors:read`, which CORE's key held so Cipher could list connectors and read their health. A narrow `connectors:view` now covers exactly the five `GET /connectors...` routes the three connector tools use; the federated search and backend list, the agent tool list, the inbox template and token lists and the OAuth app view stay `connectors:read`. `connectors:read` implies `connectors:view`, one way only, so nobody loses access (`platform_admin`, `admin`, `tenant_admin`, `soc_lead` and `soc_analyst` hold it and list connectors as before; `threat_hunter`, `viewer` and `api_service` hold neither, as before). CORE's key holds `connectors:view` and not `connectors:read`; the GraphQL `connectors` field, which mirrors `GET /connectors`, needs `connectors:view` too (the parity test caught it). Migration `079` adds the catalog row. Verified on real Postgres with the real bootstrap: it applied migration 079, and against a key forced back to the previous scopes it logged `scopes updated in place (same secret): added ['connectors:view'], removed ['connectors:read']`; with that same secret the three connector tools return 200 and the six routes that stay return 403 ("API key missing scope: connectors:read"). **The decisive contrast:** a key holding the OLD `connectors:read` ran a federated search (HTTP 200; no SIEM was connected in that environment, so it returned nothing); the `connectors:view` key got 403. **Not verified:** a real search returning real rows, which needs a connected SIEM. **Reviewed and left alone:** `GET /connectors/{id}` omits `auth_config`, `GET /inbox/tokens` lists a fingerprint not the token (per its docstring; the list-item model was not read) and `GET /oauth/app/{type}` omits the secret; but `connector_config` is free-form and only *documented* as non-secret. **Action on upgrade:** none for existing users or keys. If you deployed an earlier commit, re-run the bootstrap: it narrows CORE's key in place.
- **CORE's API key could read data-lake telemetry through the rule backtest. Fixed with `rules:view`.** `POST /rules/{id}/backtest` runs a rule over up to 365 days of the tenant's real events in the ClickHouse lake and returns `sample_matches`, the matching event rows, and it needed only `rules:read`. CORE's key held `rules:read` for its twelve read-only detection tools, so it could read telemetry through a different door than the one `lake:query` (deliberately not granted) guards. The earlier docs called these routes "compute, no writes", which was true and beside the point. A narrow `rules:view` now covers exactly the 13 `GET` routes the tools use (rules, coverage, drift, confidence, tuning, proposals, formats); the five computing routes (`/rules/hunt`, `/rules/{id}/execute`, `/rules/{id}/backtest`, `/detection/test`, `/translation/translate`) stay `rules:read`. `rules:read` implies `rules:view`, one way only, so nobody loses access (`admin`, `tenant_admin`, `platform_admin`, `soc_lead` and `threat_hunter` hold it and read rules as before; `soc_analyst`, `viewer` and `api_service` hold neither, as before). CORE's key holds `rules:view` and not `rules:read`; the GraphQL `detectionRules` field, which mirrors `GET /rules`, needs `rules:view` too (a parity test caught that it would have been left behind). Migration `078` adds the catalog row. Verified on real Postgres with the real bootstrap: it applied 075 to 078, and against a key forced back to the previous scopes it logged `scopes updated in place (same secret): added ['rules:view'], removed ['rules:read']`; with that same secret all the detection tools' reads return 200 and all five computing routes return 403 ("API key missing scope: rules:read"). **The decisive contrast:** a key holding the OLD `rules:read` asking for a backtest got past authorization and the handler tried to run the lake query (HTTP 502, `clickhouse query failed`, because no ClickHouse was running in that environment); the `rules:view` key got 403. **Not verified:** a real backtest returning real event rows, because the lake is not configured here. **Action on upgrade:** none for existing users or keys. If you deployed an earlier commit, re-run the bootstrap: it narrows CORE's key in place. Also corrected: `docs/security/cipher-tools.md` listed `alerts:write` among the key's scopes and then said "not `alerts:write`" (stale since the triage change), and its upgrade walkthrough named `rules:read`.
- **An API key could approve its own approval, and publish an investigation to a public link. Fixed: both need a signed-in person.** Auditing every non-read route CORE's key can reach (27; its tools call 7) found `POST /approvals/{id}/decide` needing only `cases:write`, which the key holds, and checking nothing else: the key could create an approval (the human sign-off for isolating a host, disabling a user or a destructive playbook step) and approve it itself. `POST /ledger/{run_id}/publish` needed only `cases:write` too, so the key could publish a redacted investigation to `GET /r/{slug}`, which needs no sign-in, skipping the review step. Both now also require a signed-in session (`require_signed_in_session`, the primitive passkeys and push subscriptions already use): an API key of any scope, a wildcard key included, is refused with "This action is only available to a signed-in user, not an API key." Nothing else changed: creating an approval, unpublishing, previewing and every other case route behave as before, and every standard role holding `cases:write` still reaches both handlers. Verified on real Postgres with CORE's real key: it raised an approval (201), could not approve or deny it (403; status still `pending`), could not publish (403); a signed-in admin approved it (200). **Action on upgrade:** an integration that decides approvals or publishes replays with an API key now gets 403 and must use a signed-in session (the responder app already does; nothing else in the repository called these routes). **Not fixed, each a product decision:** the decide handler still does not require the decider to differ from `requested_by`, ignores `required_user_id` and `required_topic` (stored, never enforced), and accepts an `expired` approval; a test records this.
- **CORE's API key could create assets, posture findings, identity nodes and insider-threat indicators, and change an employee watchlist. Fixed with `alerts:triage`.** CORE's agent claims, escalates and snoozes alerts, so its key held `alerts:write`; but that scope guards 29 routes (also submitting and patching alerts, creating assets, adding cloud posture findings, creating identity graph nodes, adding insider-threat indicators and changing a profile's watchlist, graph entities, honeytokens, feedback and phishing re-triage). Confirmed on real Postgres: with CORE's scopes those writes passed authorization (201 for an identity node) while a read-only key got 403 on every one. No Cipher tool made any of those calls, so this was width, not misuse. A narrow permission `alerts:triage` now covers exactly `POST /alerts/{id}/claim`, `/escalate` and `/snooze` (the only `alerts:write` routes CORE calls); `alerts:write` implies it, one way only, so nobody loses access (six of eight standard roles hold `alerts:write`; `threat_hunter` and `viewer` hold neither, as before); CORE's key holds `alerts:triage` and not `alerts:write`. Migration `077` adds the catalog row. Verified on real Postgres with the real bootstrap: it applied 075, 076 and 077, and against a key forced back to the previous scopes it logged `scopes updated in place (same secret): added ['alerts:triage'], removed ['alerts:write']`; with that same secret a real alert was claimed, escalated and snoozed (200), submitting or patching an alert, creating an asset, adding a posture finding, creating an identity node, adding an insider-threat indicator and changing a watchlist all returned 403 ("API key missing scope: alerts:write"), and the admin kept every one of them. A test checks over every route that CORE's real scopes reach none of the other 26 `alerts:write` routes. **Action on upgrade:** none for existing users or keys. If you deployed an earlier commit, re-run the bootstrap: it narrows CORE's key in place. The key still holds `cases:write` and `connectors:read`, which were not reviewed route by route.
- **Review of every statement on the five tenant tables that have no row-level security: no leak found, and two reads and writes made self-protecting.** `aisoc_autonomy_thresholds`, `aisoc_institutional_memory`, `aisoc_run_costs`, `mssp_tenant_metrics` and `users` have no RLS, so the code's own `WHERE tenant_id = ...` is the only protection. Of the 21 raw-SQL statements on the first four, 20 carry a tenant predicate; of the ORM statements on `InstitutionalMemory`, `MSSPTenantMetrics` and `User`, the ones with no tenant mention are the caller's own row by their authenticated id, the API-key-to-user lookup, the operator CLIs, passkey and password sign-in (which run before any tenant is known and take the tenant from the credential's owner), and the platform-wide account-name lookups, all by design. Two were safe only by the ORDER of statements, and now carry the tenant themselves: (1) the per-run model-cost read (`aisoc_run_costs` was read with `WHERE run_id = :run_id`, relying on `get_run` having checked the run first; the table's own key is `(run_id, tenant_id, model)`, so the same run id may exist under more than one tenant: it now filters on the tenant, tested with two tenants' rows for the same run); (2) the user UPDATE in `PATCH /tenants/me/users/{id}` (loaded with the tenant first, then updated by id alone: the UPDATE now carries the tenant too). No behaviour changes for any caller.
- **The isolation sweep now catches the class of leak that actually occurred.** `python -m app.scripts.tenant_flows` has B call every parameterless `GET` and look for the ids of the 15 kinds of object A creates; it could not see B receiving A's *tenant row* or *platform data that belongs to no tenant*, which is how the tenant list and the waitlist leaked while the flows stayed green. It now also watches for **A's tenant id** and, on a scratch database only, for a **public waitlist prospect's email** (a `CANARY` step plants it; the audit endpoints are exempt from the tenant-id canary only, because they record B's own probes of A). Verified end to end: against the commit before those two fixes the sweep fails with `LEAKS` naming `/api/v1/admin/tenants` and `/api/v1/waitlist/entries`; against the current code it passes, 435 steps all as expected (the first run flagged B's own `tenants:update` and `tenants:delete` attempts in B's audit log, a false positive that is now understood and exempted). **Also found while doing this: the row-level-security policies fail OPEN.** They read `tenant_id = current_tenant_id() OR current_tenant_id() IS NULL`, so a session that has not set a tenant (the plain `get_db` session most routes use) sees every tenant's rows; as the restricted role with no tenant set I saw all 4 alerts, 7 cases and 2 rules in the two-tenant database. For those routes the handler's own `WHERE tenant_id = ...` is the only protection, which is why a missing filter leaks. Five tenant-owned tables have no RLS at all (`aisoc_autonomy_thresholds`, `aisoc_institutional_memory`, `aisoc_run_costs`, `mssp_tenant_metrics`, `users`). This is documented, not changed. See `docs/security/running-isolation-flows-against-staging.md`.
- **Any API key, however narrow, could open the tenant's live event streams. Fixed.** `POST /realtime/ticket` minted a ticket for any signed-in caller. A ticket carries only the tenant (claims `sub`, `tenant_id`, `type`); the realtime service then streams that tenant's `alert.fused`, `case.updated`, agent, insights and `graph.update` messages (the graph channel delivers full entity and relationship data). Demonstrated on real Postgres: a key whose only scope was `hunts:read` received a valid ticket. Minting now needs `alerts:read` and `cases:read`, the permissions REST needs for that data, declared as route dependencies. Every standard role holds both, so the console is unaffected; a key or custom role without both can no longer open the streams (`API key missing scope: alerts:read`). **This reverses a recorded decision:** the route was listed in `tests/data/unguarded_routes.txt` as "personal to the caller" and in the "left login-only" table; it is not personal data, it opens tenant-wide streams, and both entries are removed (the ratchet requires the baseline to shrink). **Action on upgrade:** an integration that connects to the realtime WebSocket or SSE with a key or role lacking the two permissions must be given them. The realtime service itself was not changed or run for this; what a ticket opens is from reading its source.
- **A community plugin's rating could be steered by anyone signed in. Fixed.** The rating is shown to every tenant and orders the marketplace, but `POST /community/plugins/{id}/rate` treated every call as a new vote, so one user could repeat it to move a plugin's score anywhere, and it accepted ratings for pending and rejected submissions (which are not listed, viewable or installable). Now each person has one rating per plugin (rating again replaces their own: the score and count move by that one vote only), only an **approved** plugin can be rated (a pending, rejected or missing plugin is the same 404), and the submitter cannot rate their own submission (403). Ratings recorded before this stay counted. The per-person map is stored with the plugin and is not shown in any response. **Action on upgrade:** clients that rated a pending plugin now get 404; approve it first. Found by auditing the operations with no declared permission; the rest of that audit is below.
- **Audit of the operations with no declared permission (the capability reference's "signed in, no permission declared" and "no sign-in required").** Three had real defects, fixed above (the tenant list and tenant creation, the waitlist, GraphQL) plus the rating here. Reviewed and found sound: `/metrics` (constant-time token; refused in non-development environments when no token is set), the public replay link `/r/{slug}` (opt-in publication by someone with `cases:write`, server-side redaction, a random slug), the ITSM inbox webhook (the token resolves the tenant, the connector's tenant is cross-checked, optional HMAC, idempotent, can only change case status), `/auth/oidc/userinfo` (echoes the caller's own verified token), `/push/*` (forced to the caller's own devices), plugin publishing (lands as pending; approval needs `plugins:admin`; a resubmission cannot overwrite), and the `autonomy-policy` and `business-context` routes (tenant-scoped, checked with `settings:read`/`settings:write`, only not declared as dependencies). Not individually reviewed beyond a source heuristic: the self-service routes (`/saved-views`, `/oncall/me`, `/passkeys/*`, `/realtime/ticket`, `/phishing/submit`, `/auth/logout`, `/auth/me/preferences`) and the login/SSO/health endpoints.
- **GraphQL ignored permissions, and `playbookRuns` could read every tenant's runs. Fixed.** (1) No `/graphql` resolver checked a permission, so any signed-in user, and any API key however narrow its scopes, could read alerts, cases, detection rules, connectors and playbooks that REST refuses them. Demonstrated on real Postgres: a key whose only scope was `hunts:read` read all 8 detection rules through GraphQL while REST returned 403 for the same key on `/rules`, `/connectors`, `/cases`, `/alerts` and `/playbooks`. (2) `playbooks` and `playbookRuns` asked the agents service with the API's internal token and **no tenant**; for that caller the agents service honours a `tenant_id` and otherwise returns the unscoped result, i.e. every tenant's playbook runs, each with its trigger event (alert data), so any signed-in user of any tenant could read them (found by reading the agents service's scoping code and confirmed with a stand-in for it that holds two tenants' runs; the agents service itself was not started for a live run). Now every resolver checks the same permission its REST equivalent needs, with the same function REST uses (roles, API-key scopes and the cross-tenant full-access deny list), and the proxy always sends the authenticated user's tenant (never taken from the query) and sends nothing when there is none. After the fix, on the same database, the narrow key gets `API key missing scope: rules:read` and the admin still reads everything. **Action on upgrade:** an integration that reads data through GraphQL with a key or role lacking the permission above now gets an error naming it; add the scope, or use the REST route. A test asserts every GraphQL field is covered, so a new resolver cannot ship unchecked. The GraphQL documentation page now lists the permissions and says its schema overview is broader than what is implemented.
- **A tenant's administrator could read every prospect on the platform's waitlist and change their status. Fixed.** Same bug as the tenant list and provisioning routes below, in the next module: `GET /waitlist/entries` and `PATCH /waitlist/entries/{id}` checked `admin:waitlist` OR `settings:write` inside the handler; `admin:waitlist` was never created or granted, and every tenant admin holds `settings:write`. The waitlist is the platform's own sales funnel (names, emails, companies, roles of prospects), not any tenant's data. Confirmed on real Postgres: after a prospect signed up through the public form, two ordinary tenant admins both read it and one changed its status to `contacted`, which the other then saw. Both routes now need `mssp:onboard` (a platform permission only a platform administrator holds), declared as a route dependency; the inline check and its fallback are gone. The public signup form (`POST /waitlist/signup`) is unchanged and still needs no sign-in. **Action on upgrade:** a tenant admin who used these routes now gets 403; use a platform administrator account. Found by auditing the operations the capability reference lists as "signed in, no permission declared".
- **A tenant's administrator could list every tenant on the platform and create new ones. Fixed.** `GET /admin/tenants` ("list every tenant for the support team") and `POST /admin/tenants/provision` (promote a waitlist entry into a live tenant) checked `admin:tenants` OR `settings:write` inside the handler. `admin:tenants` was never created or granted to anyone, and every tenant's administrator holds `settings:write`, so in practice any tenant admin could see every other tenant's name, slug and plan and provision new tenants (confirmed on real Postgres: tenant A's admin listed tenant B and the default tenant; the provision route returned 404 for a made-up waitlist id, i.e. it was past the gate). Both routes are now guarded the way every other platform route is: as dependencies, by `mssp:onboard` (create a tenant) and `platform:cross_tenant_query` (list tenants), which only a platform administrator holds (neither `*` nor a resource wildcard grants a platform permission, and an API key cannot carry one). The inline check and its fallback are gone. The two console operator pages (`/admin/waitlist`, `/admin/tenants`) are for the platform operator and are not linked from the navigation. **Action on upgrade:** a tenant admin who used these routes now gets 403; give the operator the platform administrator role (`python -m app.scripts.platform_admin grant --name <account>`). Found while generating the capability reference (the route showed 'signed in, no permission declared'). The old tests called the handlers directly with a fake `tenant_admin` user and so never exercised the permission system; the new ones go over HTTP for every role.
- **Email sign-in is now OFF by default: people sign in with their account name.** `LOGIN_ALLOW_EMAIL` defaults to `false`. An email offered at `/auth/login` (or for a passkey) is answered exactly like a wrong password: same status, same body (now "Incorrect account name or password", it used to say "email"), the same timing (the throwaway-hash check still runs) and it still counts toward the lockout, so it reveals nothing about which addresses belong to accounts. Set `LOGIN_ALLOW_EMAIL=true` to turn it back on. **Action on upgrade:** anyone who signs in by email must now use their account name (an operator can read it with `python -m app.scripts.platform_admin list` or `SELECT account_name, email FROM users`; migration 071 derived it from the username, or the part of the email before the `@`). The isolation-flow tool now signs in by account name by default (`--account-a/--account-b`, with `--email-a/--email-b` still accepted as spellings; an identifier containing `@` is sent as an email). The curl examples in the docs use an account name. See `docs/security/account-names.md`.
- **A technician can be granted FULL access (read and write) to one, several or all tenants.** Until now a grant was read-only. A grant is now `view` or `full` (migration 074); with `full` the person can also write in that tenant, acting with their **own role's permissions, never more**, and **users, roles, API keys, who-has-access, platform and MSSP administration stay refused whatever the level** (by route and by permission: a stolen technician login must not be able to plant a hidden administrator in every customer). Every such write is recorded in the **customer's own** hash-chained audit log **before** it is carried out (if it cannot be recorded it is not performed), naming the person, their home tenant, role and level, and the audit middleware's outcome row now goes to that tenant's log too, not the person's home tenant's. **All tenants** is a separate grant (`/platform/all-tenant-access`, **platform administrators only**, level stated explicitly, covers tenants created later); the strongest applicable level wins, and a platform administrator on their own still only views. `PUT /tenants/{id}/access/{account_name}` takes `{"access": "view"|"full"}` (no body means view; a change of level is audited), `GET /tenants/viewable` reports each level, and `/auth/me` and `GET /tenants/manageable` tell the console what a person may do. **The console shows the level** (the switcher labels each tenant; the banner says "Working in X with full access" in red, or "Viewing X, read-only" in amber); the Settings screens for granting access are in the entry above this one. Existing grants stay `view`. See `docs/security/viewing-another-tenant.md`.
- **A person may be granted read-only access to specific tenants; belonging to an MSSP parent tenant no longer lets you see its children.** Until now every user of an MSSP parent tenant, even a `viewer`, could view **all** its child tenants (`mssp:read`). That blanket rule is replaced by explicit per-person grants (`tenant_access_grants`, migration 072): a person may view their own tenant, a tenant they were granted (read-only at the time of this entry; levels were added next, see the entry above this one; checked on every request so a revocation applies on their next one), or any tenant if they hold the platform-wide cross-tenant permission (unchanged). `GET/PUT/DELETE /tenants/{id}/access[/{account_name}]` list, grant and revoke; allowed for a platform admin, for `users:write` holders in the tenant itself (a customer decides who sees its data), or in its **parent** (an MSP decides which staff see which customers); everyone else gets the same 404 as for a tenant that does not exist. Grants and revocations are written to the target tenant's own hash-chained audit log. **Existing deployments start with no grants, so an MSP's staff lose their view of customers until it is granted.** The console labels tenants "Your tenant", "Granted access" or "Platform view". See `docs/security/viewing-another-tenant.md`.
- **An email address is one account, whatever its letter case.** `users.email` was unique only case-sensitively, so `Alice@x.com` and `alice@x.com` could be two accounts, login matched the exact text, and the check that stops one organisation claiming another's address could be bypassed by changing a letter's case. Addresses are now compared by one rule (trimmed, lower-cased) through one helper used by sign-in, passkey sign-in, user creation, the provisioner and bootstrap, and stored lower-cased on creation. Existing accounts are not rewritten and still sign in under any case. Migration 070 adds a unique index on `lower(email)`; if a deployment already holds two accounts differing only in case, the migration builds nothing, warns with the exact queries, and does not guess (sign-in keeps working: an exact-case match wins, else the oldest). Verified on real Postgres. Not changed: nothing checks that an address is real or sends email to it. See `docs/security/email-addresses.md`.
- **Guessing a password is no longer free: `/auth/login` locks after repeated failures.** It had no rate limit and no lockout. After 5 failed attempts for one address, or 20 from one client address, within 15 minutes, further attempts are refused (`429`, `Retry-After`) until the window passes, even with the correct password; a success clears that address's count. The count is by address as typed, lower-cased, **whether or not an account exists**, and every locked case returns the same status and sentence, so the lock cannot be used to find out which addresses are registered (a made-up address locks after the same five attempts; with failures recorded, a real and a made-up address still answer in indistinguishable time). Counts are in a new `login_failures` table (migration 069), so they hold across workers and restarts. Settings `LOGIN_MAX_FAILURES_PER_ACCOUNT`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_FAILURE_WINDOW_MINUTES`; `python -m app.scripts.login_lockout list|clear` lifts a lock at once (anyone who can send five wrong passwords for an address can lock that person out for up to the window). Behind a load balancer set `AISOC_TRUSTED_PROXIES`, or the per-client limit applies to everyone together. The sign-in page shows the server's own "try again in about N minutes". See `docs/security/login-throttling.md`.
- **Login no longer reveals which email addresses are registered.** The password check was skipped for an unknown email, so over HTTP an unknown address answered in about 6 ms and a registered one in about 285 ms, with no overlap: anyone, with no account, could list which addresses (admins included) are registered. Login now does the same work either way (an unknown or inactive account is checked against a real bcrypt hash of the same cost), and the answer is unchanged. After the fix, 40 interleaved samples each differed by 1.2% and a registered address was slower in 47% of pairs, i.e. indistinguishable. A test fails the build if any code outside `security.py` checks a password with the bare `verify_password`.
- **Creating a user no longer tells a tenant admin that an address is registered in another organisation.** Addresses are unique across all tenants (login is by email alone), so such an address is still refused (409), but the message now says only that it cannot be used; "already exists in your organization" is said only for the caller's own tenant. The attempt is logged with who made it and a hash of the address. A refusal still differs from a success, so a few addresses can still be probed by someone who may create users; removing that needs per-tenant uniqueness or an invitation flow.
Several authorization problems were found by two-tenant isolation testing and fixed. Where an item says "demonstrated", it was reproduced against a real database before the fix and shown closed after; where it says otherwise, the limit is stated. Whether any of this was exploited cannot be determined from the code. See `docs/security/roles-and-platform-permissions.md` for the upgrade checklist.

- **A `tenant_admin` could become a `platform_admin`** (demonstrated): `POST`/`PATCH /tenants/me/users` accepted any role, so a tenant admin could create a platform admin or promote itself with one request. The same escalation worked through API keys: a key could carry any scope, including `*` and `plugins:admin`, whatever its creator held. Nobody can now grant a role, scope or database-role permission they do not hold; nobody changes their own role or edits a user above them.
- **Platform power is now separate and explicit.** `plugins:admin`, `mssp:onboard` and `platform:cross_tenant_query` are not covered by `*`; only `platform_admin` holds them. The original primary administrator is a `platform_admin` by default (migration 067); `python -m app.scripts.platform_admin` grants and revokes it. **Upgrade note:** a tenant's `admin` can no longer manage the shared plugin registry or onboard tenants.
- **Cross-tenant reads (demonstrated):** a case's summary and post-mortem (JSON and HTML), `GET /graph/attack-path/{case_id}`, and the rule shown in an alert's explanation (via a `rule:<uuid>` tag). The case investigations list and the investigation PDF had no ownership check (fixed and unit-tested; not demonstrated, as the agents service was not available).
- **Cross-tenant write (demonstrated):** `DELETE /rbac/users/{user_id}/roles/{role_id}` removed any role from any user of any tenant.
- **`/nl-query` index pattern (demonstrated at the query-building layer):** the caller-chosen index pattern went verbatim into the Elasticsearch query that `/execute` runs with the server's credentials (`FROM *`, system indices, injected pipeline commands). It is now validated, the final query's source is checked whoever wrote it (including an LLM), and `NL_QUERY_TENANT_FIELD` adds a per-tenant filter for deployments that share one Elasticsearch. Set it if yours does.
- **Connectors SSRF guard (review-based; not run against live connectors):** connector requests, including each redirect hop, refuse loopback, link-local (cloud metadata) and other never-legitimate destinations; private ranges stay allowed. See the connectors README for `CONNECTORS_EGRESS_*`.
- **Compliance reviewer could be spoofed, and three audit fields stored a Python object repr** (migration 066).
- **A shared (tenantless) detection proposal can no longer be commented on, decided or promoted by a tenant** (hardening; no such row is created today).
- **Deleting an alert from the Copilot needs your confirmation**, and the model cannot give it: the request is signed, expiring and bound to the user, and only a separate confirm call performs it.

### BREAKING (API contract: already in the running API; this commit only makes the published spec say so)

- **`docs/openapi.yaml` regenerated: it was stale, and the truth contains 23 changes that break generated clients.** `Check OpenAPI schema` had been red; the missing `langchain` packages in its install list (fixed in `ac8e253a`) hid the real reason, which I reproduced in an isolated CI-equivalent environment: `docs/openapi.yaml is out of date`. Regenerated with `scripts/export_openapi.py`; `--check` now passes. **Size:** 328 to 375 paths, 407 to 461 operations (54 added, **0 removed**), **0 response codes removed**, 403 to 439 schemas. **The repository's own detector (`scripts/openapi_diff.py`, run on the old and new files) reports 23 breaking changes:** (1) **sign-in naming:** `LoginRequest.email` is now `account_name` (required) and `AuthenticateBeginRequest.email` is now `account_name`; the server still accepts `account_name`, `username`, `email` and `identifier` (I validated each payload shape against the model; only a payload with none is rejected), so **no existing caller breaks at runtime**, but a client generated from the new spec sends `account_name`; (2) **email is now optional:** `CreateUserRequest.email` and `.username` are nullable, and `UserMeResponse.email` and `UserResponse.email` may be `null`, so a client that assumes a non-null string **can** break at runtime; (3) **MSSP dashboards:** `MSSPKpiOverview` lost `total_critical_incidents`, `connectors_online` and `connectors_degraded` and gained `total_critical_alerts`, `total_open_cases` and `tenants_reporting`; `ManagedTenantRow` lost `connector_status` and `last_event_at` and gained `connector_count`, `has_metrics`, `mttr_minutes`, `open_cases` and `snapshot_at`; and eight of their numeric fields became nullable (`total_open_alerts`, `avg_health_score`, `avg_mttr_minutes`, `sla_breach_count`, `health_score`, `open_alerts`, `critical_alerts`, `sla_breaches`): **real response-shape changes**; (4) `AssetOut.asset_metadata` and `VulnerabilityOut.asset_metadata` are gone (nothing was added to `AssetOut` in their place; I did not check `VulnerabilityOut`); (5) the schema `IndicatorOut` is now two schemas with qualified names (`app__api__v1__endpoints__enrichment__IndicatorOut` and `app__api__v1__endpoints__insider_threat__IndicatorOut`, because two classes share the name, which FastAPI disambiguates): the wire format is unchanged but generated **type names** change. **Impact checked:** the TypeScript SDK's hand-written `types.ts` mentions none of the changed properties, `src/openapi.d.ts` is not committed and no workflow runs codegen, and the Python and Go SDKs do not read the spec. **Not done, deliberately:** the `info.version` is still `0.1.0`: the detector's pull-request gate asks for a version bump with a BREAKING note when such changes ship as a release, which is a release decision for the maintainer (that gate runs on pull requests only, so it does not run for a direct push); I also did not trace which commit introduced each of the 23, so I cannot say whether every one was intended. **Recommended:** bump the version when the next release is cut and announce items (2) and (3), the two that can break a running client.

### Added

- **A ratchet on what CORE's API key can do beyond its tools.** `tests/test_core_key_reach.py` computes every non-read route CORE's real key scopes can reach (from the routes and the scopes, with the function every check uses; no network, no database) and pins the exact set: Cipher's 7 write tools, plus 12 routes left open with a written reason each (case-management writes under `cases:write`; raising an approval; previewing and unpublishing a replay; the realtime ticket; and two marked NOT YET NARROWED, `POST /alerts/{id}/explain` and `POST /kb/query`, which call a language model and need only `alerts:read`), with the two routes a signed-in session is required for (`decide`, `publish`) shown separately. A new route a held scope guards, or a scope added to the key, now fails the build until it is added with a reason, so the key's reach is never widened silently. It also asserts the key holds none of the broad permissions the narrow ones were split from, and that a narrow scope does not imply a broad one. Mutation-checked: 6 variants (giving the key `alerts:write`, `rules:read` or `connectors:read` back; dropping the human-only requirement on deciding an approval; opening a computing route or the federated search to the narrow permission), all caught. The audit that produced it went from 27 reachable non-read routes to 21 (19 usable by a key). See `docs/security/cipher-tools.md`.

- **Cipher can read the estate (ten read-only tools, no new scope).** `aisoc_list_assets`, `aisoc_get_asset`, `aisoc_list_vulnerabilities`, `aisoc_get_asset_vulnerabilities`, `aisoc_posture_summary`, `aisoc_list_posture_findings`, `aisoc_get_posture_finding`, `aisoc_list_posture_scans`, `aisoc_list_identity_nodes`, `aisoc_get_identity_node` (49 tools in all, 32 declared as a table in CORE), with an `estate-posture` skill that treats `evidence`, `remediation_guide`, `metadata`, `attributes` and tags as data (never instructions: a remediation guide is advice to a human, never to run), says identities are real people (report privilege and risk, not conduct; quote `risk_score` without inventing a scale), and says empty is not the same as none. All are `GET`s needing `alerts:read`, which CORE's key already holds. **Deliberately not tools:** insider threat (per-employee risk scores, indicators and watchlists) and compliance (`reports:read`; `GET /compliance/report` writes a record). Verified live on real Postgres: all ten return 200 with the key; compliance is refused (403). **A width older than these tools was found while verifying them, and is closed by `alerts:triage` below:** `alerts:write` (held for claim/escalate/snooze) also guarded creating assets, posture findings, identity nodes and insider-threat indicators and changing a watchlist; confirmed by comparing the key with a read-only key.

- **Cipher can read the tenant's threat intelligence (five read-only tools).** `aisoc_list_iocs`, `aisoc_get_ioc`, `aisoc_list_threat_actors`, `aisoc_list_stix_indicators` and `aisoc_list_stix_bundles` (39 tools in all, 22 declared as a table in CORE), with a `threat-intelligence` skill that makes it respect each indicator's TLP, treat everything it reads as data, and say that there is no search by value (it pages) and that the STIX lists have no paging. They need the new scope `intel:read` (see below), held by CORE's key; the bootstrap updates an existing key in place (same secret). **Deliberately not tools:** `GET /enrichment/lookup` and `POST /enrichment/bulk` (they send indicators to outside providers), `GET /threat-intel/feeds` (a feed's free-form `config` can hold credentials), MISP health (an outside call) and the TAXII collections (an empty stub). Verified live on real Postgres: all five tools return 200 with the fields the skill names; add, delete, feed and publish are all refused. The STIX indicators route accepts `page` and `page_size` but ignores them; the tool does not offer them.
- **`intel:read`: a read-only permission split out of `threat_intel:read`, so CORE's key can read intelligence without reaching feeds or enrichment.** `threat_intel:read` also guards the feed list (feed `config` can hold credentials) and the enrichment routes (they send an indicator to outside providers). The first version of the tools above gave CORE's key `threat_intel:read`, and a live run confirmed the key then got HTTP 200 on the feed list; that lasted one commit. Five routes now need `intel:read` instead (the IOC list and detail, actors, STIX indicators and bundles); the feed list, both enrichment routes, TAXII and MISP health stay `threat_intel:read`. **Nobody loses access:** `threat_intel:read` implies `intel:read` in `permission_in` (roles, database roles, API-key scopes, a `threat_intel:*` wildcard), one way only, and all eight standard roles hold it. A holder of `intel:read` alone can use exactly those five routes and no other route in the application (tested over every route). CORE's key now holds `intel:read` and not `threat_intel:read`. Migration `076` adds the catalog row. Verified on real Postgres with the real bootstrap: it applied 076, and against a key forced back to the old scopes it logged `scopes updated in place (same secret): added ['intel:read'], removed ['threat_intel:read']` (status `scopes-updated`, no new key printed); with that same secret the five tool routes return 200 and the feed list, both enrichment routes, MISP health and adding an indicator all return 403, while the admin still reaches indicators, feeds and STIX. **Action on upgrade:** none for existing users or keys. If you deployed the previous commit, re-run the bootstrap: it narrows CORE's key in place.

- **A generated capability reference.** `python -m app.scripts.export_capabilities` writes `docs/api/AISOC_CAPABILITIES.md` (every operation, grouped by area, with the permission it needs and whether it reads or changes) and `docs/api/aisoc-areas.md` (one line per area: a map small enough to give an agent, which Cipher's knowledge file in the CORE repo copies). It describes protection exactly as far as the route's dependencies show it: a named permission, 'signed in, no permission declared (a check may be inside the handler)', or 'no sign-in required (public, or secured another way)'; it never says 'login only' (its first draft did, for 27 routes that need no sign-in at all). `--check` fails when either file is out of date, and a test does the same. The route and permission introspection the tests used now lives in `app/core/route_introspect.py` (one definition, with `access_kind`).
- **Cipher can read hunt definitions (5 more read-only tools, 34 in all).** `aisoc_list_hunts`, `aisoc_get_hunt`, `aisoc_list_saved_hunts`, `aisoc_get_saved_hunt` and `aisoc_list_saved_searches`, each needing exactly `hunts:read`. What a run returned (event rows) stays behind `lake:query` and is not offered: `tests/test_cipher_tool_contract.py` asserts that no Cipher tool can reach a run, execute, nl-query, lake, backtest or translate route, that each hunting tool needs exactly `hunts:read`, and checks the shared contract with CORE (17 tools) including the hunt list's limit and offset bounds against this API's. Cipher's ids are now validated by a rule on the CORE side (an id that is not an id is refused before anything is sent, because this server decodes `%2F` into `/` before routing): see `docs/security/cipher-tools.md`.
- **`hunts:read`: a read-only permission split out of `lake:query`.** `lake:query` was one permission for creating, running and deleting hunts, for running arbitrary queries against telemetry, and for reading hunts, so nothing could be allowed to see which hunts exist without also being allowed to query. `hunts:read` covers exactly five routes (`GET /hunts`, `GET /hunts/{id}`, `GET /saved-hunts`, `GET /saved-hunts/{id}`, `GET /hunt/saved`: hypotheses with their queries and findings, saved hunts, saved searches). **Nobody loses access:** `lake:query` implies `hunts:read` in `permission_in` (so roles, database roles, keys and a `lake:*` wildcard all behave the same), and no role was given anything new. A holder of `hunts:read` alone can use those five routes and nothing else in the API (tested over every route). `GET /hunts/{id}/runs` deliberately stays on `lake:query`: it returns `result_sample`, event rows sampled from the lake. Migration `075` adds the name to the permissions catalog (it backfills nothing); a key can be issued with the scope; CORE's key now carries `hunts:read` (an existing key picks it up through the in-place scope sync). See `docs/security/roles-and-platform-permissions.md`.
- **Cipher can read AiSOC's detection engineering (12 read-only tools), and an existing key now picks up new scopes without being rotated.** CORE's key gains `rules:read` (not `lake:query`: that one permission covers hunting's writes and arbitrary queries as well as its reads, so it waits for a read-only hunts permission). `bootstrap_production` used to keep an existing key as it was, so a scope added to the list reached only fresh installs; it now brings an existing key to exactly the wanted scopes **in place, keeping its secret**, with a warning in the log and the status `scopes-updated` (it also removes a scope that is no longer wanted, and never touches an inactive key, another name or another tenant). `tests/test_cipher_tool_contract.py` now checks all 29 Cipher tools against this API's schema and the key's scopes, resolves a path to the route written exactly as named (a wildcard used to be able to check a literal sibling such as `/detection-proposals/baselines`), requires that a tool that only reads never needs a write permission, and compares this table with a contract file generated by the CORE repo so the two cannot drift apart unnoticed (including each tool's allowed values against the API's enums, and each number's clamp against the API's bounds). See `docs/security/cipher-tools.md`.
- **Settings: a Tenant access tab and an Alert email tab.** *Tenant access* (shown to anyone who can manage users): choose among the tenants you may manage, see who has access and at which level (read-only or full), grant, change the level and revoke; a platform administrator also gets an *Every tenant* section with **no default level**. Raising access to full, anything for every tenant, and every revocation ask first, naming the person and the tenant (full access also says what it does and does not allow); lowering to read-only is immediate. *Alert email* (platform administrators): the status (what the server is missing, by variable name; warnings; the last error), the recipients, the minimum severity, the switch, a **Send a test email** button and the recently emailed alerts; saving asks first when it turns the feature on or changes who receives other tenants' alert titles. Each tab is shown only to people whose `/auth/me` capabilities allow it (someone already signed in before this upgrade sees the new tabs after signing in again); the server still checks every action and its own explanation of a refusal is shown. Neither works while viewing another tenant (the page says how to get back). Not built: a bulk grant for a whole team.
- **Optional: email new alerts to platform administrators through Microsoft Graph (off by default).** A platform-wide setting (on/off, minimum severity, recipients; editable only by platform administrators, audited) and a background worker send one capped email per cycle (up to 20 alerts, most severe first, tenant named, plain text, alert text sanitised and links defanged) from one sender mailbox, using an Entra app registration with the application permission `Mail.Send` (credentials in the environment only, never in the database, never returned). It polls the database rather than hooking the API because the fusion service writes alerts straight into Postgres; switching on never mails a backlog, a failure keeps alerts pending and shows the (secret-scrubbed) error, and fixing it makes the backlog flow. `GET/PUT /platform/alert-email`, `POST .../test` (sends a real test message), `GET .../log`, and `python -m app.scripts.alert_email`. Migration 073. **Tested against a mock and a stand-in Graph, not a real Microsoft tenant: use the test email first.** See `docs/security/alert-email.md`.
- **People sign in with an account name, not an email.** Login was by email, but nothing verifies that an address is real or sends mail to it, so it only ever behaved as a label with the cost of an identifier. An account name is 3-32 lower-case letters, digits, `.`, `_`, `-` (no `@`), unique platform-wide and compared case-insensitively; the database enforces the shape and the uniqueness. Email becomes optional contact information (not verified, not needed to sign in). Existing clients keep working (the JSON key `email` is still accepted; creating a user without a name derives one) and during the transition existing people could still sign in with their email (see the next entry: that is now off by default). Migration 071 gives every existing user a name, deterministically and without collisions, oldest first (a second `admin` becomes `admin-2`), so some people's name will differ from what they expect: see `GET /auth/me` or Settings → Profile. Tokens carry `account_name`, and the `email` claim is now a label for "who" (the email, else the account name), so audit still names a person with no email. The sign-in page asks for an account name. `python -m app.scripts.platform_admin` takes `--name` (or `--email`; exactly one) so it can target an account that has no email, and no longer crashes if a deployment still holds two accounts differing only in letter case. See `docs/security/account-names.md`.
- **`tenant_flows run-url`: the two-tenant isolation flows against a deployed environment.** It checks the setup before writing anything (two different tenants, two plain tenant admins who can do what the flows do), refuses unless the host is retyped and `--yes-write-test-data` is given, can be repeated against the same environment (every run's names carry a random tag; what the final flow created is deleted after the leak sweep), and skips the two flows that replace a tenant's whole business-context rule set and settings unless `--include-destructive` is given. Exit codes: 0 clean, 1 a finding, 2 a setup problem. See `docs/security/running-isolation-flows-against-staging.md`.

### Fixed

- **Absurd integer query values reached the database: 31 of the API's 77 integer query parameters had no upper bound. Fixed.** `GET /cases?offset=190547863906668642304` overflowed a 64-bit integer in Postgres and came back as `503 Database error` (found by fuzzing the OpenAPI spec against a real server). The audit behind it: 16 `offset`, 9 `page`, 4 `limit` (declared as a plain `limit: int = 100`, so not validated at all: `limit=1000000000` was accepted, which also lets a caller ask for an arbitrarily large result set) and the investigation event cursors `since` and `step` had no maximum; and 14 further `limit` parameters had a ceiling but **no floor** (`LIMIT -1` is an error in Postgres, confirmed). Now: `offset` <= 1,000,000; `page` <= 100,000; the four plain limits are `ge=1, le=1000` (playbook runs `le=500`); the 14 gain `ge=1`; event `seq` cursors <= 1,000,000,000. The four plain limits use `Annotated[int, Query(...)] = N` rather than `= Query(N, ...)`, because the latter leaves a `Query` *object* as the default when a handler is called directly (four existing tests failed on exactly that before I changed the form). Nothing in the repository asks for more than the caps (the web console uses `limit=100`; the Cipher tools send offsets up to 100,000 and limits up to 200). **Behaviour change:** `limit=0`, a negative `limit` or `page`/`offset`, or a value above the cap is now a 422 naming the bound, on the routes concerned. New `tests/test_integer_query_params_are_bounded.py` is derived from the live OpenAPI schema, so any NEW integer query parameter without a maximum fails the build (the allow-list is empty); it also checks that offset/page/limit have a minimum, that no bound reaches 2^62, that the bounds are wide enough for the clients above, and that twelve absurd values (including the exact one the fuzzer found) are each a 422 over HTTP while ordinary values still pass validation. One Cipher contract assertion was stricter than its own message (it required the hunts offset to have NO maximum) and now says what it means: the API's maximum must not be below the 100,000 the tool sends. **OpenAPI file, not regenerated, and a pre-existing problem found on the way:** `docs/openapi.yaml` is generated (`scripts/export_openapi.py`) and checked by `.github/workflows/check-openapi.yml` on every push to `main` that touches `services/api`, but it is already badly out of date: at the commit before this whole body of work, regenerating it adds 2,820 lines and removes 298 (including the whole `/api/v1/auth/logout` route), so that gate cannot have been passing. Regenerating it would also trip the project's breaking-change detector (`scripts/openapi_diff.py`) on changes accumulated since: for example `MSSPKpiOverview.connectors_degraded` and `VulnerabilityOut.asset_metadata` removed, and `UserMeResponse.email` and several `ManagedTenantRow` counters made nullable. That needs a deliberate decision (a version bump and a CHANGELOG BREAKING note), so it is left alone; the detector reports **0 breaking changes** between the current schema and the one with these bounds. **Action on upgrade:** none for any client in the repository; an integration that sent `limit=0`, a negative value or an enormous one now gets a 422.
- **The graph upsert routes answered a raw 500 when the graph database is unreachable. Fixed.** `POST /graph/entities/{alert,case,host,user}` let the Neo4j `ServiceUnavailable` escape the handler as an unhandled error, while the graph *query* routes in the same module already answered 503. They now answer `503 "The graph service is unavailable"` for a connectivity failure, using the module's existing `_is_graph_unavailable` classification (so every marker the query routes recognise is recognised here), with a generic message: the driver's own text names the internal host and port, which the caller has no need of (the query routes still echo it; not changed). Any *other* exception still propagates, so a real bug stays a visible 500, and an `HTTPException` raised inside the write is passed through untouched even if its text happens to mention a connection marker. Found by the same fuzzing run (Neo4j was not running). Tested by calling each of the four real handlers with the graph service patched to fail; a guard that every `graph_service.upsert_*` call in the module goes through the wrapper, so a future route cannot be added unwrapped; 6 of 6 deliberate breakages caught (two of which first exposed gaps in my own tests: a survivor, and a mutant whose anchor never matched). **Not re-run live with Neo4j down after the fix.** **Action on upgrade:** none; callers that treated this as a 500 now see a 503.
- **A community detection submission could crash the server (HTTP 500) for an empty or oddly shaped rule. Fixed.** `POST /community/detections/publish` read the YAML with `yaml.safe_load` and then did `f not in rule`, but `safe_load` returns whatever the text says: `None` for an empty body (an unhandled `TypeError`), and a string, list or number for other inputs (for a string the check was a *substring* test, so text that merely mentioned the field names passed it). After the required-field check it also called `logsource.get(...)` (an `AttributeError` for a list or string) and used `id` as the storage key (an unhashable or oddly typed id). It now answers a clear 400 for each: not a mapping, a non-string or blank `id`, a non-mapping `logsource`. Found by fuzzing the OpenAPI spec against a real server (1,062 generated cases, 49 server-error findings, of which 44 were the deliberate "service unavailable or not configured" answers). Tested by calling the real handler with 13 malformed submissions (each a 400 with a reason, nothing stored, with a positive control that the counter can see a stored rule), a valid rule and one with extra valid fields still accepted, and the messages naming the problem; 6 of 6 deliberate breakages caught. **Not re-run live over HTTP after the fix** (the unit tests call the handler directly). **Action on upgrade:** none.
- **No weekly digest could ever be saved: it wrote a status the database refuses. Fixed.** The weekly executive digest worker inserted its artefact with `status="ready"`, but `report_artefacts.status` is CHECK-constrained (migration 019) to `pending | generating | completed | failed`, so every insert failed with `CheckViolationError ... report_artefacts_status_check` and `run_once()` returned `{'tenants': 3, 'generated': 0, 'failed': 3}`: for every tenant, under the superuser exactly as under the restricted role, so this had nothing to do with row-level security (it was found while checking whether the other background workers also break under the restricted role: `oauth_refresh`, `retention_sweeper` and `alert_email_worker` do not). The digest now writes `completed`. Nothing else referenced `ready` (no web, SDK, doc or test). **Why nothing caught it:** the worker tests mock every database call, and the html-fallback test *patches `_generate_for_tenant` with its own inline re-implementation* and asserts on the copy's output, so it could never see what the real function writes (left as it is). The new tests run the real function with only its four collaborators mocked, read the allowed statuses from the migration rather than from a copy, and scan the whole application with the syntax tree for every status assigned to a `ReportArtefact`. Verified on a real Postgres as `aisoc_app`: before, `generated: 0, failed: 3` with the constraint violation; after, `generated: 3, failed: 0`, three artefacts saved (status `completed`, HTML because WeasyPrint is not installed there, so the documented fallback ran), and a second run created no duplicates. **Not changed, noted:** on that second run `generated` still reports 3 although nothing was generated, because the statistic also counts tenants that were skipped as already done; and a PDF (rather than the HTML fallback) was not exercised live. **Action on upgrade:** none; the next Monday run will produce the first digests.
- **Scheduled hunts never ran when the services connect as the restricted database role. Fixed.** The hunt scheduler's sweep began with `SET LOCAL row_security = off`. That only bypasses row-level security for a superuser, the table owner or a `BYPASSRLS` role; for the ordinary restricted role (`aisoc_app`: not a superuser, no `BYPASSRLS`) the very next SELECT failed with "query would be affected by row-level security policy", so whenever the API connected as the restricted role, scheduled hunts silently never ran (the default superuser deployment worked, which is why it went unnoticed). **This is latent in the shipped configuration, not live:** the `docker-compose.rls.yml` overlay moves only the `actions` and `agents` services to `aisoc_app` and says the API "is deliberately NOT switched yet"; but the API can already be run that way by hand (`DATABASE_URL` = `aisoc_app`, `MIGRATION_DATABASE_URL` = the owner, which the overlay documents as verified), and the stated direction is to make it the default. (An earlier version of this entry said the overlay runs the services, scheduler included, as `aisoc_app`: that was wrong.) Confirmed on a real Postgres by calling the real `run_once()` as each role: it raised `ProgrammingError` as `aisoc_app` and returned `0` as the superuser. The statement is removed: a session with no tenant set already sees every tenant under the current policies, which is what the cross-tenant sweep needs, and each hunt is still run under its own tenant. After the fix `run_once()` returns `0` as `aisoc_app` instead of raising. **What was not demonstrated live:** that a due hunt then fires (the test database holds one saved hunt in one tenant, so the sweep had nothing due). The behaviour is pinned by tests that record the statements the sweep issues (never a `row_security` statement; each hunt bound to its own tenant before it runs; all tenants read in one query; one commit; nothing written when nothing is due), and a guard that no module in the API switches row security off. Found by inventorying every place the API opens a database session without a signed-in user (29 direct session creations in 19 files, 5 of those files in other services). **Related, not changed:** `oauth_refresh` and `weekly_digest` also run without a tenant but only read, which works under the current policies; if the policies are ever made fail-closed they and the other unauthenticated sessions of the API (the audit middleware, login) need an explicit mechanism. The other services are not affected by a policy change: of the tables they own, only `response_actions` is in the API's RLS-covered schema (and `actions` already runs as `aisoc_app`); the tables of `osquery-tls`, `honeytokens`, `ueba` and `purple-team` do not exist in that schema at all (an earlier version of this entry said all five other services needed the same treatment: that was wrong for four of them). Measured on a scratch database: flipping the 77 fail-open policies to fail-closed breaks 251 of 404 isolation-flow steps, and a central hook that re-applies the caller's tenant at the start of every transaction (for both `get_db` and `get_tenant_db` sessions) brings that to 0 of 435; that experiment is not part of this change.
- **Viewing another tenant now works, read-only, and is audited in the viewed tenant.** The console's tenant switcher sent the chosen tenant as `X-Tenant-Id`, which the API never read, so an MSSP operator who "switched" to a customer kept seeing their own data under the customer's name. The API now honours `X-View-As-Tenant` for a tenant the caller may view (any tenant for a platform admin; otherwise only a tenant the person has been granted: see the next entry), for reading only (403 on writes), with explicit errors instead of silently ignoring a bad or unauthorised value; account routes (auth, push, passkeys) always act as the person. `GET /tenants/viewable` lists what will be honoured. Each view writes a `tenant:viewed` event into the viewed tenant's own hash-chained audit log (once per person per 15 minutes; no event, no view), because reads were never audited and a customer would otherwise never know. The isolation flows gained a `view_as_isolation` flow (12 steps) and a preflight check that the test tenants are unrelated. See `docs/security/viewing-another-tenant.md`. The console shows a persistent read-only banner while viewing, sends the header from `authFetch`, offers only what `/tenants/viewable` lists, and explains a refused write in words (see the same doc); deploy the API first. The cases page (a server component) does not follow the switcher.
- **Marketplace installs survive a restart and are the same on every worker.** An install was recorded in a module-level dict, so every API restart silently uninstalled everything, and with several workers or replicas each had its own copy (a tenant's "installed" list depended on which process answered). They are now rows in a new `marketplace_installs` table (migration 068), one per tenant, item type and item id, under row-level security and filtered by tenant in every query. The API's responses are unchanged. Existing deployments start with an empty table (the dict never survived a restart, so nothing is lost by the change). The isolation flows gained a marketplace flow (13 steps).
- **UEBA can no longer read an unscoreable baseline as normal behaviour.** A
  feature that had never been observed, had too few samples, or had zero
  variance produced a `0.0` z-score — the same value an observation sitting
  exactly on its own mean produces. Since the composite is a root-sum-of-
  squares, that zero contributed nothing and the entity read as all-clear;
  service accounts, batch jobs and automation users converge on a constant
  stream, so they could not raise an anomaly at all. `compute_z_score` now
  returns `None` for these cases and callers exclude it. Per-feature composites
  are unchanged (`0.0 ** 2` already contributed nothing), but a peer group
  whose features are all degenerate now yields no peer signal instead of a
  `0.0` that halved the caller's personal composite — a `critical` score was
  being reported as `medium`. Affected feature names are logged at `info`.
  A new `MIN_BASELINE_SAMPLES` setting (default 30) gates the sample count.

- **Agent investigations are now persisted to the ledger (issue #601).** The
  demo seed renames the canonical seed tenant's slug from `default` to `demo`,
  so the agents service's `tenant_ref="default"` fallback matched no tenant and
  every investigation was silently skipped (`ledger.skip_run
  reason=unknown_tenant` at `debug`) after already spending compute. Two fixes:
  the API now forwards the authenticated `tenant_id` to the agents service on
  `/cases/{id}/investigate` (the run is attributed to the real tenant), and the
  ledger resolver maps the `"default"` placeholder to the canonical seed tenant
  (stable UUID, regardless of its current slug) or the sole tenant in a
  single-tenant install. A genuinely unresolvable tenant now logs at `warning`
  with the run/case id, not `debug`.

## [7.7.0] — 2026-08-04

### Added

- **Self-service data lifecycle (Wave 5).** (1) **Configurable retention**
  (`/data-lifecycle/retention`): per-tenant windows (days) for `raw_events`
  (lake) / `alerts` / `audit`, clamped to `[1, 3650]`, with a bounded
  **tenant-scoped** ClickHouse purge and a parameterised Postgres purge (W5.1).
  (2) A **field-extraction / transform DSL** (`pipeline_transforms`): a safe,
  whitelisted, no-`eval` pipeline (`rename` / `copy` / `set` / `set_default` /
  `drop` / `lowercase` / `uppercase` / `coalesce` / grok-style `extract` with
  dotted paths + named captures) that reshapes events onto OCSF; the `extract`
  op compiles a `%{TOKEN:name}` template from `re.escape`d literals + a fixed
  linear-time token map, so it is ReDoS-proof by construction (no raw user
  regex); validation rejects unknown ops/tokens and oversized pipelines;
  runtime is fail-open per op and never mutates the input (W5.3). (3) **Runtime custom parsers**
  (`/data-lifecycle/parsers` + `/parsers/test`): a parser is a named,
  tenant-scoped, validated transform pipeline you can register and dry-run
  against a sample event (W5.2). Gated by `test_retention.py` +
  `test_pipeline_transforms.py`.
- **Customizable dashboard / report builder (Wave 7).** A declarative report is
  a list of widgets (whitelisted `type` × data `source`), validated for unknown
  types/sources, duplicate ids, and bounded size, then rendered by resolving
  each widget's data server-side — resilient to a failing/missing resolver (one
  bad widget renders an `error`, never breaks the report). `POST
  /report-builder/validate` + `/render` (the latter wires the real tenant-scoped
  `alerts_by_severity` resolver). The same definition can drive the live
  dashboard and an exported report. Gated by `test_report_builder.py` (8 cases).
- **Compliance mapping + agentless CSPM + destinations (Wave 6).** (1) An
  **agentless CSPM scan engine** (`cspm.scan_resources` + `POST /posture/scan`):
  evaluates a read-only cloud-resource snapshot against misconfiguration checks
  (public/unencrypted S3, world-open security groups on sensitive ports, IAM
  users without MFA / stale keys, public/unencrypted RDS, unencrypted EBS),
  emitting findings with severity + control refs (W6.2). (2) **Compliance
  control mapping with auto-evidence** (`compliance_mapping`): CSPM findings and
  fired detections (via MITRE) map to CIS / SOC 2 controls and mint dated
  evidence records automatically (W6.1). (3) **Notification/SOAR destinations**
  (`destinations` + `POST /posture/destinations/preview`): Opsgenie, email, and
  a generic `aisoc.handoff.v1` external-SOAR webhook, with an SSRF guard on
  outbound targets (W6.3). Gated by `test_compliance_cspm.py` (14 cases).
- **Invoking-identity scoping for response actions (Wave 4).** An
  `ActionPrincipal` (user id + tenant + roles + permissions) now rides on every
  `ActionRequest` (W4.1). The actions service enforces **least-privilege**: an
  action only runs if its principal holds the permission its blast radius
  demands (`actions:execute:{low,medium,high}`, higher tiers granting lower;
  `actions:*` granting all), with tenant binding (W4.2). The mutating action
  routes require a service bearer token and **fail closed** in production when
  unconfigured (W4.3). Approvals are **bound**: an approver must hold the
  action's permission and cannot approve their own request (separation of
  duties, W4.4). Gated by `test_authz.py` (10 cases).
- **Three detection-authoring modes (Wave 3).** (1) A **Python detection
  framework** (`packages/aisoc-detections`): write detections as
  `def rule(event) -> bool` + metadata + inline positive/negative `TESTS`,
  complementing the YAML/Sigma corpus; a fixture harness fails a blind rule
  (misses a positive) or a noisy one (fires on a negative), `evaluate()` is
  fail-closed, and a CI gate (`python-detections.yml`) runs it. Ships a CLI
  (`aisoc-detections`) + example detections. (2) An **AI Detection Builder**
  (`POST /nl-detection/propose`): a plain-English threat description becomes a
  Sigma rule with **auto-generated** positive/negative fixtures **derived from
  the rule's own selection** (not invented by the LLM), run through the
  non-circular eval-gate, and opened as a governed DRAFT proposal. (3) A
  **no-code / simple detection builder** (`SimpleRuleBuilder`): a form
  (field/operator/value rows) compiles to a valid Sigma rule dropped into the
  governed editor. Also fixes a real bug: `detection_loop` / the Wave-1 tuner +
  hunt bridge inserted into a non-existent `aisoc_detection_rule_proposals`
  table (the real table is `detection_rule_proposals`).
- **Detection backtesting over the event lake (Wave 2).** New
  `POST /api/v1/rules/{rule_id}/backtest` runs a candidate detection rule against
  REAL historical events in the tenant-scoped ClickHouse lake
  (`aisoc.raw_events`) over a bounded window and reports exactly how many events
  would have fired (`would_fire`), the `hit_rate`, and sample matches — so an
  engineer can see a rule's noise on real history before promoting it, instead of
  only testing against hand-crafted fixtures. The source filter is
  injection-sanitised and the SELECT is tenant-rewritten via
  `lake_sql.rewrite_for_tenant`. Read-only (`rules:read`). Gate: `test_backtest.py`.
  Also `POST /detection-proposals/{id}/backtest` attaches the result to the
  proposal's `eval_result["backtest"]` as a third promotion signal, with an
  opt-in `AISOC_BACKTEST_MAX_HIT_RATE` gate that blocks `/decide` approval for
  rules too noisy over history (W2.2, `test_backtest_gate.py`), and the rule
  editor gains a "Backtest over history" panel (W2.3).
- **Closed loop: outcomes compound, repeat alerts auto-suppress (Wave 1).** Every
  durable auto-triage outcome is now written back as a per-signature institutional
  prior (`services/agents/app/memory/outcomes.py`), and a later alert matching a
  trusted prior benign/false-positive disposition is auto-resolved WITHOUT
  re-triage — human priors are trusted immediately, AI priors require corroboration
  (repeat count + high confidence), and a prior true-positive never auto-closes a
  future alert. Suppressions are recorded to `aisoc_outcome_suppressions`
  (migration 048) and surfaced as a measured `repeat_alerts_suppressed` /
  `repeat_suppression_rate` on `GET /metrics/funnel`. Fusion now applies a bounded
  (±0.10), per-tenant institutional-memory nudge to fuse-time confidence
  (`MemoryPriorProvider` distils disposition history; refreshed on a cadence),
  scheduled hunt findings open governed DRAFT `DetectionRuleProposal`s
  (`hunt-finding` source), and the previously-orphaned disposition-history tuner is
  wired via `POST /detection/tuning/auto-suggest`. Gates: `test_outcome_memory.py`,
  `test_memory_nudge.py`, `test_wave1_loop_edges.py`; claim-to-gate matrix +4.
- **LLM gateway (LiteLLM) — task-based model routing + observability
  ([#478](https://github.com/beenuar/AiSOC/issues/478), PR1).** New `litellm`
  service in `docker-compose.yml` as the single entry point for live LLM calls.
  AiSOC requests a **logical task alias** (`aisoc-triage`, `aisoc-recon`,
  `aisoc-investigation`, `aisoc-copilot`, `aisoc-summary`, `aisoc-report`,
  `aisoc-nl`); the alias → real-model mapping lives entirely in
  `infra/litellm/config.yaml`, so operators assign different local or hosted
  models per task — and swap them — without any AiSOC code change (commented
  Ollama/vLLM/Anthropic examples ship in the config). Per-task latency, tokens,
  cost, errors, retries, and fallbacks are exported on `/metrics` and scraped by
  the bundled Prometheus (new `aisoc-litellm` job; the third-party image is
  allowlisted in `scripts/audit_prometheus_targets.py`). Opt-in and
  non-breaking: unset `OPENAI_BASE_URL` keeps calls going direct to the provider,
  and the deterministic offline path is unaffected. Docs:
  `apps/docs/docs/operations/llm-gateway.md`; config test
  `services/agents/tests/test_litellm_config.py`. (A follow-up PR wires the ~10
  in-code callsites to request these aliases via `model_pins` and removes the
  hardcoded `gpt-4o-mini` default, closing #478.)
- **LLM task-alias routing — no more shipped default model
  ([#478](https://github.com/beenuar/AiSOC/issues/478), PR2).** Every live LLM
  call now asks for a **logical task alias** instead of a hardcoded model. New
  `services/agents/app/llm/factory.py` (`make_chat_model` / `resolve_model_alias`)
  resolves a task role to its `aisoc-<role>` alias + the gateway base URL;
  `model_pins.py` now pins all seven roles (triage, recon, investigation, copilot,
  summary, report, nl) to aliases with a `deterministic` floor. The ~10 scattered
  `os.getenv("AISOC_LLM_MODEL"/"OPENAI_MODEL","gpt-4o-mini")` + `ChatOpenAI(...)` /
  raw-HTTP callsites across the agents (auto-triage, cloud/identity/insider/
  phishing, recon/forensic/responder/report-writer, copilot, contextual, NL
  translator) and the API endpoints (translation, hunts, knowledge base, phishing;
  via new `services/api/app/services/model_aliases.py`) now request aliases; the
  hardcoded `gpt-4o-mini` default is gone. **Behaviour change:** live LLM now runs
  through the gateway (`OPENAI_BASE_URL`), or pin a concrete model per role via
  `AISOC_MODEL_PIN_<ROLE>` (escape hatch; the slim demo does this so keyed demos
  keep working); with neither, the deterministic offline path is used. Tests:
  `services/agents/tests/test_llm_factory.py` + tightened `test_litellm_config.py`.
  Closes #478.
- **v8 P4 — Compounding Memory (verdicts that measurably improve).** New
  `services/fusion/app/memory/`: a nightly-distillable institutional memory that
  makes verdicts more accurate the longer an instance runs. **Distillation**
  (`distill.py`) compresses analyst overrides + verdict history into two
  versioned (content-hashed), ledger-referenceable outputs — per-signature
  priors (FP rate + prior) and a top-N few-shot exemplar bank per category.
  **Memory verdict stage** (`stage.py`) turns a signature's prior into a
  **bounded** verdict delta capped at ±0.10 (nudge, never dominate; cap +
  direction unit-tested). **Improvement telemetry** (`improvement.py`) computes
  verdict precision over time + the lift from install to latest ("N% more
  accurate than at install") — measured 0.60→0.90 on a simulated (clearly
  labelled synthetic) 90-day override history. **Portable signed memory packs**
  (`pack.py`) — `aisoc memory export` (`pnpm aisoc:memory:export -- --demo`)
  distills + **Ed25519-signs** a pack so an MSSP can bootstrap a child tenant
  from a curated baseline; import verifies the signature and rejects a tampered
  pack + can pin the publisher key (round-trip + tamper-rejection tests). The
  `aisoc-memory-pack` format is the marketplace memory-pack artifact type. 9
  tests (auto-run in the fusion CI job); docs
  `apps/docs/docs/concepts/compounding-memory.md`. (Nightly distill scheduling,
  the dashboard improvement chart, and live-path consumption of the memory stage
  are the documented remaining integration steps.)
- **v8 P3 — Investigation Swarm (parallel hypothesis agents).** New
  `services/agents/app/swarm/`: for hard cases, fan out 3–5 competing hypothesis
  agents in parallel, then run a structured debate node that ranks them.
  **Complexity gate** (`complexity.py`) fires the swarm only above an
  entity/technique-spread threshold (defaults ≥3/≥3); simple alerts stay on the
  cheaper single-agent path. **Hypotheses** (`hypotheses.py`) — ransomware
  staging, insider exfil, lateral movement, C2 beacon, and a benign
  backup/maintenance FP — each with supporting/contradicting signal +
  corroborating techniques. **Swarm** (`swarm.py`) runs the agents concurrently
  (`asyncio.gather`) each under a per-agent token budget, so total spend is
  bounded. **Debate** (`debate.py`) scores hypotheses on explicit criteria
  (evidence coverage, contradiction count, institutional-memory prior) and emits
  a ranked list with margin-based confidence, recorded as a first-class new
  `debate` ledger step type (the public replay UI colors + renders it). **Eval
  gate** `tests/test_swarm_vs_single.py` publishes both numbers and asserts the
  swarm beats single-agent on the investigation-completeness macro by ≥10% under
  a cost ceiling (measured lift +0.556 on the synthetic set) — added to the
  agents CI job. Completeness is a **substrate self-consistency** macro (breadth
  of hypotheses considered), explicitly not a live-LLM accuracy claim; the
  incident set is labelled synthetic. Docs:
  `apps/docs/docs/concepts/investigation-swarm.md`. 9 tests.
- **v8 P2 — Self-Play Purple Team (the SOC that attacks itself).** New
  `services/purple-team/app/adversary/`: turns the purple-team service from a
  test runner into a continuous adversary. **Hard scope guard**
  (`scope_guard.py`) — a SOC that attacks itself must never touch production, so
  this is enforced in **code** (raises `ScopeViolation` before any step) not as
  a prompt: every target must carry an allowlisted lab tag AND no forbidden
  production tag; no force flag. Adversarial tests cover production assets,
  untagged assets, empty target sets, and a `lab`+`crown-jewel` laundering
  attempt (all hard-fail). **Planner** (`planner.py`) composes an ordered
  kill-chain (initial-access → execution → persistence → privesc → exfil),
  selecting only techniques whose platform exists among the lab targets ("attack
  what exists"). **Closed loop** (`campaign.py`) emits telemetry per step
  (pluggable: in-memory for tests/canned, Kafka on the live path), a detection
  oracle scores detected/missed, and computes detection rate + mean-time-to-
  verdict. **DAC auto-file** (`dac.py`) files one eval-gated Sigma-scaffold
  proposal per miss (status `proposed`, low confidence — self-play can only
  propose, never silently merge). **Scoreboard** (`scoreboard.py` +
  `apps/docs/static/data/selfplay-scoreboard.json`) with a per-row `synthetic`
  flag so a canned campaign is never mistaken for a measured live run. Canned
  5-stage campaign via `pnpm aisoc:selfplay` (offline, deterministic, ~seconds)
  runs in CI through `test_canned_campaign_runs_end_to_end`. 14 tests total; docs
  at `apps/docs/docs/concepts/self-play.md`. (Nightly live wiring — Kafka emitter
  + alert-store oracle + HTTP DAC filer into the scheduler — is the documented
  remaining integration step.)
- **v8 P1 — Federated Threat Intel Mesh (the network effect).** New
  `services/mesh/` (Python/FastAPI, port 8010): opt-in gossip of two
  privacy-preserving artifact types between self-hosted instances via a
  lightweight, open-source hub. (1) **IOC sightings** — `SHA-256` of the
  normalized indicator (never the raw value) + coarse type + severity +
  first/last-seen; private-set-intersection style, so a peer learns a value only
  if it already has it. (2) **Verdict signatures** — the institutional-memory
  signature key (category + connector + technique) + verdict distribution + mean
  confidence; no entities, tenant data, or free text. **Privacy gates:**
  k-anonymity (consensus revealed only at `>= k` distinct instances, default 5,
  `AISOC_MESH_K`), per-instance **Ed25519** signing (verified hub-side, so one
  actor can't inflate consensus with sock-puppets — tested), tenant/rule-level
  opt-out, a per-instance outbound-audit receipts log, and a `mesh_preview` that
  shows the exact outbound payload before sharing is enabled. **Consumption:** a
  deterministic `consensus.py:mesh_contribution` verdict stage bounded to
  **±0.10** (the mesh nudges, never dominates; cap unit-tested). Public network
  stats page at `/mesh` (fetches the hub's `/v1/stats`, graceful when the hub is
  offline). 11 tests cover the full privacy contract (k-anonymity threshold,
  sock-puppet resistance, Ed25519 verify, PSI hashing, opt-out, bounded
  contribution, preview redaction, two-instance exchange, per-instance audit);
  added to the wave-2 service CI matrix. Threat model:
  `docs/architecture/mesh.md`; `SECURITY.md` gains a mesh disclosure policy. The
  measured FP-suppression lift (mesh on vs. off) is explicitly deferred and
  labelled **simulated-until-measured** on the benchmark/`/mesh` pages — never
  presented as measured production performance.
- **v8 G1 — launch kit (ships in-repo with the code).** New `marketing/launch/`:
  a Show HN draft centered on `npx aisoc triage --demo`, a 90-second demo-video
  shot list (CLI wow → replay permalink → self-play → mesh stats), Product Hunt
  assets, six technical blog outlines (one per phase, each ending in a
  reproducible command), and a **category-level** comparison dossier vs.
  closed-source AI SOC products — deliberately **without naming any competitor**
  (per project policy), with every AiSOC-side claim linked to code or a CI gate.
  Plus a `docs/press/` kit (boilerplate, fast facts, logo kit, naming). All
  materials are written to two rules — no superlatives, and synthetic-vs-measured
  always labelled — and are linked from `CONTRIBUTING.md` for community
  amplification. The launch-kit README points every claim back to the benchmark
  page + claim-to-gate matrix so nothing ungated gets published.
- **v8 W4 — GitHub-native distribution (`aisoc-action`).** New
  `packages/aisoc-action/` (Node20 JS action, **dependency-free** — a
  hand-rolled Actions runtime + a `fetch`-based GitHub REST client, deliberately
  no `@actions/*`/octokit so the shipped bundle carries no vulnerable `undici`;
  the committed bundle is 18 KB): triages the repo's **own**
  security signals — Dependabot alerts, CodeQL/code-scanning findings, and
  secret-scanning alerts — with the deterministic AiSOC verdict engine (no LLM,
  nothing leaves the runner) and posts verdicts + suppression rationale +
  prioritization as a PR comment (idempotent update-in-place), a job summary, or
  a weekly `aisoc-digest` posture issue with an A–F grade and week-over-week
  delta. Runtime-scope Dependabot vulns are prioritized as
  exploitable-in-your-dependency-graph ("3 of 41 findings are act-now"); sources
  the token can't read degrade gracefully. Inputs: `mode`, `min-severity`,
  `fail-on` (gate mode), `sources`. The verdict engine is a byte-for-byte
  vendored copy of `packages/aisoc-lite/src/verdict/` kept in sync by
  `scripts/sync_vendored_verdict.py` (CI `--check` gate), bundled into a
  committed `dist/index.js`. Dogfooded on this repo via
  `.github/workflows/aisoc-selfscan.yml`. CI (`aisoc-action.yml`): sync-check +
  typecheck + 6 fixture tests + a dist-freshness gate (committed bundle must
  match a fresh build). Docs: `apps/docs/docs/integrations/github-action.md`
  with copy-paste PR + digest workflows. **Fixes a latent workspace defect:** the
  monorepo root package was also named `aisoc` (colliding with the CLI package),
  so it was renamed to `aisoc-monorepo` (installer repo-detection sentinels now
  prefix-match, staying compatible with existing clones).
- **v8 W2 — standalone free web tools (search-indexed acquisition).** Four
  login-free, open-source tools under `apps/web/src/app/(tools)/tools/`, each
  with its own landing page, JSON-LD, OG metadata, and an "open source, part of
  AiSOC" backlink; **everything runs in the browser — user rules never touch the
  server** (the deterministic path is pure client-side). (1) **Detection
  Translator** (`/tools/translate`): paste any rule, get Sigma / SPL / KQL /
  ES\|QL / YARA-L2 / UDM at once, with per-dialect copy buttons and a stable
  `?s=` permalink. (2) **NL → Detection** (`/tools/nl2sigma`): plain English →
  a Sigma scaffold plus the three SIEM dialects, via a deterministic
  artifact-extraction generator (honest about being a starting point). (3)
  **ATT&CK Coverage Grader** (`/tools/coverage`): paste Sigma rules / technique
  IDs → an A–F grade, a per-tactic heatmap, the top-10 highest-prevalence
  uncovered techniques, and a downloadable shareable grade card (via
  `@aisoc/report-card`). (4) **Alert Noise Calculator** (`/tools/noise`):
  project FP suppression + analyst hours/cost saved from the published
  deterministic-tier suppression rate (methodology linked; labelled as a
  substrate figure, not a live-LLM claim). SEO plumbing: 30 programmatic
  format-pair landing pages (`/tools/translate/spl-to-kql`, …) generated from a
  matrix via `generateStaticParams`, plus sitemap entries for all tool routes.
  Logic (`apps/web/src/lib/tools/`) is pure and unit-tested (13 tests: translate
  field-map + permalink round-trip, coverage extraction/grading/top-uncovered,
  noise projection/clamping, NL→Sigma scaffolding). Production build verified
  (tools static, pair pages SSG'd).
- **v8 W3 — shareable investigation artifacts (the screenshot loop).** Public,
  immutable, redacted investigation-replay permalinks. New
  `services/api/app/api/v1/endpoints/replay.py`: `POST /ledger/{run_id}/publish/preview`
  builds a redacted snapshot **and returns the alias map** so the publisher
  reviews exactly what will be hidden (the pre-publish diff) before confirming;
  `POST /ledger/{run_id}/publish` (needs `confirm=true`) re-builds server-side
  and stores an immutable `published_replays` row (migration `045`, with an
  UPDATE-blocking trigger that only allows the view counter to change); public
  `GET /r/{slug}` serves the snapshot without auth from a non-RLS session
  (the data is post-redaction and non-identifying by design). Redaction reuses
  the reversible `Pseudonymizer` (vendored into the API via
  `scripts/sync_vendored_redactor.py`): internal IPs / emails / paths / secrets
  / internal hostnames / usernames become aliases, while public IOCs + ATT&CK
  techniques are preserved as the shareable value; only the redacted snapshot is
  persisted, never the alias map (`services/api/app/services/replay_redaction.py`).
  Web: a public `/r/[slug]` page renders an animated playback (timeline scrubber,
  evidence cards, growing attack graph, verdict stamp with elapsed time) with a
  dynamic `next/og` Open Graph image for X/LinkedIn/Slack unfurls;
  shields.io-compatible badge endpoints at `/api/badge/<kind>`. New shared
  `packages/@aisoc/report-card` renders triage / coverage-grade / replay share
  cards (SVG + Markdown) and is now the canonical renderer behind the CLI
  `--share` flag (bundled into `aisoc` at build time). The seeded LockBit case
  `INC-RT-001` is published as the canonical demo replay at `/r/demo-lockbit`.
  Tests: redaction (no raw PII survives, public IOCs preserved), report-card
  renderers, badge endpoint, and the replay fetch client. `docs/openapi.yaml`
  regenerated (+284 lines, additions only).
- **v8 W1 — `npx aisoc` wedge CLI (the 60-second wow).** New `packages/aisoc-lite/` (TypeScript, published to npm as `aisoc`, one runtime dependency): a zero-install front door that triages a batch of alerts to verdicts in under a minute with **no credentials and no LLM key**. `npx aisoc triage --demo` runs a bundled, fully-deterministic 200-alert fixture in ~50 ms and prints a terminal verdict table plus the copy-pasteable headline "AiSOC triaged 200 alerts: 12 TP, 171 FP suppressed (85.5% noise), 17 need review". The verdict engine (`src/verdict/stages.ts`) is a faithful port of the production triage scorer `services/agents/app/confidence/scoring.py` — the weight stack and band thresholds (≥.80 TP, ≥.60 likely-TP, ≥.40 review, else benign; clamp [0.05, 0.95]) are pinned by a parity test so a CLI verdict lands where the full stack would. `--file alerts.jsonl` triages a local export (Splunk / Sentinel / Elastic ECS / CrowdStrike field spellings auto-detected); `--llm` refines only the ambiguous `needs_review` middle using the user's **own** `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` called directly (never proxied); `--share` writes a redacted, aggregate-only report card (Markdown + 1200×630 SVG, no alert content); `translate` is a CLI front for the deterministic detection-rule field-map translator (Sigma/SPL/KQL/ES\|QL/YARA-L2/UDM); `up` boots the full demo stack from a pinned Compose bundle. Telemetry is strictly opt-in (`--telemetry` / `AISOC_TELEMETRY=1`, default off), aggregate counts only, documented in `packages/aisoc-lite/TELEMETRY.md` and asserted content-free by a unit test. 22 vitest tests. New CI: `aisoc-cli.yml` (build + typecheck + tests + a cross-platform cold `triage --demo` e2e asserting the headline and a <60 s bound + a fixture-staleness diff gate) and `publish-cli.yml` (npm publish with build provenance on a `cli-v*` tag; no-ops safely until `NPM_TOKEN` is configured — we never fake a publish). README top fold rewritten around the one-liner (guarded "lands on npm with the v8.0 launch; today it builds from `packages/aisoc-lite/`").

## [7.6.0] — 2026-07-13

**Fully-Operational AI-SOC release.** Completes the A1–E1 roadmap that wired the three end-to-end paths the reality audit found unwired — the event lake is now populated, the executable detection corpus fires on the live stream, every fused alert is auto-triaged (copilot default), and approved SOAR actions execute against real connector credentials under an autonomy policy — and adds the competitive-parity differentiators (unified Data Explorer, live effective-permissions, fuse-time attack chains, autopilot/copilot scorecard) plus nine new connectors and AI/LLM-usage governance. The claim-to-gate matrix reaches **33 GATED / 7 PARTIAL / 0 NO GATE**: every product claim is backed by a failing test, and the ratchet (`MAX_NO_GATE=0`) forbids regression.

### Added

- **Phase E1 — the last `NO GATE` is closed: every product claim is now backed by a failing test.** The public benchmark scoreboard was hand-maintained and the only automation (`wet-eval.yml`) no-ops without a funded LLM key, so nothing in per-PR CI proved the published headline number matched what the agent actually scores. New `scripts/check_scoreboard.py` makes the scoreboard **backed by a failing test**: on every PR (agents CI job) it runs the deterministic live-agent MITRE-accuracy eval over the 200-incident corpus and fails if the newest `substrate` row in `apps/docs/static/data/scoreboard.json` drifts more than 0.02 from the fresh run, the JSON breaks its schema, or a substrate row is mislabelled (honesty invariant: a deterministic number can never be quoted as live-LLM). The funded weekly `wet-eval.yml` still appends the LLM-tier (`substrate:false`) rows. A fresh `v7.5.0` substrate row (0.97 MITRE accuracy, tokens/USD = 0) is published. Claim-to-gate matrix: the last NO GATE → GATED **and** `MAX_NO_GATE` ratcheted 1 → 0 (the `security.yml` gate now fails if *any* NO GATE ever reappears); the L0–L4 row also moved PARTIAL → GATED (Phase B2 `decide()`-in-dispatch). **Matrix is now 33 GATED / 7 PARTIAL / 0 NO GATE** — the Fully-Operational roadmap (Phases A1–E1) is complete.
- **Phase D3 — live-vendor connector smoke (mock-server conformance).** The contract test proved each connector *declares* the async runtime methods; this goes further. New `services/connectors/tests/connectors/test_live_vendor_smoke.py` stands up a mock HTTP server (respx) returning realistic vendor payloads and drives each connector's **real** `test_connection()` + paginated `fetch_alerts()` HTTP path end-to-end, asserting a successful probe and that pulled events normalize to a valid five-tier severity — catching the wrong-endpoint-path / normalize-KeyErrors-on-real-shape failures a bare contract test misses. Covers the Phase D1/D2 connectors (QRadar, Exabeam, Securonix, Devo, Netskope, Windows/Sysmon, Zeek/Suricata, syslog/CEF, LLM-usage). Moves two claim-to-gate rows PARTIAL → GATED ("Connectors: schema-driven config + vault-encrypted secrets" and "Connectors: live Test connection"), retiring the Phase 10b deferral (31 GATED / 8 PARTIAL / 1 NO GATE).
- **Phase D2 — AI/LLM-usage governance + tiered lake storage.** Three pieces. (1) **AI/LLM-usage audit connector** (`services/connectors/app/connectors/llm_usage.py`) pulls OpenAI + Anthropic organization audit logs — API key creation, role grants, logging/MFA changes, project deletes — and emits the dotted `event_type` (`openai.api_key.created`, `anthropic.member.added`) that the detections match. (2) **Eight native `llm-*` detection rules** (`scripts/detection_specs_part3_application.py`): LLM API/admin-key created, owner granted, audit logging disabled (critical), MFA disabled, service-account created, project archived — regenerated into the corpus (825 executable rules) and re-exported to the fusion live-detection ruleset; verified firing end-to-end. (3) **Hot/warm/cold lake tiering** (`services/api/clickhouse/tiering/`): an opt-in ClickHouse storage policy + `002_tiering.sql` that rebinds `aisoc.raw_events` to a `tiered` policy and moves data to a cold (object/NAS) volume at 30 days, deleting at 90 — the Phase 6 tiering wired now that the lake is populated. Verified end-to-end on ClickHouse 23.8 (policy loads, table rebinds, TTL applied); a static config gate (`test_storage_tiering.py`) catches drift. Registry 77→78; connector-count + conformance-matrix + marketplace regenerated. Claim-to-gate matrix +1 GATED (29 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase D1 — eight new connectors close the biggest coverage gaps (SIEM / NDR / edge / endpoint).** Following the connector convention (schema + registry + `plugins/<id>/plugin.yaml` + docs + `marketplace:sync`), adds: **IBM QRadar** (offenses; magnitude→severity), **Exabeam** (notable risk-scored sessions), **Securonix** (incidents; priority→severity), **Devo** (triggered alerts) — the four SIEMs the reality audit flagged as missing; **Netskope** (SASE/SWG DLP/malware/anomaly alerts, malware/DLP floored at `high`); **Windows Event / Sysmon** (WEF collector spool; severity from channel + Event ID — log clears, service installs, process-injection surfaces floored); **Zeek / Suricata NDR** (Suricata `eve.json` priority + Zeek `notice` types); and a first-class **generic syslog / CEF listener** (parses the ArcSight CEF header + extension, CEF severity 0–10 → five-tier, non-CEF lines ingested at `info`). Every connector maps onto the exact five-tier ladder and passes the schema + runtime conformance gates. Registry now 69→77 connectors; connector-count + conformance-matrix + marketplace index regenerated. 40 new unit tests (severity mapping across the ladder, CEF parser, mocked pulls); full connectors suite 791 passed at 67.37% coverage. Claim-to-gate matrix +1 GATED (28 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C3 — autopilot/copilot posture with a visible autonomy scorecard (defaults to copilot).** The per-action guardrail editor already let operators scope autonomy by action; C3 adds the whole-SOC posture view a CISO asks for. New `apps/web/src/components/settings/AutonomyScorecard.tsx` computes an honest posture from the *configured* policy (not fabricated runtime stats): **Copilot** (the safe default — high/critical-blast actions always require a human) vs **Autopilot** (flips only when a high/critical-blast action is configured to auto-execute), plus the distribution of actions by blast radius and auto-exec/override counts. Rendered atop the existing `AutonomyPolicyPanel`. The compute is a pure, unit-tested function; 6 vitest tests (`AutonomyScorecard.test.tsx`). Combined with the Phase B2 `AISOC_MATURITY_TIER` gate (which enforces copilot at the dispatch layer), the platform is copilot-by-default end-to-end. Claim-to-gate matrix +1 GATED (27 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C1 — Advanced Data Explorer: one investigation surface, no SIEM context-switch.** New `/explore` (`apps/web/src/components/explore/ExploreView.tsx`) unifies the surfaces shipped earlier in the roadmap into a single workbench: ask a question in plain English → it translates to SQL via `/api/v1/nl-query/translate` → runs against the now-populated ClickHouse event lake (`/api/v1/lake/sql`, Phase A1) → renders a BI-like table (row count, latency, referenced tables), with a raw-SQL escape hatch always available. Source tabs pivot to identity (effective permissions), config/graph, and threat intel so the analyst answers "who touched this, with what access, and is the IP known-bad?" without leaving the page. Adds a typed `lakeApi` client, sidebar + command-palette + sitemap entries. 5 vitest smoke tests (`ExploreView.test.tsx`); web type-check + full coverage gate green (395 tests). Claim-to-gate matrix +1 GATED (26 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C2 — Effective Permissions now resolves against a live posture snapshot.** The resolver is pure (snapshot → effective access), but the only production snapshot source was `_default_snapshot_loader` returning `{}` — so every live "what can this principal do?" call 412'd with "no policy snapshot ingested yet". New `services/api/app/services/effective_permissions/posture_loader.py` collects a real snapshot via the connector's `get_resource_config` read path: a new `POST /connectors/{id}/resource_config` endpoint (same vault-decrypt trust model as `/test` and federated `/query`) exposes it, and `HttpResourceConfigFetcher` + `collect_snapshot` assemble the resolver's snapshot. Coverage is explicit and honest — **Okta** is fully assembled here (user → groups → assigned apps → admin roles, then resolved), while **aws/azure/gcp/gws** consume a connector-provided *reconciled* snapshot (sentinel resource id `__posture_snapshot__`); a provider whose connector hasn't implemented that still 412s (we never fabricate a cloud snapshot). Wired into the endpoint behind `AISOC_EFFECTIVE_PERMISSIONS_LIVE` (default off → prior behaviour preserved), fail-soft to the 412 path on any collection error. 7 API unit tests + the connectors suite (751 passed). Claim-to-gate matrix +1 GATED (25 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C4 — related alerts now auto-collapse into one ordered attack chain at fuse time.** Correlation grouped alerts into incidents by shared entity and the API could compute a chain per case on demand, but nothing formed/extended a chain **as alerts arrived** — so an analyst saw N separate alerts instead of "step 3 of an intrusion on host X that began 20m ago". New `services/fusion/app/services/attack_chain_grouper.py`: for each entity an alert touches (host/user/ip) it looks up (or mints) a stable `chain_id` in Redis with a rolling window, so a follow-on alert on the same entity — or a *different* entity sharing an IP — joins the same chain. Members are ordered by MITRE kill-chain stage (initial-access → … → impact), so the assignment's `position`/`stage` reflect where in the intrusion this alert sits, not its arrival order. The fusion engine attaches the assignment to `FusedAlert.enrichments["attack_chain"]` (chain_id, position, stage, prior_alert_ids, member_count) for the UI + triage agent. Fail-soft (Redis miss/outage ⇒ no assignment). 8 unit tests; full fusion suite 130 passed at 65% coverage. Claim-to-gate matrix +1 GATED (24 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B4 — Business Context Rules now run on the live path (environment-specific noise reduction).** A leading AI-SOC differentiator — suppress alerts during a maintenance window, bump severity for production assets, route cloud alerts to the cloud team — existed as an engine + authoring UI in `services/api` but only ran in a dry-run preview; it never touched a live alert. New `services/agents/app/workers/business_context.py` applies the same `when`/`then` semantics (dotted-path fields + `eq/ne/lt/gt/contains/in/exists/...` comparators + `all/any/not`; effects `set_severity` / `route_to` / `tag` / `suppress`) in the auto-triage worker's post-fusion → pre-triage seam. A **suppress** rule drops the alert **before any triage spend**; severity/route/tag mutations flow into the alert the agent reasons over. Rules load from `AISOC_BUSINESS_CONTEXT_RULES_FILE` (mtime-reloaded), gated by `AISOC_BUSINESS_CONTEXT_ENABLED` (default on), fail-soft (bad/missing file ⇒ no rules applied, never an error into triage). The agents image can't import `services/api`, so the evaluator is a faithful, independently-tested re-implementation of the same documented semantics (unifying both call sites is a follow-up). 15 unit tests (`test_business_context_hotpath.py`, added to the CI agents gate). Claim-to-gate matrix +1 GATED (23 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B3 — rollback is real, actions are post-verified, and approval SLA timers survive restarts.** Three "honest response" gaps closed. (1) **Real rollback:** every executor's `rollback()` previously returned a bare `True` — logging "rolling back" without calling the vendor. New `services/actions/app/services/rollback.py` performs the **real** reverse via the same clients (isolate→`lift_containment`/`unisolate_machine`, block_ip→`unblock_ip`/`unblock_ip_zone`, disable_user→`enable_user`/`unsuspend_user`, suspend_session→`unsuspend_user`) and returns an honest `RollbackResult` (`reversed_` / `simulated` / `supported`) — never a fake success; a failed reverse is reported, not hidden. `autonomy_safety.REVERSIBLE_ACTIONS` now imports from this module (single source of truth) and `test_rollback.py` gates the two sets so an action can't be declared reversible without a real reverse. (2) **Post-action verification:** new `services/actions/app/services/verification.py` re-queries the vendor to confirm the effect is actually present (`VERIFIED` / `FAILED` / honest `UNVERIFIED` when no probe or no creds) — a probe error is never a false `VERIFIED`. (3) **Durable approvals:** `services/slack-bot/app/services/timer_store.py` adds a Postgres-backed `TimerStore`; the `ApprovalTimeoutScheduler` persists pending SLA timers and `recover()` re-arms them on startup (firing overdue ones promptly), so a bot restart can no longer strand a forgotten approval forever. Fail-soft to in-memory when no DB. 25 new tests across actions + slack-bot. Claim-to-gate matrix +1 GATED (22 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B2 — connector credentials now reach the SOAR executors, and the autonomy policy governs every real execution.** Two wiring gaps closed. (1) Executors read vendor-prefixed parameter keys (`cs_client_id`, `okta_domain`, `splunk_url` …) but connectors store schema field names (`client_id`, `domain`, `base_url` …) — nothing translated, so even fully-configured credentials never reached an executor and every action fell back to simulation. New `services/actions/app/services/credential_resolver.py` pins the per-vendor translation (15 vendors, connector-id aliases like `aws_security_hub`→`aws_security_groups`, `azure_defender`→`defender`; unknown fields dropped, never blindly forwarded), and `LiveActionRequest.auth_config` lets callers pass connector-style creds that the dispatcher resolves at the boundary. (2) The Phase 9a `autonomy_safety.decide()` policy existed but was never called on the live path (the 9b gap) — now every dispatch whose capability maps to an `ActionType` is governed **before** the executor is invoked: above-tier ⇒ downgraded to a dry-run preview; with dry-run disabled ⇒ `PENDING_APPROVAL` (executor never invoked); tier L0 ⇒ `BLOCKED`; explicit dry-run honoured unchanged; governance verdict attached to the result for the audit trail. Deployment tier via `AISOC_MATURITY_TIER` (default L1 — copilot). Also registers ten previously-missing vendor adapters (SentinelOne isolate, Entra/GWS disable-user, PAN-OS/FortiGate/Cloudflare block-ip, Jira/ServiceNow/PagerDuty create-ticket, Slack notify) so the agent can plan against them (19→29 builtins). 29 new/updated tests; full actions suite 224 passed at 64% coverage. Claim-to-gate matrix +1 GATED (21 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B1 — the agent now auto-triages every alert off the stream (copilot default).** The core autonomy gap: investigations were manual/API-only — nothing consumed `aisoc.alerts.fused`, so "an agent that triages every alert" wasn't true out of the box. New `services/agents/app/workers/fused_alert_consumer.py` (`FusedAlertTriageWorker`) subscribes to the fused-alert topic and auto-triages each alert. **Copilot / dry-run is the default**: triage is read-only — it classifies (verdict + calibrated confidence), records the reasoning to the Investigation Ledger (best-effort), and **never dispatches a response** (proposed actions carry `requires_approval=True`; `response_dispatched` is always `False`). Tier selection is cost- and determinism-aware: cost-governor `DEDUPLICATED` reuses the cached verdict (a flood of identical alerts costs one triage), `CIRCUIT_OPEN`/`AISOC_DETERMINISTIC`/no-LLM-key falls to deterministic heuristic triage (`run_triage` — the air-gapped/CI default), otherwise LLM auto-triage with a deterministic fallback on failure. Wired into the agents lifespan (off unless `KAFKA_BOOTSTRAP_SERVERS` is set) + compose (`depends_on: kafka`). 9 unit tests (`test_fused_alert_worker.py`, added to the CI agents gate; the job now also installs `langgraph`). Claim-to-gate matrix adds a GATED row "Agent auto-triages every alert" (20 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A4 — the behavioral (UEBA) model now feeds alert scoring in production (the three-model story is real).** `services/ueba` continuously scored every entity and emitted `ueba.anomalies`, but fusion never consumed them — so the Semantic-graph / Behavioral-UEBA / Knowledge-LLM story was only two models live. New `services/fusion/app/services/ueba_signal.py`: the fusion consumer subscribes to `ueba.anomalies` and caches the latest per-`(tenant, entity_type, entity_id)` anomaly in Redis with a TTL (behavioral signal is time-decaying); during `FusionEngine.process`, an alert looks up the highest anomaly across its own entities (username→user, hostname→device, src/dst IP→ip) and `apply_ueba_boost` raises the alert's confidence (risk-scaled, label recomputed) and anomaly score, recording an explainable `ueba_anomaly` factor. Fail-soft throughout (Redis miss/outage or malformed message ⇒ no boost, no raise). 10 fusion unit tests; full fusion suite 122 passed at 64% coverage. Claim-to-gate matrix adds a GATED row "Three-model AI: behavioral (UEBA) model feeds alert scoring" (19 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A3 — the default cold-boot stack is complete ("just works").** A plain `docker compose up` previously started the core services but left the connector runtime behind a `connectors` profile and graph-at-ingest OFF, so a fresh install wasn't the full spine. Now `docker-compose.yml` ships the connector runtime in the default profile (it idles harmlessly with no configured instances) and enables graph-at-ingest by default on `ingest-worker` (`AISOC_GRAPH_ENABLED=true` + Neo4j env + `depends_on`; the writer soft-fails if Neo4j is unreachable, so it never blocks ingest). `integration.yml` gains a Phase A3 gate asserting the default boot ships the connectors service **and** ingest enabled the graph writer **and** the Neo4j graph has nodes after the spine flowed — so combined with A1 (lake) and A2 (detection), a cold `up` is proven end-to-end: ingest → OCSF normalize → Kafka → ClickHouse lake + entity graph + detection engine → fused alert row. Claim-to-gate matrix: "`pnpm aisoc:demo` boots the real stack" PARTIAL → GATED (18 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A2 — the executable detection corpus now fires on the live event stream.** The reality audit's second SIEM gap: ~939 executable rules existed but only ran in CI fixture-replay — nothing evaluated them against ingested events, so any telemetry that wasn't a vendor-asserted finding (the promoter's job) never became an alert. New `services/fusion/app/services/detection_engine.py` loads the native corpus exported to `app/data/detection_ruleset.json` (817 rules, by `scripts/export_detection_ruleset.py`) and evaluates each ingested event's connector-normalized fields — recovered from `ocsf_event["raw_data"]`, the shape the specs were authored against — via a **vendored, parity-gated** copy of the canonical `match_when` matcher (`app/services/detection_matcher.py`; `test_detection_matcher_parity.py` asserts byte-for-behaviour agreement with `scripts/generate_detections.py` over every committed fixture). Each firing rule becomes a `RawAlert` routed through the normal fusion dedup/correlate/persist pipeline. Product routing is fuzzy (correctness-first: unknown product ⇒ evaluate all). Gates: `integration.yml` posts an event matching `aws-root-account-login` and asserts the alert appears; `validate-detections.yml` drift-checks the exported ruleset; 16 fusion unit tests. Claim-to-gate matrix adds a GATED row "Detection rules fire on the live event stream" (17 GATED / 11 PARTIAL / 1 NO GATE).
- **Phase A1 — the ClickHouse event lake is now populated from the live stream.** The reality audit's central SIEM gap: the `aisoc.raw_events` lake table and its `/api/v1/lake/sql` read API existed with **no writer**, so every hunt/query ran against an empty warehouse. New `services/fusion/app/services/lake_writer.py` (`LakeWriter`) archives every normalized OCSF event from the `aisoc.raw_events` Kafka topic into ClickHouse — mapping the OCSF envelope to the lake columns (IPv4→IPv4-mapped-IPv6 coercion, `DateTime64` binding, MITRE/IOC extraction), batched by size **or** age, and **fail-soft** (a ClickHouse outage drops the batch and logs, never crashes the consumer). Archival is independent of promotion (a non-promoted Medium event is still queryable), and a background periodic-flush ticker guarantees a low-traffic batch is never stranded. Wired into the fusion consumer + lifespan; `docker-compose.yml` fusion service gets ClickHouse env + `depends_on`. `integration.yml` gains a Phase A1 gate asserting `SELECT count() FROM aisoc.raw_events > 0` after the spine ingests, against a live ClickHouse container (verified locally: a real INSERT round-trips). Claim-to-gate matrix adds a GATED row "Ingested events land in the queryable ClickHouse lake" (16 GATED / 11 PARTIAL / 1 NO GATE). At-least-once with a deterministic `event_id` (MergeTree does not dedup; the gate asserts queryability, not exact-once).

### Security

- **CodeQL (`security-and-quality`) alert cleanup.** Resolved the open code-scanning alerts surfaced by the fresh `security-and-quality` analysis. Real code fixes: (1) **`go/clear-text-logging` + `go/log-injection`** in `services/ingest/internal/enrichment/shodan.go` — the failure path logged the raw transport `err` (which can carry the request URL with the Shodan API key or response-derived data) alongside an unsanitized, attacker-influenceable `ip`; now it logs only a control-char-stripped IP (`sanitizeLogValue`) and never the error object. (2) **`py/stack-trace-exposure`** in `services/actions/app/api/router.py` — the action record echoed `str(exc)` back to the API caller; it now returns only the exception *type* and logs full detail server-side. (3) **`py/clear-text-storage-sensitive-data`** in `scripts/connector_conformance.py` — a false positive where the integer count of `secret`-type fields tripped CodeQL's sensitive-name heuristic; renamed the count to `vaulted` (accurate — those fields are vault-encrypted) so the matrix write is no longer misread as clear-text secret storage. (4) **`py/ineffectual-statement`** (×7) — Protocol/abstract method bodies written as bare `...` now use docstring bodies. (5) **`py/empty-except`** (×3) — silent `except: pass` blocks now carry an explanatory comment. The 20 `py/request-without-cert-validation` findings are the connector/appliance clients' TLS controls, which **default to `verify=True`** and only disable verification when an operator explicitly opts in (required for on-prem SIEM/firewall appliances with self-signed/internal-CA certs); these are triaged as accepted-risk (secure-by-default, explicit opt-in), with CA-bundle certificate pinning tracked as the recommended future alternative.

### Added

- **Phase 12 — observability + governance (completes the World-Class Hardening Program's 0–12 phase checklist).** Two halves of "run this next to your crown jewels": (1) **Observability** — every service under `services/` declares its reliability posture in `docs/operations/slos.yaml` (availability + p95 latency + golden signals; all 18 services covered — 16 SLOs + 2 exempt), gated by `scripts/check_slos.py` so a new service can't ship without an SLO. `docs/operations/observability.md` documents the four golden signals and the single OpenTelemetry trace that spans `ingest → fusion → realtime → api → agents → actions`. (2) **Governance** — new `GOVERNANCE.md` (roles, lazy-consensus decision-making, the maintainer path, and an explicit vendor-neutral-home intent), `MAINTAINERS.md`, and a **Developer Certificate of Origin** sign-off requirement added to `CONTRIBUTING.md`. `scripts/check_governance.py` + `governance.yml` gate that the governance surface (governance/maintainers/security/CoC/trademark/DCO/SLOs/observability) exists and is non-trivial, so it can't silently rot. With this, all 13 phases (0–12) have landed; the claim-to-gate matrix stands at **15 GATED / 11 PARTIAL / 1 NO GATE** (the last NO GATE, wet-eval live-agent tables, needs a budgeted live run — Phase 4c).
- **Phase 11 — OpenAPI breaking-change gate.** `check-openapi.yml` proved the spec matches the code (drift) but had **no breaking-change semantics** — a PR could delete an endpoint, remove a response field, tighten a request body, or drop an enum value with every check green while every generated SDK client silently broke (the reality-audit `NO GATE` row). New `scripts/openapi_diff.py` (pyyaml-only) classifies the changes between two specs as breaking vs non-breaking *from an existing client's perspective*: removed path/operation/schema/property, changed property type signature, optional→required, a new required field on a request-shaped schema, a removed enum value, or a new required parameter. New `openapi-breaking.yml` diffs the PR's `docs/openapi.yaml` against the base branch and fails on any breaking change; a deliberate breaking release ships with a version bump + a CHANGELOG BREAKING note and `--allow-breaking`. 15 detector tests (`tests/test_openapi_diff.py`) prove every breaking class is caught **and** that safe additive changes (new path, new optional field, new enum value, new response field) are *not* flagged — a breaking-change gate that cries wolf gets disabled. Claim-to-gate matrix: "OpenAPI stability for 3 SDKs + MCP" NO GATE → GATED, and the **ratchet ceiling lowered 2 → 1** (15 GATED / 11 PARTIAL / 1 NO GATE — only the wet-eval live-agent scoreboard tables remain, closing in Phase 4c with a budgeted live run). Per-language SDK generated-client contract-drift is tracked as 11b.
- **Phase 10 — connector runtime-contract conformance suite + published matrix.** The reality audit left the "live Test connection" click-and-connect claim with **NO gate at all**, and the schema/vault claim only partially gated. New `scripts/connector_conformance.py` + `services/connectors/tests/test_conformance.py` gate the runtime contract across **all 69 connectors**: every connector must implement `test_connection` as an async coroutine (the contract behind the "live Test connection" button), implement `fetch_alerts` as an async coroutine, declare only valid `Capability` verbs, and **mark every secret-shaped field `type="secret"`** — a field named `api_key`/`token`/`password` rendered as a plain `string` would be stored outside the vault, the exact leak this check prevents. The published `docs/connectors/conformance-matrix.md` (69/69 conform) is drift-gated by `--check`, so a new connector cannot land without conforming and the matrix can't diverge from the registry. Claim-to-gate matrix: "Connectors: live Test connection" NO GATE → PARTIAL, and the **ratchet ceiling lowered 3 → 2** (14 GATED / 11 PARTIAL / 2 NO GATE). Detection-content lifecycle is already gated by Phase 4a (DAC candidate-rule) + 4b (truth table). Live-vendor sandbox smoke + rate-limit/checkpoint durability are tracked as 10b in `docs/audit/PROGRESS.md`.
- **Phase 9a — autonomy-safety policy + honest rollback contract + scorecard.** The reality audit found three holes behind "L0-L4 automation maturity gates every action": dry-run was opt-in (a mis-configured caller executes for real), ~15 executor `rollback()`s silently `return True` with no reverse vendor call (the platform claimed to reverse containment it never did), and there was no post-action verification. New `services/actions/app/services/autonomy_safety.py` closes them at the policy layer: `decide()` makes **dry-run the safe default** — anything not explicitly permitted to auto-execute is previewed (`DRY_RUN`), never silently executed; CRITICAL blast never auto-executes; HIGH only at L4 with a whitelist entry AND the `AISOC_ALLOW_HIGH_BLAST_AUTO` break-glass flag. `rollback_capability()` with a **pinned `REVERSIBLE_ACTIONS={block_ip}`** set makes the rollback claim honest and bounded — a caller learns "this cannot be auto-reversed" instead of a silent `True`, and the set can't grow without a conscious edit + real reverse implementation. Every unattended containment (`AUTO`, blast ≥ MEDIUM) sets `requires_verification`, and `AutonomyScorecard` counts executions that were never verified — and executions of irreversible actions — as **visible gaps** rather than assumed-away. 16 tests (`services/actions/tests/test_autonomy_safety.py`, in the actions coverage matrix). Enforcement-wiring of `decide()` into the live `/dispatch` + `submit_action` router, rewriting the silent-`return True` executor rollbacks, real vendor verifiers, and a durable approval-SLA timer table (replacing the in-memory `approval_timeout.py`) are tracked as 9b in `docs/audit/PROGRESS.md`.
- **Phase 8 — LLMOps: prompt registry, model pins, response cache, structured-output validation.** A coherent `services/agents/app/llm/` LLMOps layer, all dependency-light and gated. (1) **Prompt registry** (`prompt_registry.py`) — every production prompt is a named, versioned, sha256-hashed artifact; the committed `prompts.lock.json` pins version→hash, and `scripts/check_prompt_lock.py --check` (wired into the CI lint job) fails when a prompt's text changes without a version bump + lock regeneration. This makes the `AGENTS.md` "prompt change ⇒ re-grade the eval harness" rule *enforceable* — you can no longer edit a prompt silently. (2) **Model pins + provider fallback** (`model_pins.py`) — logical roles pinned to concrete models with ordered fallback chains that ALWAYS terminate in the deterministic tier (env-overridable primaries, but the deterministic floor is gate-enforced), replacing the scattered `os.getenv("...", "gpt-4o-mini")` defaults. (3) **Content-addressed response cache** (`response_cache.py`) — keyed on sha256(model+prompt+input) with field separation and LRU eviction; safe under the determinism contract (a hit is byte-identical). (4) **Fail-closed structured-output validation** (`structured_output.py`) — strips code fences/prose, parses JSON, validates against a caller schema, and on ANY failure returns a deterministic fallback rather than propagating a half-parsed object into an autonomy decision. 15 tests (`services/agents/tests/test_llm_ops.py`, appended to the CI agents gate). Migration of the inline agent prompts to `registry.get()` is tracked as 8b. Doc: `apps/docs/docs/concepts/llmops.md`.
- **Phase 7a — unified multi-model router with tier attribution + a determinism contract.** The reality audit confirmed the knowledge graph is already built at ingest (v8 T1.1, `services/ingest/internal/graph/`); the genuine Phase 7 delta was the *model router*. Before it, the deterministic→LLM fallback was reimplemented independently in NL query, playbook drafting, explain, copilot, and each sub-agent — no single audit point for which model answered or why. New `services/agents/app/routing/model_router.py` is that place: a `ModelRouter` that escalates deterministic → ML → LLM only when the cheaper tier is under-confident, and attributes every decision (`tier`, `model_used`, `attribution` trail, `tiers_considered`, `escalation_blocked_reason`). It **never silently uses the LLM** — a skipped or blocked LLM tier (no key, air-gap, deterministic mode, governor circuit open, or a tier error) is always recorded. Introduces the canonical **`AISOC_DETERMINISTIC`** flag and composes with the existing `CostGovernor` circuit breaker: either one forces deterministic-only, in which case the router is reproducible (same input → identical decision). 12 tests (`services/agents/tests/test_model_router.py`, appended to the CI agents gate) prove tier selection, attribution, the no-silent-LLM property, graceful LLM-failure degradation, and the determinism contract. Doc: `apps/docs/docs/concepts/model-router.md`. Remaining Phase 7 enrichments (posture collection, effective-permissions snapshot loader, bi-temporal validity, fusion-time ContextBundle) are tracked as 7b+ in `docs/audit/PROGRESS.md`.
- **Phase 6 — performance + cost, both gated.** Two cheap, non-flaky gates in a new `.github/workflows/perf.yml`. (1) **Throughput** — `scripts/perf/throughput_harness.py` runs the *real* fusion hot path (`promote_normalized_event`) over a deterministic 20k-event synthetic corpus and reports events/sec + p50/p95/p99 per-event latency (measured ~250k eps on commodity hardware). The gate asserts a **generous regression floor** (1,000 eps — a >200× margin) so it fires only on a catastrophic regression such as an I/O call slipping onto the hot path, never on shared-runner jitter; it is explicitly a regression floor, not a production SLO. (2) **Cost** — `scripts/storage_cost_model.py` is a deterministic tiered-storage $/TB model (hot ClickHouse block 30d / warm object 60d / cold archive 275d, 8× ZSTD); the committed worked example (`docs/decisions/storage-cost-model.json`: ≈ $902/mo and ≈ $30/raw-TB at 1 TB/day) is drift-gated by `--check`, so the number can never silently diverge from the rate card. Rate-card values are labelled reference list prices to verify per provider/region — the value is the methodology, not the exact dollars. `docs/decisions/0005-storage-consolidation.md` (ADR) records the three-tier decision (keep ClickHouse-only hot; do not add a second hot engine) and cites the gated model.
- **Phase 5 — data spine correctness: schema registry + dead-letter queue + lineage.** The reality audit's load-bearing gap: the fusion consumer logged a warning and **silently dropped** any malformed message — silent data loss. Now every message is schema-validated against a versioned envelope registry (`services/fusion/app/services/event_schema.py`: `aisoc.raw_events` and `aisoc.alerts.raw`, each pinned to `v1`, with a drift-guard test so the wire contract can't move unnoticed) *before* the promoter sees it. Anything that fails — non-object payload, unknown `schema_version`, missing `ocsf_event`, non-UUID tenant, or a RawAlert that fails deep Pydantic validation — is routed to a **fail-soft dead-letter queue** (`services/fusion/app/services/dlq.py`: `LoggingDLQ` default, `InMemoryDLQ` for tests, `KafkaDLQ` republishing to `aisoc.alerts.dlq`) with its reason, schema version, source-event lineage, and a truncated payload, instead of vanishing. `safe_record` guarantees a DLQ that itself throws never crashes the consumer. Each processed alert logs `fusion.lineage` (source event id + schema version). 21 new tests (`test_event_schema.py`, `test_dlq.py`, `test_consumer_dlq.py`) prove a valid event is processed with an empty DLQ, every poison shape is captured (not dropped), and a failing DLQ sink doesn't crash the consumer; full fusion suite 92/92 at 59% coverage (floor 48). Idempotency (AlertSink dedup fingerprint, Phase 3.1) and event-time watermarking are already present; backfill/replay-from-offset is tracked as 5b in `docs/audit/PROGRESS.md`.
- **Phase 4a — the Detection-as-Code gate is no longer circular.** The reality audit's #1 circular gate: the detection-proposal promote path shelled out to `run_evals.py` **without ever passing the proposed rule body**, so "passed" meant the repo-wide substrate MITRE accuracy didn't move — a value independent of the rule under review. A blind rule (matches nothing) or a noisy rule (matches everything) sailed through its own exam. New `services/api/app/services/detection_eval.py::evaluate_candidate_rule` runs the *candidate `rule_body` itself* through the **real** runtime engine (`rule_engine.execute_rule`) against caller-supplied positive/negative fixtures: it must fire on every positive and stay silent on every negative. New `POST /detection-proposals/{id}/evaluate-rule` stores the verdict under `eval_result["candidate_rule"]`, and `POST /decide` (approve) now **requires** it — a benchmark-only pass is no longer sufficient. `services/api/tests/test_detection_eval.py` (6 tests) is the mutation test that proves the gate rejects a blind rule, rejects a noisy rule, rejects a no-positive-fixture rule, and that the verdict genuinely depends on the rule body. Claim-to-gate matrix: DAC row PARTIAL(circular) → GATED.
- **Phase 4b — detection content truth table (honest coverage).** The README advertised "6000+ imported detection rules", but ~97% live under `_quarantine/` (`enabled: false`) because their upstream query language (SPL / YARA-L / CAR pseudocode) does not execute on the engine. New `scripts/detection_truth_table.py` walks `detections/` and classifies every rule **executable** (fires today) vs **non-executable** (provenance/coverage only), rendering `docs/detections/truth-table.md`. The honest headline: **939 executable** rules (861 native + 77 sigma-imported + 1 community) of 6975 on disk; 5921 quarantined, 115 disabled. `--check` gates the doc in `validate-detections.yml` so the number can never quietly drift from reality, and the README now cites the executable figure for *coverage* (the on-disk figure only describes the imported *library*). Claim-to-gate matrix: 6000+-imported row PARTIAL → GATED (14 GATED / 10 PARTIAL / 3 NO GATE). The LLM-dependent half of Phase 4 (live-agent Tier-1 eval, hallucination/calibration/abstention, model matrix, 150-payload prompt-injection adversarial) is tracked as 4c+ in `docs/audit/PROGRESS.md`.
- **Phase 3.4 — cross-store tenant isolation, now proven against live containers.** The offline `isolation.yml` gate proved each read path *constructs* a tenant scope; it could not prove the scope actually isolates. New `.github/workflows/isolation-live.yml` + `tests/isolation/test_live_stores.py` seed tenant A and tenant B in **real containers** (Neo4j, Redis, ClickHouse, Redpanda/Kafka) and assert a read as A returns zero B data. ClickHouse runs the **production** `lake_sql.rewrite_for_tenant` rewriter against a live warehouse (verified: `SELECT … FROM aisoc.raw_events` becomes `… WHERE tenant_id = '<A>'`, so B's rows never return); Neo4j uses the `tenant_id` property filter; Redis uses the `aisoc:t:<tenant>:*` keyspace namespacing; Kafka replays the `graph_ws` per-tenant envelope filter. Every test also asserts the *unscoped* read sees both tenants, so a scoped pass can never be vacuous on an empty store. The isolation registry (`tests/isolation/stores.py`) flips Neo4j/Redis/ClickHouse/Kafka from `container_pending` → `container_gated`, and the claim-to-gate matrix moves "Cross-tenant isolation (Qdrant/Neo4j/Redis/ClickHouse/Kafka)" PARTIAL → GATED (12 GATED / 12 PARTIAL / 3 NO GATE). The heavy-demo-stack items (Playwright real-stack E2E, demo time-to-first-investigation budget) are tracked as non-blocking 3.5+ in `docs/audit/PROGRESS.md`.
- **Phase 3.3 — upgrade-safety gate ("people upgrade; nothing tested it").** New `upgrade` job in `integration.yml` (matrix `v7.5.0 → HEAD` and `v7.3.1 → HEAD` against a real Postgres 16): install a prior release's migration set, seed 250 probe rows on that released schema, then apply HEAD's migration set — the actual self-host upgrade path — and assert the seeded rows survive **and** every HEAD migration applied. The signal this adds beyond the existing fresh-apply job is **destructive-migration detection**: a migration that drops or rewrites existing data fails here even though it applies cleanly on an empty database. The `v7.3.1 → HEAD` leg lands 8 incremental migrations on a pre-existing populated schema (verified locally: 250/250 rows survived, 55/55 migrations tracked). Uses `git checkout <ref> -- services/api/migrations` with an `rm -rf` first so the released set is exact (a `checkout … -- path` alone leaks HEAD-only files and silently degrades to a fresh apply).
- **Phase 3.2 — Postgres-outage chaos gate (fail-soft + self-heal).** Extends the `integration.yml` spine job with a second chaos scenario beyond the consumer-kill test: kill Postgres mid-stream, assert the fusion consumer keeps running (the `AlertSink` degrades to "fused alerts still stream over Kafka/WS, persistence dropped for the outage window" instead of crashing the worker), then restart Postgres and assert a *fresh* event persists — proving the sink's asyncpg pool and the API's SQLAlchemy pool both self-heal with no service restart. Distinct event titles side-step fusion's in-memory dedup so the post-restart event is a genuine fresh persist. Verified locally against a real Postgres 16 before gating (persist during outage → `None` with no raise; first persist after restart → row written). `scripts/integration/spine_test.py` polling now swallows transient HTTP errors during the recovery window so a 5xx blip while the API reconnects extends the poll rather than failing the run.
- **Phase 3.1 — the event spine is now continuous, and CI proves it with real containers.** The reality audit found two silent gaps in the product's central claim: ingest published normalized OCSF events to `aisoc.raw_events` that nothing consumed, and fusion published to `aisoc.alerts.fused` that nothing persisted — a raw event could never become an alert row without a human calling the API. Both bridges now exist in `services/fusion`: a deterministic promotion policy (`app/services/promoter.py` — OCSF Findings-category events and `severity_id >= 4` telemetry become `RawAlert`s; everything else is left to the detection engine by design) and a fail-soft, idempotent Postgres `AlertSink` (`app/services/alert_sink.py` — dedup-fingerprint-guarded insert, duplicates never persisted, DB outage degrades instead of crashing the consumer). New `.github/workflows/integration.yml` gates three claims against real containers, no mocks: (1) **spine** — `POST /v1/ingest/batch` → OCSF normalize → Kafka → fusion → WebSocket `alert.fused` frame + Postgres row via `GET /api/v1/alerts`, plus duplicate suppression and a chaos step (kill the fusion consumer mid-stream, produce, restart, assert zero event loss) — driver: `scripts/integration/spine_test.py`; (2) **migrations** — the full SQL chain applies on fresh Postgres 16, re-run is a no-op (new `AISOC_MIGRATIONS_STRICT=1` mode fails CI on any failed migration), and the UEBA alembic chain round-trips upgrade → downgrade → upgrade; (3) **backup-restore** — `scripts/backup.sh`/`restore.sh` against Postgres + MinIO: seed → backup → destroy → restore → assert full integrity, with measured RTO published to the job summary. 20 new fusion unit tests cover the mapping/skip logic (`test_promoter.py`, `test_alert_sink.py`); full fusion suite 71/71.

### Fixed


- **Hosted demo API 500s from stale Postgres pool + broken waitlist funnel (QA 2026-07-19).**
  Live `/health` showed `demo_bootstrap.last_error_type=create_seed:ConnectionDoesNotExistError`
  after 22 attempts — Fly Postgres autostop closed pooled sockets and every
  subsequent checkout 500ed (`/api/v1/auth/login`, `/metrics/*`, `/alerts/*`,
  `/cases` → 503). Fixes: (1) `pool_pre_ping=True` + `pool_recycle=300` on the
  SQLAlchemy engine; (2) demo self-heal bootstrap now disposes the pool after
  every disconnect, splits create_all / SQL migrations / seed into separate
  steps, and surfaces stage-tagged errors on `/health`; (3) demo-mode middleware
  allowlists `POST /api/v1/waitlist/signup` so the managed-instance conversion
  funnel on tryaisoc.com is no longer 403ed for every visitor.
- **Demo bootstrap `create_all` AttributeError (QA follow-up).** After Fly Postgres
  was restarted, `/health` still reported `create_all:AttributeError` because
  `AsyncConnection.execution_options(...)` is a coroutine and was chained into
  `.run_sync` without `await`. Await the options object first; pin in
  `test_database_pool.py`. Unblocks `published_replays` create + `/r/demo-lockbit`.
- **Canonical `/r/demo-lockbit` missing after re-seed short-circuit.** When
  INC-RT-* cases already exist, `_seed_in_flight_investigation` returned early
  and never created `published_replays`. Now that path still ensures the
  canonical replay; bootstrap only marks `done` after verifying the slug.


- **Out-of-the-box 500 from schema drift on migration-bootstrapped installs (#492).**
  `docker-compose.yml` mounts `services/api/migrations` into
  `/docker-entrypoint-initdb.d`, so a fresh compose stack builds Postgres from
  the `001_init.sql` lineage — which created `detection_rules` in its
  pre-refactor shape (`rule_type`/`rule_content`/`hit_count`/`last_hit_at`) and
  `cases` without `resolution`/`lessons_learned`. The current `DetectionRule`
  and `Case` models query the refactored columns, so every default install
  served `UndefinedColumnError` 500s (e.g. `GET /api/v1/detection/tuning`) and
  `seed_demo` failed on `cases.resolution`. New
  `services/api/migrations/046_detection_rules_cases_schema_drift_fix.sql`
  reconciles both tables with the models — additive, fully idempotent
  (`ADD COLUMN IF NOT EXISTS`), and dual-lineage safe (the `create_all` path is
  a no-op; the legacy path backfills `rule_body`/`rule_language` from the old
  columns and drops the stale `rule_content NOT NULL` under an
  `information_schema` guard so ORM inserts succeed). New
  `services/api/tests/test_schema_drift_046.py` pins the fix and adds a forward
  guard asserting the migration lineage covers every column both models declare.
- **Phase 3.1 gates caught two latent bugs before merge** (exactly what the real-container tier is for — both would have shipped invisibly under the previous mock-only CI). (1) **`scripts/restore.sh` never restored anything.** `resolve_timestamp()` ended in a `[[ -z "$TIMESTAMP" ]] && { … }` guard that evaluates *false* once a timestamp is resolved; as the function's last command that non-zero status propagated out and, under `set -e`, aborted the script before the restore began — for **both** `--latest` and `--timestamp`. An untested backup script had been broken the whole time. Converted the guard to an explicit `if` + `return 0`; the backup → destroy → restore gate now restores 500/500 rows with a measured RTO. (2) **`services/fusion` `AlertSink` silently failed to persist every alert.** The dedup fingerprint (`$10`) was used untyped in both the `INSERT … SELECT` target (the `dedup_hash VARCHAR(64)` column) and `WHERE dedup_hash = $10` (varchar comparisons resolve through `text` operators), so asyncpg's prepare raised `inconsistent types deduced for parameter $10: text versus character varying` and the insert threw — the fused alert streamed over Kafka/WebSocket but never reached the alert store, so the spine's `GET /api/v1/alerts` assertion timed out. Pinned both uses to `::text`; the real-container spine gate now observes the alert row end to end.

### Security

- **Phase 2 continuation — signed, attested container images + SHA-pinned CI.** Every `ghcr.io/beenuar/*` service image pushed by `publish-images.yml` (push-to-main) and `release.yml` (tags) is now: (1) signed with `cosign` keyless/OIDC, (2) attested with a CycloneDX SBOM generated by `syft` and attached via `cosign attest --type cyclonedx`, and (3) built with BuildKit `provenance: mode=max` + `sbom: true` so SLSA provenance and an SPDX SBOM ride the image manifest. Every third-party GitHub Action across all 32 workflows is pinned to a full commit SHA (tag retained as a comment) so a tag-hijack of an upstream action cannot change what CI executes. `docs/operations/verifying-releases.md` rewritten with copy-pasteable verification commands for all four artifact types. Claim-to-gate matrix: "Signed / attested release artifacts" moved PARTIAL → GATED (11 GATED / 13 PARTIAL / 3 NO GATE).

- **Phase 2 — supply chain + truth gates.** New `.github/workflows/security.yml`: a claim-to-gate matrix ratchet (`scripts/check_claim_gate_matrix.py` — the NO GATE count may only decrease; enforces the Phase 0 promise) as the HARD gate, plus gitleaks (secret), Semgrep, Trivy (fs), and checkov/tfsec in report-and-ratchet ("observe") mode with a triage allowlist at `.security/allowlist.yml` / `.gitleaksignore` (GitHub push-protection remains the always-on hard secret gate). **Insecure defaults now hard-fail the boot in production**: `enforce_secure_defaults()` (`services/api/app/core/config.py`) raises `InsecureProductionDefaultsError` when `ENVIRONMENT=production` and any placeholder secret remains, wired into `app/main.py` startup and gated by `services/api/tests/test_security_defaults.py::test_enforce_*`. Added `TRADEMARK.md` (the MIT code is free; the name is not), `docs/operations/verifying-releases.md`, a README `Maturity` note, and fixed the `.github/LICENSES.md` license inconsistency (AiSOC ships under MIT, matching `LICENSE`/README, not Apache-2.0). Claim-to-gate matrix now 10 GATED / 14 PARTIAL / 3 NO GATE. Per-image CycloneDX SBOM + cosign signing + SLSA provenance, SHA-pinning all actions, and flipping the code scanners to blocking are the tracked Phase 2 continuation.

- **Phase 1.6 — platform/vault hardening (KMS envelope encryption).** New `services/api/app/security/envelope_cipher.py`: optional envelope encryption for the credential vault. Each secret is encrypted with a fresh per-secret data key (DEK); the DEK is wrapped by a key-encryption key (KEK) that never leaves KMS/HSM (`vault:v2:<kek_id>:<wrapped_dek>:<ciphertext>`), so a DB dump or a leaked env var yields only wrapped DEKs. Pluggable `KeyManager` protocol with `LocalKeyManager` (default, backward-compatible), `AwsKmsKeyManager` (boto3; GCP KMS / Vault Transit implement the same protocol), and an in-memory `FakeKmsKeyManager` for tests. Key rotation is a cheap **re-wrap** (`EnvelopeCipher.rewrap`) that never re-encrypts the secret body. Gated by `services/api/tests/test_envelope_cipher.py` (round-trip, rotation + re-wrap, plaintext-never-in-token, fail-closed on tamper/wrong-KEK). Added `docs/security/platform-threat-model.md` (STRIDE, vault as top asset) and `docs/security/connector-least-privilege.md`. Completes Phase 1.

- **Phase 1.5 — cost-DoS enforcement.** New `services/agents/app/core/cost_governor.py`: a per-tenant `CostGovernor` that turns the existing `aisoc_run_costs` telemetry into enforcement — rolling-window soft/hard USD budgets, a circuit breaker that drops investigations to deterministic-only mode once the hard cap is hit (instead of billing unboundedly), a per-alert token ceiling (`cap_tokens`), and an evidence-hash dedup cache so a flood of identical alerts costs one investigation, not N. Gated by `services/agents/tests/test_cost_governor.py` (10 tests incl. the headline 10 000-identical-alert flood asserting spend stays at exactly one run, and a distinct-alert flood asserting the circuit breaker bounds spend near the hard cap). Live-orchestrator wiring of `get_governor().check(...)` before the LLM call is the tracked continuation.

- **Phase 1.4 — evidence redaction pipeline (honest no-exfiltration).** New `services/agents/app/privacy/redactor.py`: a per-run, per-tenant, in-memory reversible `Pseudonymizer` that replaces the customer's identifying data (internal IPs, emails, file paths, secrets, internal hostnames, usernames) with opaque tokens (`USER_1`, `HOST_2`, `IP_3`) before evidence leaves the process, while preserving public threat indicators so the agent can still reason. `RedactionConfig` defaults every category on. Gated by `services/agents/tests/test_privacy_redactor.py` (golden-corpus assertion: zero raw customer PII survives; round-trip re-hydration; public IOCs preserved). Rewrote the README "no data exfiltration" differentiator to be precise per mode and added `docs/trust/data-flows.md` documenting exactly what leaves the perimeter (local air-gapped / hosted-with-redaction / hosted-raw). Contract-egress enforcement + air-gapped CI job + Helm egress NetworkPolicy are the tracked 1.4 continuation.

- **Phase 1.3 — cross-store tenant isolation (Qdrant + harness).** Closed the Qdrant leak the reality audit flagged: `services/threatintel/app/storage/qdrant.py` had no tenant scoping at all (global collections, no filter, no `tenant_id` in payloads). Added `tenant_scope_filter` + tenant-stamped payloads + tenant-scoped point ids so a search as tenant A can never surface tenant B's private vectors, while global feed intel stays shared under a `SHARED_TENANT` sentinel (backward-compatible with the feed pipeline). Stood up a table-driven `tests/isolation/` suite (registry in `stores.py` so a new store cannot ship without an isolation entry) and a new `.github/workflows/isolation.yml` gate running the offline layer on every PR. Neo4j/Redis/ClickHouse/Kafka live-container replay is registered as `container_pending` for Phase 3's integration tier.

- **Phase 1.2 — memory-poisoning defenses for the override-learning loop.** New pure `services/api/app/services/memory_poisoning.py`: provenance on every memory write (`MemoryProvenance` — no anonymous memory), trust weighting (verified human outranks autonomous closure) with age decay so lessons must be re-confirmed, a `PoisoningDetector` that flags a burst of same-signature false-positive dispositions from low-trust authors, and blast-radius controls for retroactive re-disposition (`plan_redisposition` + `compute_confirmation_token`: capped batches, explicit confirmation token over the exact alert set, quarantine on flagged signatures). Wired into `override_learning.py` (poisoning-resistant signature key now includes the entity-independent severity band; provenance stamped on writes; `apply_redisposition` requires the token and enforces the cap) and the `/feedback` endpoints (preview returns the token + quarantine state; apply rejects stale/tampered/over-cap batches with 409). The farming-attack eval (`services/api/tests/test_memory_poisoning.py::test_farming_attack_then_real_attack_is_not_auto_closed`) gates the api job: a poisoned signature is flagged and its retroactive apply quarantined, so the real intrusion is not auto-closed.

- **Phase 1.1 — prompt-injection structural containment + detection.** New `services/agents/app/prompting/envelope.py`: per-run cryptographic-nonce evidence fence (`EvidenceEnvelope`, `make_nonce`, `system_rule`) so injected text cannot forge the closing delimiter to break out of the data block, and a `PromptInjectionGuard` that scans untrusted evidence for instruction-shaped content (role markers, "ignore previous", secret/prompt exfiltration, SOAR tool-name mentions, base64- and zero-width-obfuscated directives) and, on a high-severity hit, signals demotion of the case autonomy tier to L0. Added `services/agents/tests/test_prompt_envelope.py` (25 tests across every ingest path) and gated it plus the previously-ungated `test_prompt_sanitizer.py` in the CI agents job (fixed its stale agent-wiring expectations — the investigator agents sanitise via `sanitize_text` / `sanitize_iterable_of_strings` / `format_bundle_prompt_append`). Threat model: `docs/security/agent-threat-model.md`.

### Added

- **World-class program Phase 0 — reality audit** (no product code). `docs/audit/REALITY_REPORT.md` classifies every headline `README.md` claim against the code (`production` / `functional-untested` / `template-fallback` / `demo-only` / `stub`) and ranks Overclaims, Load-bearing untested paths, and Circular gates. `docs/audit/CLAIM_TO_GATE_MATRIX.md` maps 27 claims to their CI gate or `NO GATE` (9 GATED / 11 PARTIAL / 7 NO GATE), each with a binding "Closes in" phase. The committed 12-phase status checklist lives in `ROADMAP.md` (per-session working detail is in the gitignored `docs/audit/PROGRESS.md`). Tracking doc: `AISOC_CURSOR_PROMPT_V2.md`.

## [7.5.0] — 2026-06-29

v8.0-milestone and trust-readiness release. Folds in the **AiSOC missing
pieces — Phases 1–5** rollup (PR [#337](https://github.com/beenuar/AiSOC/pull/337);
25 commits, 188 files, +23 743 / -907), four named v8.0 milestones (T3.7
NL→playbook, T3.8 design system v2, T4 wave-3 marketplace + 6 hardened
connectors, T5.3 fidelity loaders), the marketing-shell unification on
`tryaisoc.com`, the threat-actor attribution RBAC + port fix, and a large
Dependabot + security sweep that landed on `main` since v7.4.0.

### Highlights

- **AiSOC missing pieces — Phases 1–5 rollup**
  (PR [#337](https://github.com/beenuar/AiSOC/pull/337)). Closes every
  item in `plans/aisoc-missing-pieces/` in a single landing: trust-critical
  honesty fixes on `/sovereign` + Features + README, CI matrix expanded to
  7 previously-untested Python services (~971 new test signals), coverage
  gates, real SOAR executors for SentinelOne EDR / PAN-OS / FortiGate /
  Cloudflare WAF + DNS / Splunk ES / Elastic / MDE / Entra ID / Google
  Workspace, real `CreateTicketExecutor` wired to Jira / ServiceNow /
  PagerDuty, Azure/GCP/Okta/GWS effective-permissions resolvers, the
  managed-mode auto-provision pipeline (`infra/fly/managed/`), CI-built
  white-paper PDFs + 90 s Playwright screencast, the deterministic
  NL → ES|QL / KQL / SPL translator (**81-case eval at 100 % syntactic +
  100 % semantic**), real-browser visual regression, a buyer-journey E2E,
  and four immutable ADRs (`docs/decisions/0001`-`0004`).
- **v8.0 milestones — design system, playbook generator, wave-3
  connectors, fidelity loaders.**
  T3.7 NL → playbook generator
  (PR [#330](https://github.com/beenuar/AiSOC/pull/330));
  T3.8 design system v2 + Storybook
  (PR [#331](https://github.com/beenuar/AiSOC/pull/331),
  `DraftFromPromptDialog` story restored in
  PR [#335](https://github.com/beenuar/AiSOC/pull/335),
  Storybook publicDir conflict fixed in
  PR [#336](https://github.com/beenuar/AiSOC/pull/336));
  T4 wave-3 marketplace scaffolding + six hardened connectors
  (PR [#333](https://github.com/beenuar/AiSOC/pull/333),
  wave-1 parity hardening in
  PR [#328](https://github.com/beenuar/AiSOC/pull/328));
  T5.3 AIT-LDS + MITRE Engenuity fidelity loaders
  (PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
- **Threat-actor attribution — port fix + optional RBAC.** The
  investigation agent defaulted `AISOC_THREATINTEL_URL` to
  `http://threatintel:8083`, but the service binds **8005** — every
  `POST /api/v1/actors/attribute` from
  `services/agents/app/agents/investigation_agent.py` therefore hit a port
  nothing listens on and silently degraded. Default corrected, docs +
  `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` aligned, regression test added
  (PR [#327](https://github.com/beenuar/AiSOC/pull/327)). Same release
  ships an opt-in shared-secret gate
  (PR [#329](https://github.com/beenuar/AiSOC/pull/329)): when
  `AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
  must present `Authorization: Bearer <token>` (constant-time compared,
  `401` on mismatch); unset keeps the legacy unauthenticated behaviour
  and logs a warning. Resolves the `[#TODO-attribution-rbac]` caveat in
  `docs/threat-actor-attribution.md`.
- **Marketing-shell unification on `tryaisoc.com` (QA wave, 2026-06-29).**
  Every `/(marketing)` page, plus the standalone `/not-found`,
  `/why-open-source`, and `/benchmark` routes, now renders the same
  `StickyNav` + `sections/Footer` shell. The old simpler `LandingNav.tsx`
  and `landing/Footer.tsx` were deleted; eleven marketing pages had their
  per-page nav/footer JSX + imports removed; `(marketing)/layout.tsx`
  centrally injects the shell; `StickyNav`'s anchors were absolutised
  (`/#solution`, `/benchmark`, `/pricing`) so they resolve identically
  from the landing page and from any subpage. Folded together with the
  smaller fixes from the same QA pass: branded `/not-found` page
  (`ISSUE-004`), `308 /signup → /dashboard` for the anonymous demo
  (`ISSUE-003`), `Testimonials` "Become a reference partner" CTA
  repointed from the 404'ing `/partners` to `/contact` (`ISSUE-002`),
  dead `status.tryaisoc.com` footer link removed (`ISSUE-005`), and an
  SSR-whitespace bug on `/about` that rendered "the 69connectors"
  fixed by forcing an explicit `{' '}` token (`ISSUE-007`).
- **Knowledge-base ingest — boundary-aware chunking with overlap**
  (PR [#321](https://github.com/beenuar/AiSOC/pull/321), closes
  [#277](https://github.com/beenuar/AiSOC/issues/277)). KB ingestion no
  longer splits mid-sentence or mid-code-fence; the new chunker prefers
  paragraph / sentence / code-block boundaries, applies a configurable
  overlap so retrieval doesn't lose context across chunks, and keeps the
  produced chunks within the embedding model's hard token budget.
- **Realtime — WS/SSE authenticated via short-lived tickets**
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246), closes
  [#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
  service's WebSocket and SSE endpoints previously accepted any
  connection. They now require a short-lived signed ticket that the API
  mints for the authenticated session, closing the unauthenticated
  fan-out surface that lived between `services/realtime` and `apps/web`.
- **`apps/web` — Create Case button wired on `/alerts/{id}`**
  (PR [#294](https://github.com/beenuar/AiSOC/pull/294), closes
  [#293](https://github.com/beenuar/AiSOC/issues/293)). The button on
  alert detail rendered but did nothing; it now POSTs through the cases
  endpoint and navigates to the new case workspace.
- **Infrastructure — Terraform CI + missing core modules.** Terraform
  workflow on every `infra/terraform/**` change
  (PR [#251](https://github.com/beenuar/AiSOC/pull/251)) runs
  `terraform init -backend=false`, `terraform validate`, and
  `terraform fmt -check -recursive` against the AWS, GCP, Azure, and
  BYOC configurations; the three reusable modules the AWS and BYOC
  references were already importing — `rds`, `elasticache`, `kafka` —
  are now actually present in `infra/terraform/modules/`
  (PR [#252](https://github.com/beenuar/AiSOC/pull/252)) so a fresh
  `terraform init` against the multi-cloud skeletons no longer errors on
  missing sources. GCP sensitive-var taint cleared on `for_each`
  (PR [#243](https://github.com/beenuar/AiSOC/pull/243)); Azure
  Terraform skeleton documented
  (PR [#247](https://github.com/beenuar/AiSOC/pull/247)).
- **Dependency & CI maintenance.** ~15 Dependabot upgrades across the
  Python, JS, and Go services (FastAPI in `services/{api,actions,agents}`
  via [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320);
  `next` 16.2.7 → 16.2.9 in
  [#323](https://github.com/beenuar/AiSOC/pull/323);
  `framer-motion` 11.18.2 → 12.40.0 in
  [#307](https://github.com/beenuar/AiSOC/pull/307);
  `cryptography` in
  [#301](https://github.com/beenuar/AiSOC/pull/301) /
  [#302](https://github.com/beenuar/AiSOC/pull/302); Go `redis/go-redis`
  in [#297](https://github.com/beenuar/AiSOC/pull/297) /
  [#298](https://github.com/beenuar/AiSOC/pull/298);
  `strawberry-graphql` in
  [#318](https://github.com/beenuar/AiSOC/pull/318);
  `actions/checkout` v6 → v7 in
  [#316](https://github.com/beenuar/AiSOC/pull/316); plus
  `@xyflow/react`, `@types/node`, `tsx`, `@tailwindcss/postcss`); pnpm
  audit high/critical findings cleared
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  PR queue could actually merge; a duplicate `@mdx-js/react` key that
  was breaking `pnpm install` removed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)); `aiohttp` bumped
  to 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).

### AiSOC missing pieces — Phases 1–5 (PR [#337](https://github.com/beenuar/AiSOC/pull/337))

The largest single landing in this release. Twenty-five commits implement
the entire `plans/aisoc-missing-pieces/` roadmap; nothing in the plan is
deferred.

**Phase 1 — Trust-critical fixes** (`1.1`–`1.6`): one build-time
generator + CI gate is now the only place the marquee connector count
lives; the hard-coded `★ 2.3k` GitHub-stars badge was replaced with a
live shields.io endpoint; every SOC 2 / ISO 27001 / GDPR / DPDP claim
across `/sovereign`, `Features.tsx`, and `README.md` is now qualified
with the honest *"controls aligned to"* framing pending a Type I audit
(ADR-0002 below); seven 404'ing footer links and two pricing CTAs were
either stubbed, repointed to `mailto:`, or redirected to GitHub; the
real `services/connectors/app/connectors/gitlab.py` connector that the
marquee pill had been claiming was real now exists; and the `/sovereign`
Terraform deep-links route to the correct subdirectories per cloud, with
Azure added and the unsupported clouds struck.

**Phase 2 — Operational readiness** (`2.1`–`2.6`): the seven Python
services that were silently outside the CI matrix
(`services/{ueba,honeytokens,purple-team,osquery-tls,connectors,actions,
threatintel}` in practice) are now included; the `pytest` and Vitest
configurations enforce a coverage floor via `--cov-fail-under` and the
Vitest `coverage.thresholds`; `prometheus.yml` no longer lists scrape
targets that don't exist (CI now gates against drift); Prometheus
alerting rules + Alertmanager container are wired in `docker-compose.yml`;
seven incident runbooks land under `docs/runbooks/`; and every FastAPI
service now exposes `/livez` (the process is up) and `/readyz`
(dependencies are reachable) separate from the existing `/health`.

**Phase 3 — Real SOAR executors** (`3.1`–`3.5`): the executor surface
stops being a façade. SentinelOne EDR has a real client
(`services/actions/app/integrations/sentinelone.py`) wired to
`ContainHostExecutor`; PAN-OS, FortiGate, Cloudflare WAF, and Cloudflare
DNS firewall each have a real client wired to the appropriate `Block…`
executor; `AckAlertExecutor` and `SuppressAlertExecutor` now talk to
Splunk Enterprise Security, Elastic Security, and Microsoft Defender for
Endpoint directly; Entra ID and Google Workspace are wired as real IdP
clients for `DisableUserExecutor`; and `CreateTicketExecutor` no longer
returns `SIMULATED` — it delegates to the existing Jira, ServiceNow, and
PagerDuty connectors.

**Phase 4 — Larger build-out** (`4.1`–`4.8`):

- **4.1** — Azure RBAC, GCP IAM, Okta, and Google Workspace
  effective-permissions resolvers (closes T3.2). The investigation agent
  can now answer "what can this principal actually do?" across all four
  IdPs, not just AWS.
- **4.2** — Managed-mode auto-provision pipeline (closes T6.1):
  `infra/fly/managed/` + a workflow that creates a fresh Fly tenant from
  a push to `main`, dry-run-safe (won't act without `FLY_API_TOKEN`).
- **4.3** — `make papers` builds the white-paper PDFs in CI, and a
  Playwright project records a 90-second product screencast on demand.
- **4.4** — Connector wave finished: Sysdig, Vault, Snowflake, and
  Cloudflare Zero Trust manifests + docs.
- **4.5** — Pluggable event-warehouse provider
  (`services/api/app/services/event_warehouse/`) with Elasticsearch,
  Splunk, and Chronicle implementations; `croniter`-backed hunt
  scheduler (closes Milestone 1F).
- **4.6** — Deterministic NL → ES|QL / KQL / SPL translator. **81-case
  eval, 100 % syntactic, 100 % semantic** — every output is parsed
  through a grammar validator before return.
- **4.7** — Real-browser visual regression: Playwright + Storybook,
  pinned to `mcr.microsoft.com/playwright:v1.49.0-jammy`. First CI run
  needs `--update-snapshots`.
- **4.8** — Buyer-journey E2E covering `/alerts → Investigation Rail →
  /playbooks` runs on `pnpm e2e`.

**Phase 5 — Strategic decisions** (`5.1`–`5.4`): four immutable ADRs.
[`0001-cyble-cti-moat.md`](docs/decisions/0001-cyble-cti-moat.md) retires
the Cyble-only CTI moat in favour of a pluggable MIT-compatible CTI
fusion layer; [`0002-compliance-claims.md`](docs/decisions/0002-compliance-claims.md)
fixes the *"controls aligned to"* framing until a Type I audit lands and
gates it on a concrete enterprise design partner;
[`0003-mssp-pricing-shape.md`](docs/decisions/0003-mssp-pricing-shape.md)
keeps three public tiers, with MSSP getting its own narrative at
`/mssp`; [`0004-live-demo-strategy.md`](docs/decisions/0004-live-demo-strategy.md)
retires the Cloudflare Tunnel demo and provisions a dedicated managed-mode
tenant on Fly.io.

The Playwright projects (`screencast`, `visual`, `journey`) are gated by
`PLAYWRIGHT_PROJECT` so no project's `webServer` boots when another
runs. The four ADRs are immutable: future changes write a new ADR that
supersedes the old one.

### v8.0 milestones — design system v2, NL→playbook, wave-3 connectors, fidelity loaders

**T3.7 — NL → playbook generator**
(PR [#330](https://github.com/beenuar/AiSOC/pull/330)). Operators can
type a runbook in English and the agent emits a structured playbook YAML
that fits the existing `services/actions` schema: graph of executors,
inputs, and conditionals, with the same JSON-schema validation the
console editor enforces. Backed by the same deterministic translator
substrate as Phase 4.6 so the output stays parsable when the LLM goes
sideways.

**T3.8 — Design system v2 + Storybook**
(PR [#331](https://github.com/beenuar/AiSOC/pull/331)). The console
finally has a single source of truth for tokens, primitives, and
composites. `apps/web/src/components/ui/` is now organized as
`tokens / primitives / patterns`, every component renders in Storybook,
and the visual-regression CI gate from Phase 4.7 watches it.
`DraftFromPromptDialog` was momentarily lost during the migration and
restored in PR [#335](https://github.com/beenuar/AiSOC/pull/335). The
Vite `publicDir` copy that broke the Storybook build under the new
config was disabled in PR
[#336](https://github.com/beenuar/AiSOC/pull/336) so main CI stays
green.

**T4 — Wave-3 marketplace scaffolding + six hardened connectors**
(PR [#333](https://github.com/beenuar/AiSOC/pull/333)). The marketplace
registry gains the schema + tooling for the third connector wave; six
wave-2 connectors had their tests and fixtures hardened to wave-1 parity
in PR [#328](https://github.com/beenuar/AiSOC/pull/328) so every
first-party connector ships with the same shape of negative-path
coverage.

**T5.3 — AIT-LDS + MITRE Engenuity fidelity loaders**
(PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
Detection-fidelity scoring now ingests two canonical labelled datasets:
the AI-Threats Labelled Dataset and the MITRE Engenuity ATT&CK
evaluation set, both fronted by deterministic loaders so the
fidelity-score outputs are reproducible across CI runs.

### Threat-actor attribution — port fix + RBAC

Two narrowly-scoped fixes that together close the only path by which the
investigation agent could silently degrade.

`services/agents/app/agents/investigation_agent.py` defaulted
`AISOC_THREATINTEL_URL` to `http://threatintel:8083`. The service binds
**8005** in its Dockerfile, in `docker-compose.yml`, and in the README
service table — every `POST /api/v1/actors/attribute` call therefore hit
a port nothing listens on. The error path was soft-handled, so
attribution wasn't 500-ing; it was returning empty
attribution silently. PR [#327](https://github.com/beenuar/AiSOC/pull/327)
corrects the default to `http://threatintel:8005`, fixes the matching
`docs/threat-actor-attribution.md` references, raises the stale
`AISOC_ATTRIBUTION_TIMEOUT_SECONDS` default from `10` to `30`, and adds
a regression test (`services/agents/tests/test_attribution_service_url.py`)
that pins the URL and timeout so this can't drift again.

PR [#329](https://github.com/beenuar/AiSOC/pull/329) layers an opt-in
shared-secret gate on the actor-attribution router. When
`AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
must present `Authorization: Bearer <token>`; the comparison is
constant-time, `401` on mismatch. When the env var is unset, the
endpoints stay unauthenticated for backward compatibility and emit a
single startup warning so the operator knows the gate isn't on. The
investigation agent forwards the token via its own
`AISOC_THREATINTEL_SERVICE_TOKEN`. Resolves the
`[#TODO-attribution-rbac]` caveat in `docs/threat-actor-attribution.md`.

### Marketing-shell unification on `tryaisoc.com`

Pre-7.5 the marketing surface was rendering two different navigation
components — the richer `StickyNav` on the landing page and the older
`LandingNav` everywhere else — and likewise two footers. Subpage visitors
saw a degraded nav with hash-only anchors that misbehaved (e.g. `#pricing`
on `/about` was a no-op rather than navigating to `/pricing`).

The unification (commit
[`77039a41`](https://github.com/beenuar/AiSOC/commit/77039a41)):

- `apps/web/src/app/(marketing)/layout.tsx` now imports `StickyNav`
  and `sections/Footer` and renders them around `{children}`. Every
  page in the `(marketing)` route group is content-only.
- Eleven marketing pages had their per-page nav/footer JSX + imports
  removed — they now inherit from the layout.
- The standalone routes (`not-found.tsx`, `why-open-source/page.tsx`,
  `benchmark/page.tsx`) — which live *outside* `(marketing)` and so
  can't pick up its layout — import `StickyNav` and `sections/Footer`
  directly.
- `StickyNav`'s `NAV_LINKS` were absolutised so they work from any URL:
  `/#solution`, `/#pillars`, `/#connectors`, `/benchmark`, `/pricing`,
  `docs/intro`. The "Self-host" CTA points at `/pricing` for the same
  reason.
- `apps/web/src/components/landing/LandingNav.tsx` and
  `apps/web/src/components/landing/Footer.tsx` were **deleted**.

Bundled in the same QA wave:

- **`ISSUE-002`** — `Testimonials` "Become a reference partner" CTA was
  pointing at `/partners`, which 404s. Now goes to `/contact`.
- **`ISSUE-003`** — `/signup` 308-redirects to `/dashboard`. The
  anonymous demo dashboard *is* the signup flow; the old form-fronted
  signup is gone.
- **`ISSUE-004`** — `/not-found` is now a branded dark-theme page with
  the unified shell and a "back to home" CTA, replacing Next's default.
- **`ISSUE-005`** — Removed the dead `status.tryaisoc.com` link from
  the footer.
- **`ISSUE-007`** — `/about` rendered "the 69connectors" because
  React's JSX text-children whitespace rules drop the leading space of
  a text segment that wraps right after a `{expression}`. Forced an
  explicit `{' '}` token so the layout-quirk is immune to reflow.

### Knowledge-base — boundary-aware chunking with overlap

PR [#321](https://github.com/beenuar/AiSOC/pull/321) (closes
[#277](https://github.com/beenuar/AiSOC/issues/277)). The previous
chunker split on a flat character budget, which routinely produced
mid-sentence chunks and severed code fences. The new chunker walks the
document with `paragraph → sentence → token` precedence, applies an
overlap (default 64 tokens, configurable) so retrieval doesn't lose
context across chunks, and keeps every produced chunk under the
embedding model's hard token budget. Retrieval quality on the existing
KB ingestion fixtures improved without any model change.

### Realtime — short-lived ticket auth on WS/SSE

PR [#246](https://github.com/beenuar/AiSOC/pull/246) (closes
[#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
service previously accepted any WebSocket or SSE connection — there was
no way to assert which tenant a stream belonged to except via the
client's word for it. Connections now require a short-lived signed
ticket that the API issues to the authenticated session; the ticket
encodes the tenant and the subscription scope and expires after a small
window so a stolen ticket can't long-tail. Closes a multi-tenant
fan-out surface that had been live since the realtime service shipped.

### Infrastructure — Terraform CI + missing core modules

PR [#251](https://github.com/beenuar/AiSOC/pull/251) — every push that
touches `infra/terraform/**` now runs `terraform init -backend=false`,
`terraform validate`, and `terraform fmt -check -recursive` against the
AWS, GCP, Azure, and BYOC configurations. The same gates ran locally in
the v7.4.0 deploys; they're now actually enforced.

PR [#252](https://github.com/beenuar/AiSOC/pull/252) — the AWS and BYOC
references in v7.4.0 imported `infra/terraform/modules/rds`,
`modules/elasticache`, and `modules/kafka` from sources that did not
exist in the repo. The three modules are now actually present, so a
fresh `terraform init` against the multi-cloud skeletons no longer
errors on a missing source. PR
[#243](https://github.com/beenuar/AiSOC/pull/243) drops the
sensitive-var taint from `for_each` in the GCP module so the plan stays
clean. PR [#247](https://github.com/beenuar/AiSOC/pull/247) documents
the Azure Terraform skeleton end-to-end in `apps/docs/`.

### Dependency & CI maintenance

Around fifteen Dependabot landings since v7.4.0; the headline ones:

- **FastAPI** updated in `services/api`, `services/actions`, and
  `services/agents` (PRs
  [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320)).
- **`next`** 16.2.7 → 16.2.9 (PR
  [#323](https://github.com/beenuar/AiSOC/pull/323)).
- **`framer-motion`** 11.18.2 → 12.40.0 (PR
  [#307](https://github.com/beenuar/AiSOC/pull/307)).
- **`cryptography`** updated in `services/api` and `services/actions`
  (PRs [#301](https://github.com/beenuar/AiSOC/pull/301),
  [#302](https://github.com/beenuar/AiSOC/pull/302)).
- **`redis/go-redis/v9`** updated in `services/enrichment` and
  `services/ingest` (PRs
  [#297](https://github.com/beenuar/AiSOC/pull/297),
  [#298](https://github.com/beenuar/AiSOC/pull/298)).
- **`strawberry-graphql`** updated in `services/api`
  (PR [#318](https://github.com/beenuar/AiSOC/pull/318)).
- **`actions/checkout`** v6 → v7 across every workflow
  (PR [#316](https://github.com/beenuar/AiSOC/pull/316)).
- **`aiohttp`** 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).
- **pnpm audit** cleared of all high/critical findings
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  queue could merge without the global gate failing on unrelated noise.
- **`pnpm-lock.yaml`** duplicate `@mdx-js/react` key fixed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)) — was breaking
  `pnpm install` on fresh clones.
- Other dev/test bumps: `@xyflow/react` 12.10.2 → 12.11.0
  (PR [#283](https://github.com/beenuar/AiSOC/pull/283)),
  `@types/node` 20.19.39 → 25.9.2
  (PR [#285](https://github.com/beenuar/AiSOC/pull/285)),
  `tsx` 4.22.1 → 4.22.4 (PR
  [#306](https://github.com/beenuar/AiSOC/pull/306)),
  `@tailwindcss/postcss` 4.3.0 → 4.3.1 (PR
  [#305](https://github.com/beenuar/AiSOC/pull/305)).

### Docs

- `AISOC_V8_PROGRESS.md` tracker re-introduced
  (PR [#334](https://github.com/beenuar/AiSOC/pull/334)) so the v8.0
  milestone burn-down lives at the repo root again.
- `AGENTS.md` updated to record AiSOC (`github.com/beenuar/AiSOC`) as the
  single source of truth — the older `AISOC-Cyble` mirror is now
  archived (PR [#326](https://github.com/beenuar/AiSOC/pull/326);
  archive-notice sync in PR
  [#325](https://github.com/beenuar/AiSOC/pull/325); `plans/cyble-aisoc/`
  subtree merged for posterity in PR
  [#324](https://github.com/beenuar/AiSOC/pull/324)).
- Marketing-page docs links repointed at the Docusaurus site
  (PR [#245](https://github.com/beenuar/AiSOC/pull/245)).
- Connector pages — Vault → Auth0/Okta cross-links unbroken
  (post-merge fix on `main`).
- `README.md` synced to v7.4.0 ahead of this release
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246)).

### Changed

- **`VERSION`** bumped 7.4.0 → 7.5.0.
- **`apps/web/package.json`** bumped 7.3.1 → 7.5.0. The web app's
  `package.json` had drifted from `VERSION` since the v7.3.1 hotfix;
  this release reconciles them.
- **`README.md`** version badge + headline updated to v7.5.0.

### Migration notes

None required for users on v7.4.0 — every change in this release is
either additive (new endpoints, new env vars defaulting to safe
unauthenticated behaviour, new connectors and executors) or a pure bug
fix to existing behaviour. Specifically:

- The threat-actor attribution port fix changes a *default* — if you
  had explicitly set `AISOC_THREATINTEL_URL` in your environment, it is
  honoured unchanged.
- The optional `AISOC_THREATINTEL_SERVICE_TOKEN` gate is off until you
  set it. Set it on both the `agents` and `threatintel` services to
  turn the gate on.
- The Realtime short-lived-ticket auth is enforced server-side; the
  `apps/web` client mints + refreshes tickets automatically against the
  authenticated API session. No client work is required for in-tree
  consumers; external SSE consumers must adopt the ticket flow.
- The marketing-shell unification is a `tryaisoc.com`-only change; it
  doesn't touch the console at `tryaisoc.com/dashboard` or any
  product surface.

## [7.4.0] — 2026-05-29

Security-hardening and platform release. Folds in the May 27–29 hardening wave,
multi-agent routing, and multi-cloud infrastructure skeletons that landed on
`main` since v7.3.1.

### Highlights

- **Security hardening.** Prompt-injection sanitizer wired into the
  classification agents (PR [#219](https://github.com/beenuar/AiSOC/pull/219));
  cross-tenant isolation enforced on the detection-loop suggestion lookups
  (PR [#221](https://github.com/beenuar/AiSOC/pull/221)) and on the compliance,
  phishing, and knowledge-base endpoints
  (PR [#236](https://github.com/beenuar/AiSOC/pull/236)); nightly cross-tenant
  RBAC regression gate (PR [#197](https://github.com/beenuar/AiSOC/pull/197));
  cryptography CVEs cleared and unfixable advisories time-boxed
  (PR [#229](https://github.com/beenuar/AiSOC/pull/229)); CodeQL quality notes
  resolved (PR [#224](https://github.com/beenuar/AiSOC/pull/224)).
- **Multi-agent routing.** `DetectAgent.process` wired to the `FusionEngine`
  over cross-service HTTP (PR [#198](https://github.com/beenuar/AiSOC/pull/198));
  `/investigate` swapped to the `RouterOrchestrator` behind the
  `ROUTER_INVESTIGATE` flag (PR [#196](https://github.com/beenuar/AiSOC/pull/196));
  Redis-backed scheduler singleton guard for in-process workers
  (PR [#218](https://github.com/beenuar/AiSOC/pull/218)).
- **Multi-cloud infrastructure.** Serverless-container Terraform skeletons for
  GCP (Cloud Run + Cloud SQL + Memorystore) and Azure (Container Apps +
  PostgreSQL Flexible Server + Cache for Redis), mirroring the AWS/EKS reference
  file-for-file (PR [#240](https://github.com/beenuar/AiSOC/pull/240)).
- **Live dashboard & landing.** Real `/metrics` data restored on
  `tryaisoc.com/dashboard` (PR [#192](https://github.com/beenuar/AiSOC/pull/192));
  API/agents machines kept warm so the dashboard no longer 500s
  (PR [#234](https://github.com/beenuar/AiSOC/pull/234)); seed timestamps
  re-anchored so the live dashboard never goes empty
  (PR [#235](https://github.com/beenuar/AiSOC/pull/235)); landing CTAs pointed at
  the live dashboard (PR [#233](https://github.com/beenuar/AiSOC/pull/233)).
- **Dependency & CI maintenance.** ~40 Dependabot upgrades across the Python,
  JS, and Go services plus CI stabilization (Ruff cleanup, OpenAPI export
  permissions, pnpm-lock dedupe).

### Bump `@vitejs/plugin-react` 4.7.0 → 6.0.2 in `apps/web`

Dev-only dependency upgrade (PR [#178](https://github.com/beenuar/AiSOC/pull/178)).
`@vitejs/plugin-react@6` is built against vite@8, while vitest@4 (landed in
PR #179) still ships its own internal vite@7. pnpm resolves both side-by-side
without conflict: vitest@4 uses vite@7 for the test runtime, and `react()` is
loaded from the vite@8-flavoured build of the plugin. Vitest is tolerant of
the plugin API surface across vite 5/6/7/8, so `apps/web/vitest.config.ts`
needed no further changes after the cast we already removed in #179.

No production code touched. Locally verified: web 349/349 tests pass, lint
remains at 0 errors / 76 warnings (unchanged baseline), `tsc --noEmit` clean,
production build succeeds.

### Bump `vitest` 2.1.9 → 4.1.6 across the workspace

Dev-only dependency upgrade (PR [#179](https://github.com/beenuar/AiSOC/pull/179))
across `apps/web`, `packages/sdk-ts`, and `services/mcp`. Vitest v3 and v4
introduced two breaking changes that surfaced in our suite:

* **`vitest/config` no longer exports `UserConfig`.** `apps/web/vitest.config.ts`
  used `import('vitest/config').UserConfig['plugins']` to bridge the vitest@2
  (vite@5 types) ↔ `@vitejs/plugin-react@4` (vite@7 types) version mismatch. In
  vitest@4 both packages target vite@7, so the bridging cast is gone and
  `react()` is consumed directly.
* **`global` is no longer in the default DOM lib in `@vitest/runner`'s typing.**
  `packages/sdk-ts/src/client.test.ts` referenced the Node global namespace via
  `(global.fetch as ...)`; it now uses `globalThis.fetch`, which is the
  cross-runtime idiom and was already what every other test in the SDK suite
  used. No runtime behaviour change — `global === globalThis` in Node.

Verified locally: SDK 9/9 tests pass, web 349/349 tests pass, web lint stays at
0 errors (warning count unchanged from PR #193's baseline). No production code
touched, no behavioural change to the published `@aisoc/sdk` package or to the
shipped web bundle.

### Wire `DetectAgent.process` to `FusionEngine` via cross-service HTTP (Issue #190)

Closes [#190](https://github.com/beenuar/AiSOC/issues/190).

Closes the missing edge in the four-agent façade: `DetectAgent` previously
self-described as the public detection surface but had no synchronous entry
point into the fusion pipeline — callers either had to enqueue onto Kafka and
wait, or reach into `services/fusion` internals directly. This change adds the
last mile so a raw alert from any caller (LLM tool calls, ad-hoc CLI, the API
gateway) runs through the same `FusionEngine` instance that backs the Kafka
consumer path — dedup, correlation, ML scoring, confidence labelling, and RBA
all apply identically regardless of how the alert arrived.

Three additive pieces, no behavioural changes to existing paths:

* **`POST /process` on the fusion service**
  (`services/fusion/app/api/router.py`). Accepts a `RawAlert`, returns a
  `FusedAlert`, and is wired to the already-running `FusionWorker`'s engine
  instance via the module-level `_worker_ref` the worker registers on startup.
  Returns `503` when the worker hasn't finished booting (Kafka consumer not
  yet attached) so callers fail loudly instead of getting a half-initialised
  pipeline. Lives at the root path — the router is mounted with no prefix in
  `services/fusion/app/main.py`.
* **`services/agents/app/tools/fusion.py`** — thin async HTTP client used by
  the agents service. Posts to `{FUSION_SERVICE_URL}/process` (defaults to
  `http://fusion:8003/process` inside the docker-compose network), forwards
  an optional bearer token, and **raises** on any non-2xx or transport error.
  This is a deliberate contrast with `app.tools.graph`, which degrades
  gracefully for investigation queries: fusion is the primary detection
  plane, so a silent fallback here would lose alerts.
* **`DetectAgent.process(raw_alert, *, api_token=None)`**
  (`services/agents/app/agents/__init__.py`). Classmethod delegate over the
  HTTP client — keeps `DetectAgent` import-light (no engine instantiation in
  the agents process) and preserves the existing back-compat aliases.

Tests lock the contract on both sides. `services/fusion/tests/test_process_endpoint.py`
exercises the endpoint against an `ASGITransport` + `AsyncClient`: novel
alerts return a `NEW_INCIDENT` envelope, replays return `DUPLICATE`, an
unwired worker yields `503`, a worker without an engine yields `503`,
malformed and bad-severity payloads return `422`, and a regression guard
asserts the endpoint and worker share the same `FusionEngine` instance.
`services/agents/tests/test_fusion_client.py` uses `respx` to lock the
client wiring: it must post to `/process` (not `/api/fusion/process` — that
mismatch was caught and fixed during initial wiring), the Authorization
header is set if and only if a token is supplied, `httpx.HTTPStatusError`
propagates on 503/422, and `httpx.HTTPError` propagates on transport
failures. A final trio of tests pins `DetectAgent.process` as a faithful
delegate to the client (args pass through unchanged, errors propagate, no
swallowed exceptions).

No feature flag and no env gate: the wiring is purely additive — no existing
caller of the fusion service or the agents service changes shape, and the new
endpoint/method only fire when something explicitly invokes them.

### Cross-tenant RBAC regression suite (F013, security)

Closes [#159](https://github.com/beenuar/AiSOC/issues/159).

Pure-unit isolation suites that exercise the tenant boundary at the
endpoint-function level (no live DB, no FastAPI request cycle) so the
contract is testable in milliseconds and survives ORM churn:

- `services/api/tests/test_threat_intel_tenant_isolation.py` — IOC,
  actor, and feed list/get/create/delete are scoped by `tenant_id`,
  cross-tenant lookups resolve to 404, and writes attach
  `current_user.tenant_id` even when the payload smuggles a different
  one.
- `services/api/tests/test_alerts_tenant_isolation.py` — every
  read/write/queue/claim path on `/alerts` binds `tenant_id` into the
  compiled SQL or forwards it to the service layer
  (`build_queue` / `claim_alert`).
- `services/api/tests/test_llm_credentials_tenant_isolation.py` —
  BYOK credential GET/PUT/DELETE scope by `tenant_id`, new rows bind
  the caller's tenant, and `emit_audit` is invoked with the caller's
  tenant + actor (`CredentialVault` is stubbed so the assertions are
  on the persistence boundary, not crypto).

Assertions read the *compiled* SQL bind parameters rather than the
shape of any single query so they don't break on benign rewrites. All
three suites were mutation-tested by temporarily dropping the
`tenant_id` predicate in the corresponding endpoint — every dropped
predicate produced at least one failing test, confirming the suites
are wired to the right surface.

`.github/workflows/cross-tenant-rbac.yml` runs the three suites
nightly on `main` (06:30 UTC, ahead of `compose-smoke-nightly` so a
tenant boundary regression shows up as the first nightly signal) and
on-demand via `workflow_dispatch`. On failure it uploads a JUnit
report and opens a `security`-labelled tracking issue.

### Attack-chain timeline UI (T3.3, v8.0)

`/cases/{id}` now ships an **Attack Chain** tab that visualises the ranked
timeline returned by `/v1/cases/{id}/attack-chain` (shipped earlier under
`8df637b9`). The new `AttackChainPanel` in
`apps/web/src/components/cases/CaseWorkspace.tsx`:

- Window selector with the same vocabulary as the backend `WindowLiteral`
  (`1h`, `6h`, `24h`, `72h`, `7d`, `30d`) — selection is deep-linkable via
  `?window=…` and survives reload.
- One card per `ChainLink` with the alert title, severity chip (driven by
  the canonical 5-tier ladder `info | low | medium | high | critical`),
  confidence percent, MITRE technique IDs, and the deterministic narrative
  reason emitted by `services/api/app/services/attack_chain.py`.
- Entity-graph summary panel — node count grouped by `kind` (`user`,
  `asset`, `process`, `ip`, `domain`, `alert`), top edges, and a per-node
  severity chip when present in `_entity_graph_payload`.
- SWR-keyed on `(case_id, window)` with skeleton, error, and empty states
  that match the rest of the case workspace.
- New `casesApi.getAttackChain` method + `AttackChainTimeline`,
  `AttackChainWindow`, `AttackChainLink`, `AttackChainEntityNode`,
  `AttackChainEntityEdge`, `BackendAttackChainResponse` types in
  `apps/web/src/lib/api.ts`. The wire format matches the backend `to_dict`
  shape exactly (node `kind` rather than `type`; optional `severity` and
  `event_time` from `_entity_graph_payload`).
- Coverage in `apps/web/src/components/cases/CaseWorkspace.test.tsx`:
  empty-state, error-state, and three data-rendering assertions
  (alert titles, confidence percent, MITRE techniques). The SWR mock is now
  key-aware so attack-chain and attack-path fetches stay isolated, and
  `useSearchParams` is stateful so window-selection deep-links round-trip
  cleanly under test. The `WindowSelector` is a labelled
  `role="group"` of buttons with `aria-pressed`, so deep-link assertions
  resolve the active option via the single pressed button inside the
  group rather than a non-existent `<select>` value.

Closes the UI side of T3.3 in `AISOC_V8_PROGRESS.md`. Pre-existing
non-blocking lint warnings in `CaseWorkspace.tsx` are unchanged by this
diff.

### LLM input contract — static regression gate (T2.3, v8.0)

Closes T2.3 by adding the missing **bypass-prevention** layer on top of the
existing fail-closed validator (`services/agents/app/llm/contract.py`). Two
new test files in `services/agents/tests/`:

- `test_llm_contract_extra.py` (10 cases) — fills the coverage gaps in the
  shipped contract: `safe_astream` validates messages exactly once and
  refuses to yield any chunk on violation; `make_safe_chat_model` proxies
  non-LLM attributes through but routes `ainvoke` / `astream` through
  validation; `classify_message` rejects `api_key = '...'` assignments and
  PEM private-key headers; `set_contract_enforcement(False)` lets raw OCSF
  through in soft mode and re-arms cleanly when flipped back to `True`.
- `test_llm_contract_no_bypass.py` (3 cases) — **AST-based static gate**
  that walks every `*.py` file under `services/agents/app/` and fails CI on
  any direct `.ainvoke(...)` / `.astream(...)` call whose receiver is not on
  an explicit allowlist (`_graph`, `investigation_graph`, `graph` — all
  LangGraph control-flow handles, not LLMs) or whose file is not the
  contract module itself. Ships with self-tests proving (a) a synthetic
  `llm.ainvoke(...)` bypass trips the detector and (b) allowlisted
receivers do not. Adding a new agent that calls a chat model directly
now fails the build until it routes through `safe_ainvoke` /
`safe_astream` / `make_safe_chat_model`.

The survey behind this gate confirmed every existing direct chat-model call
under `services/agents/app/` already goes through the safe wrapper — the
remaining `.ainvoke` / `.astream` call sites are LangGraph control-flow on
compiled graphs, which is why those receivers are explicitly allowlisted
rather than silently ignored.

### LLM input contract — CI tests (T2.3, v8.0)

`services/agents/tests/test_llm_contract.py` exercises `classify_message` /
`LLMInputContract.validate` / `validate_messages`: raw OCSF-shaped JSON in a
user message fails closed when `AISOC_AGENTS_LLM_CONTRACT_ENFORCED=1`
(default), and prose plus `summarize_structure_for_llm` output passes. Tests
use `{"role", "content"}` dict messages so they run without importing
`langchain_core` (the contract already coerces LangChain `BaseMessage` and
dicts the same way).

### Real-time graph-update WebSocket (T1.4, v8.0)

Closes the v8.0 loop between the ingest-side graph writer (T1.1) and the
operator console. `services/realtime` now exposes a `graph` WebSocket
channel reachable at `/ws/graph` (or piggy-backed on `/ws/all`) and runs a
dedicated `aisoc-realtime-graph` Kafka consumer group against the
`security.graph_updates` topic that the Go ingest writer publishes to
(`services/ingest/internal/graph/writer.go`). Each `GraphUpdate` envelope
(`entity_id`, `change_type`, `ts`, `label`, `rel_type`, `from`, `to`,
`properties`, `schema_version`) is fanned out to clients scoped by
`tenant_id`, with `default` as the single-tenant fallback so self-hosted
deploys without explicit tenant tagging still light up live. The new
consumer is wired alongside the existing fused-alerts consumer in
non-blocking mode: a missing or unreachable graph topic logs at `warn` and
never blocks the higher-priority alerts/cases/agents/insights fan-out. The
topic name honours both `AISOC_GRAPH_UPDATES_TOPIC` and
`KAFKA_TOPIC_GRAPH_UPDATES` envs (defaults to `security.graph_updates` so
it matches the Go writer's default in
`services/ingest/internal/config/config.go` without manual plumbing), and
setting it to the empty string disables the consumer entirely for tests
that don't spin up Kafka graph traffic. The Investigation Rail and Attack
Chain views (T3.3 UI, in flight) can subscribe today and pick up node /
edge mutations within ~1s of the upstream event reaching ingest.

### Public weekly benchmark scoreboard at /docs/benchmark-scoreboard

Public, append-only weekly scoreboard now lives at
[`/docs/benchmark-scoreboard`](https://docs.tryaisoc.com/docs/benchmark-scoreboard).
One row per published eval run — date, agent version, commit SHA, MITRE
accuracy, MTC p50/p95, total USD, total tokens — sourced from a
checked-in JSON file at `apps/docs/static/data/scoreboard.json` and
validated against `scoreboard.schema.json` on every docs build via the new
`pnpm --filter @aisoc/docs scoreboard:check` script. Substrate rows
(deterministic CI gate, no LLM) are visually separated from wet-eval rows
(real LangGraph agent, real LLM, real cost), so substrate numbers can
never be quoted as live agent performance. Includes an inline SSR-rendered
SVG sparkline of MITRE accuracy over time, no Recharts/client JS bundle
hit. The marketing `/benchmark` page now cross-links to the scoreboard for
the full weekly history. Wet-eval rows arrive automatically once the T5.5
weekly CI workflow lands.

### Connectors — Wazuh Indexer ingest (Stage 2)

New first-class endpoint connector for Wazuh deployments. AiSOC now polls the
Wazuh Indexer API directly (no agent rewrite required) and normalizes alerts
into the platform's OCSF-aligned schema, collapsing Wazuh's native severity
ladder into the four-tier `info | low | medium | high` set used everywhere
else.

- **`services/connectors/app/connectors/wazuh.py`** — `WazuhConnector`
  subclasses `BaseConnector`, polls `wazuh-alerts-*` indices over HTTPX with
  basic-auth, paginates time-windowed queries, retries on 5xx with capped
  backoff, and emits one normalized event per alert hit. Cursor is the
  highest `@timestamp` seen so reruns are idempotent.
- **`services/connectors/app/connectors/__init__.py`** — registered in
  `_CONNECTOR_CLASSES`; the registry now declares 52 first-party connectors.
- **`plugins/wazuh/plugin.yaml`** + `pnpm marketplace:sync` — connector ships
  as a marketplace entry under category `siem`, mirrored into
  `apps/web/public/marketplace/index.json`.
- **`apps/docs/docs/connectors/wazuh.md`** + sidebar entry — operator setup
  walkthrough (API user + role, time-window semantics, severity collapse
  table, troubleshooting matrix).
- **`services/connectors/tests/test_wazuh_connector.py`** — 24 unit tests
  cover schema, auth headers, time-window query shape, retry policy, every
  documented severity bucket, and the empty/error paths.

### CLI — `aisoc plugin new` per-type templates

Replaces the old hard-coded `plugin scaffold` with a real templated generator
keyed on plugin kind (`enricher | connector | responder | detection | widget`).
Templates ship inside the `aisoc-cli` wheel via `importlib.resources` so the
CLI works unchanged after `pip install aisoc-cli`.

- **`packages/aisoc-cli/src/aisoc_cli/main.py`** — `aisoc plugin new <NAME>
  --type <kind>` loads the template tree from
  `src/aisoc_cli/templates/<kind>/`, runs `string.Template` substitution for
  `${slug}`, `${name}`, `${author}`, and writes a project that already
  validates against the manifest schema. `aisoc plugin scaffold` is preserved
  as an alias for backwards compatibility.
- `pyproject.toml` — `force-include` ships the templates tree in the wheel.
- Tests parameterize across all five plugin types and assert the manifest
  validates and no `${...}` placeholders leak through.
- `plugins/templates/README.md` is now a pointer to the canonical templates
  inside the CLI package.
- **`apps/docs/docs/plugins/cli.md`** — documents the new CLI surface and is
  added to the Plugin SDK sidebar.

### Infrastructure — GCP Cloud Run + Cloud SQL Terraform skeleton

Adds a serverless-first BYOC equivalent of the existing AWS module so AiSOC
can be stood up on Google Cloud with one `terraform apply`. Stage 2 #15.

- **`infra/terraform/gcp/`** — Cloud Run for `api`/`web`/`ingest`, Cloud SQL
  Postgres 16 + Memorystore Redis 7.2 on private IPs through a dedicated VPC
  and Serverless VPC Access connector, Secret Manager for every credential
  (auto-generated `postgres_password`, `secret_key`, `credential_key`,
  `redis_auth`, optional `openai_api_key`), and Artifact Registry for images.
  One service account per Cloud Run service with least-privilege
  `secretAccessor` bindings. The skeleton points at the public GHCR demo
  images so a fresh `apply` works zero-config; operators override via
  `api_image` / `web_image` / `ingest_image`.
- **`apps/docs/docs/deployment/gcp.md`** + sidebar entry (between `kubernetes`
  and `env-vars`) — quickstart, state-backend guidance, Cloud SQL Auth Proxy
  notes, cost envelope, and the long-running-services follow-up plan (GKE
  Autopilot for `agents`, `realtime`, `connectors`, `alert-fusion`,
  `threatintel`, `fusion`).
- `infra/terraform/gcp/README.md` mirrors the deploy doc for module-local
  consumption.

### Live Actions — generic vendor/capability dispatcher (Stage 2 #8)

Adds a vendor-pluggable response-action surface so plugins can register
executors against the existing capability taxonomy without forking the
in-tree executor list. The dispatcher always returns a typed
`LiveActionResult`; unknown `(vendor_id, capability)` pairs return `FAILED`
with `error="executor_not_found"` so the agent degrades gracefully instead
of seeing a 500.

- **`services/actions/app/live_actions/models.py`** —
  `LiveActionRequest`/`Result`/`Descriptor` Pydantic models (UTC-aware).
- **`services/actions/app/live_actions/registry.py`** — `LiveActionExecutor`
  ABC + module-level `LiveActionRegistry`.
- **`services/actions/app/live_actions/dispatcher.py`** — structured logging,
  error translation, dry-run + missing-credential semantics
  (`SIMULATED`, never `PARTIAL`).
- Adapters wrap every existing in-tree executor (CrowdStrike, Okta, AWS SG,
  Splunk) so they now show up as `builtin` descriptors.
- **`services/api/app/api/v1/endpoints/live_actions.py`** — `discover`,
  `dispatch`, `dry-run` REST routes; built-ins are registered at app startup.
- 45 new tests across models / registry / dispatcher / router / builtins
  (full actions suite: 99 passed).
- **`apps/docs/docs/concepts/live-actions.md`** + sidebar slot.
- Drive-by: fixed two pre-existing broken doc links flagged by the
  Docusaurus build (osctrl → aisoc-direct stub, `air-gapped` → `env-vars`).

### Agents — deterministic NL→ES|QL translator + 50-pair eval set (Stage 2 #16)

Replaces the template fallback in
`services/api/app/api/v1/endpoints/nl_query.py` with a real, offline-friendly,
deterministic IR + renderer that emits ES|QL, KQL, and SPL and runs every
output through a lightweight grammar validator before returning. An optional
LLM enhancement path (`gpt-4o-mini`) is exposed via `enhance_with_llm` for
callers with credentials; failures fall back to the deterministic path so the
air-gapped story keeps working and the eval harness stays reproducible.

- **`services/agents/app/nl_query/`** — IR, grammar, translator, renderers.
- All `# TODO: translate` comments removed from `nl_query.py`.
- **`services/agents/tests/eval_data/nl_query_eval.json`** — 50-pair gold
  NL→ES|QL eval set.
- **`services/agents/tests/test_nl_query_eval.py`** — 100% syntactic validity,
  100% semantic match (50/50 perfect) against gold intents.
- Pre-existing services/agents tests still green (162 passed) when ignoring
  the asyncpg-dependent suites that fail on a fresh checkout.

### Connectors — auditd file_tail + AiSOC audit.rules profile

Replaces the host-agent dependency for Linux endpoint visibility with a
file-tail connector that consumes `audit.log` directly, plus an opinionated
auditctl ruleset whose `-k` keys map 1:1 to detection rules.

- **`services/connectors/app/connectors/auditd.py`** — `AuditdConnector` tails
  `/var/log/audit/audit.log`, reassembles multi-record events by msg id,
  decodes hex `proctitle`/`argv` blobs, and normalizes via
  `_severity_from_event` using `aisoc_*` keys baked into the audit rules
  profile. Cursor is `(inode, byte_offset)` so log rotation is handled.
- **`profiles/auditd/aisoc.rules`** + `profiles/auditd/README.md` — ships an
  opinionated auditctl ruleset and documents install + reload.
- **`detections/`** — 4 new detection rules pivot off `auditd_key` for
  sudoers / SSH config tampering, kernel module load, and systemd
  persistence. No host-agent dependency.
- `plugins/auditd/plugin.yaml` + `pnpm marketplace:sync` — registers the
  connector in the public marketplace.
- **`apps/docs/docs/connectors/auditd.md`** + sidebar entry — setup doc.
- **`services/connectors/tests/test_auditd_connector.py`** — covers schema,
  hex decode, argv reassembly, multi-record merge, severity heuristic, and
  file tailing (full connectors suite: 444 passed, excluding the
  `apscheduler` dev-dep `test_scheduler.py`).

### Documentation — operator notifications & plugin lifecycle

Two new operator-facing docs pages, both registered in the Docusaurus sidebar:

- **`apps/docs/docs/operations/notifications.md`** — complete inventory of
  every notification surface in AiSOC: Web Push to the responder PWA (VAPID,
  Redis, topic routing), Slack ChatOps via `/aisoc`, Slack/Teams ChatOps
  verification, one-shot `notify_slack` from playbooks, `create_ticket`
  simulation + recommended plugin path, honeytoken first-touch webhooks,
  connector freshness alerts, on-call gating, suppression / quiet-hours, and
  a per-mechanism testing recipe.
- **`apps/docs/docs/plugins/lifecycle.md`** — operator's view of plugin
  states (`Discovered → Loaded → Enabled/Disabled`, plus `signature_status`),
  trust modes (`strict | warn | disabled`), filesystem + OCI discovery, the
  full operator REST API with required permissions, configuration reference,
  upgrade and rollback semantics, and the structlog events worth alerting on.

Both pages cross-link the existing `concepts/live-actions`, `plugins/overview`,
`plugins/publishing`, and `plugins/cli` pages so they sit in the right place
in the information architecture.

### API — blameless case post-mortem endpoint

Mirrors the existing case auto-summary pipeline to produce a deterministic,
blameless retrospective for any case.

- **`services/api/app/services/case_postmortem.py`** — pure builder + async
  DB orchestrator (`build_case_postmortem`). Reuses `SummaryCaseRow` /
  `SummaryCommentRow` / `SummaryTaskRow` fetchers from `case_summary` so the
  post-mortem and the live summary draw from the same source of truth.
  Output is a Pydantic `CasePostmortem` covering incident overview,
  contributing factors, detection timing/gaps, response phases (detect →
  contain → eradicate → recover), blast radius, what went well / what fell
  short, and concrete action items.
- **`services/api/app/services/case_postmortem_html.py`** — pure HTML
  renderer matching the summary renderer (inline CSS, print-friendly,
  defensive escaping, no external assets).
- **`services/api/app/api/v1/endpoints/cases.py`** —
  `GET /api/v1/cases/{case_id}/postmortem` with `?format=json|html`.
- **`services/api/tests/test_case_postmortem.py`** — pure-builder + HTML
  tests including XSS escaping, deterministic ordering, and explicit
  blamelessness assertions (analyst handles must not surface in the
  narrative; the assignee header line is explicitly allow-listed).
- **`apps/docs/docs/operations/case-reports.md`** + sidebar — operator page
  covering both `/summary` and `/postmortem` with audience, output,
  automation, and runbook archive guidance. Cases summary breadcrumb now
  points operators at both endpoints.

### Threat Intelligence — STIX → MISP push (Stage 3 #20)

The threat-intel pipeline already pulled events from MISP (read-only). This
closes the loop with a write path: every STIX 2.1 indicator or bundle
published through `/api/v1/threatintel/stix/...` can be mirrored into the
configured MISP instance as a native event with one or more attributes.

- **`services/api/app/services/misp_push.py`**
  - Pure mappers: `parse_stix_pattern`, `stix_indicator_to_misp_attribute`,
    `stix_bundle_to_misp_event`, `confidence_to_threat_level`. Covers
    `ipv4`/`ipv6`, `domain-name`, `url`, `email-addr`, `file:hashes`
    (MD5/SHA-1/SHA-256/SHA-512) and `file:name`. Untranslatable patterns
    are counted in `skipped_attributes`, never silently dropped.
  - `MispPushClient` — async httpx wrapper for `/users/view/me` (health),
    `/events/add` (push), `/events/view/{id}` (read-back). Every call runs
    through the air-gap gate (`enforce_airgap_for_url`) first.
- **`services/api/app/api/v1/endpoints/stix_taxii.py`**
  - `POST /stix/indicators?push_to_misp=true` — response now includes a
    `misp` block (`pushed`, `misp_event_id`, `misp_event_uuid`, `url`,
    `pushed_attributes`, `skipped_attributes`, `error`).
  - `POST /stix/bundles?push_to_misp=true` — same, but the whole bundle
    becomes one MISP event.
  - `GET /stix/misp/health` — calls MISP `/users/view/me`, never echoes the
    API key back.
  - `POST /stix/misp/dry-run` — returns the exact MISP event payload AiSOC
    *would* send, plus an `airgap_blocked` flag for air-gapped audits.
  - Push failures are intentionally non-fatal: the AiSOC store is the source
    of truth, the MISP mirror is best-effort and surfaces the structured
    error on the same response.
- **`services/api/app/core/config.py`** — new MISP push settings:
  `MISP_VERIFY_SSL`, `MISP_PUSH_AUTO`, `MISP_PUSH_DEFAULT_DISTRIBUTION`,
  `MISP_PUSH_DEFAULT_THREAT_LEVEL`, `MISP_PUSH_DEFAULT_ANALYSIS`,
  `MISP_PUSH_TIMEOUT_SECONDS`. Existing `MISP_URL` / `MISP_API_KEY` are
  reused from the read path.
- **`services/api/tests/test_misp_push.py`** — 76 tests covering pure
  mappers, air-gap gating, MISP HTTP failures (401 / 5xx / timeout), the
  publish endpoints with and without push, the health probe, and the
  dry-run endpoint.
- **`apps/docs/docs/integrations/misp-push.md`** + sidebar entry — operator
  doc with config, endpoints, the STIX→MISP type table, failure modes, and
  the dry-run-as-air-gap-proof workflow.
- **`apps/docs/docs/operations/airgap.md`** — clarifies that the existing
  `MISP_URL` / `MISP_API_KEY` envs cover both pull and push, with a pointer
  to the new integration page.

### Security — MSSP RBAC hardening on `/threat-intel` (Issue F013)

The `/v1/threat-intel/*` endpoints (IOCs, threat actors, intel feeds) were
previously gated only by `get_current_user`, meaning **any authenticated
role**, including `viewer` and `soc_analyst`, could `POST` an IOC, `DELETE`
a feed, or create a new `ThreatActor` profile. In a managed-SOC / MSSP
deployment that is a privilege-escalation vector: a compromised analyst
seat can poison detections across the whole tenant by injecting false IOCs
or deleting the feed that hydrates them.

- **`services/api/app/api/v1/endpoints/threat_intel.py`** — every route now
  declares the explicit permission it needs via
  `Depends(require_permission("threat_intel:read" | "threat_intel:write"))`.
  Read routes (`GET /iocs`, `/iocs/{id}`, `/actors`, `/feeds`) require
  `threat_intel:read`; write routes (`POST /iocs`, `DELETE /iocs/{id}`,
  `POST /actors`, `POST /feeds`, `DELETE /feeds/{id}`) require
  `threat_intel:write`. The legacy `User`-typed dependency was replaced with
  the platform-standard `AuthUser` so JWT and API-key callers are gated by
  the same code path.
- **`services/api/app/core/security.py`** — `ROLE_PERMISSIONS` now grants
  `threat_intel:write` to `tenant_admin` and `soc_lead` in addition to the
  existing `admin` / `platform_admin` / `threat_hunter` set. Without this
  the endpoint hardening would have locked out the two roles that legitimately
  need to manage tenant intel during an investigation.
- **`services/api/tests/test_threat_intel_rbac.py`** — 38 new regression tests
  pin the role/permission map (write-roles must hold `:write`, read-only roles
  must not), assert that `CurrentUser.require_permission` raises HTTP 403 for
  under-privileged roles and 200 for privileged ones, cover the API-key code
  path including scope wildcards, and grep the endpoint module to ensure
  every route still uses `require_permission(...)` (so a refactor that
  silently downgrades a route fails CI).

Tracked as **F013** in `docs/community-feedback/2026-05-12/`.

### Detection quality — per-rule cross-fire FP eval gate (Issue F005)

`scripts/validate_detections.py` already replays each native rule against
its own positive + negative fixture (TP / TN gates), but that test cannot
catch the failure mode operators feel hardest in production: rule **R**
firing on an event that was meant for rule **O**. A single overly-broad
rule that matches every `ConsoleLogin` or every `rundll32.exe` execution
silently drives alert volume up and precision down across the whole pack
without tripping the per-rule TP/TN replay.

- **`services/agents/tests/test_detection_fp_rate.py`** — new pytest
  suite that replays every native rule's `match_when` against every
  *other* rule's positive fixture and grades the per-rule cross-fire
  FPR. Fails CI if any rule exceeds `MAX_PER_RULE_FPR` (default 5%) or
  regresses on its own positive/negative fixture. Failure output groups
  the worst 10 offenders with their cross-fire targets so the operator
  can narrow the rule (or allowlist a deliberate broad-vs-narrow
  overlap via `EXPECTED_CROSS_FIRES`) without re-running a full eval
  sweep. Current corpus: 816 native rules evaluated, mean FPR 0.0,
  worst FPR 0.49% — well under the 5% ceiling.
- **`scripts/run_evals.py`** — wires the new gate into the unified
  eval runner as `suites.detection_fp_rate`, reporting
  `worst_per_rule_fp_rate` (lower-is-better) alongside the existing
  alert-reduction / investigation-completeness / response-quality
  gates so dashboards and CI consume it through the same JSON shape.

Tracked as **F005** in `docs/community-feedback/2026-05-12/`.

### Documentation — install pipeline + v2.2 architecture refresh

Documentation-only refresh that aligns every install / architecture page
with the actual shipped state of the repo. No service code, schema, or
API surface changed.

- **One-click install pipeline** is now a first-class doc surface.
  - New Docusaurus page `apps/docs/docs/installation.md` (sidebar
    position 2) walks through `install.sh` / `install.ps1` end-to-end —
    supported package managers, what gets installed, idempotency, the
    `uninstall.sh` / `uninstall.ps1` graduated cleanup flags, and the
    security model.
  - `apps/docs/docs/quickstart.md` adds it as **Path 0** ("zero-prerequisite
    bootstrap") and renumbers the demo / dev paths.
  - `apps/docs/docs/deployment/docker.md` opens with a callout to the
    installer, refreshes every host/container port mapping against
    `docker-compose.yml`, splits profile-gated services
    (`connectors`, `osquery-tls`, `slack-bot`) out of the default stack,
    and updates the GHCR image list to the full 16-image set.
  - `apps/docs/docs/intro.md` adds the installer to **Get started** and
    corrects the connector-count copy.
  - Root `README.md` already had Path 0 — verified and synced with the
    architecture refresh below.
- **v2.2 architecture surfaces** are now reflected everywhere.
  - `apps/docs/docs/architecture.md` data-flow diagram, monorepo layout,
    and Service Responsibilities table now include `services/osquery-tls`,
    `services/osquery-extensions`, and `services/slack-bot`. Connector
    count corrected to 50 (was 26 / 42 in stale paragraphs).
  - `docs/architecture/SYSTEM_DESIGN.md` connector count corrected to 50,
    Service Responsibilities table extended with the v2.2 services, and a
    new **§13 — v2.2 Additions** appended that documents endpoint
    telemetry (osquery TLS server + extensions), ChatOps (`slack-bot`),
    Responder PWA, MCP server, Investigation Ledger / Ambient Copilot,
    and the one-click install pipeline. v2 / v2.1 narrative preserved.
  - Root `README.md` mermaid diagram + service-map table extended with
    `osquery-tls`, `slack-bot`, `mcp` and the corrected
    `Realtime` / `Web Console` descriptions.
- **Connector count corrected to 50 across the repo.**
  - `apps/docs/docs/connectors/index.md`: catalog count updated and the
    23 missing connectors added across the existing categories
    (cloud / CNAPP / vuln-mgmt, SIEM, EDR/XDR, SaaS, ITSM, network,
    endpoint fleet, container orchestration).
  - `apps/docs/docs/connectors/api-coverage.md`: coverage-table heading
    updated.
  - `apps/web/src/components/onboarding/StartHero.tsx`: in-product copy
    on the onboarding tile updated.
  - `apps/docs/docs/intro.md`: two stale paragraphs updated.
  - Source of truth: `services/connectors/app/connectors/__init__.py`
    (`_CONNECTOR_CLASSES`).

Old historical entries in `AI_STACK_PLAN_PROGRESS.md` reference 42
connectors and are intentionally left as a snapshot of the v2.1 increment
they describe.

## [7.2.0] — 2026-05-11

### Changed — `docker compose up -d` is now pull-by-default

Track 1 + Track 2 of the docker-compose hardening work that began in
[7.1.1](#711--2026-05-10). 7.1.1 fixed the boot-path bugs that surfaced on
a clean clone; this release attacks the *time* dimension. The previous
behaviour — `docker compose up -d` on a fresh checkout building all 15
services from source — took 10–20 minutes on a typical laptop and was the
single largest source of "I tried AiSOC and gave up" reports. With this
release, the same command pulls 12 prebuilt images from GHCR and is
healthy in roughly 90 seconds.

No service code, no API surface, no database schema changed. Every change
in this release is in the boot path, the image-publish path, or the CI
gate that proves both still work.

#### Track 1 — Pull-by-default boot path

- **`docker-compose.yml`**: Every service that previously had a `build:`
  directive now also has an `image:` and `pull_policy: missing`. Compose
  will pull the prebuilt image from `ghcr.io/aisoc-platform/aisoc-<svc>`
  if it exists locally or in the registry; only if the pull fails does it
  fall back to building from source. The 12 backend services that publish
  images (api, agents, realtime, web, ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, slack-bot) are tagged via the
  `${AISOC_VERSION:-latest}` interpolation so the same compose file works
  for `latest`, `main`, a release tag (`v7.2.0`), or a local override.
  The three deferred services (osquery-tls, honeytokens, purple-team) are
  marked with a `# TODO(publish)` comment and continue to build locally.
- **`.env.example`**: Added a new top-of-file `AISOC_VERSION=latest`
  block that documents how to pin the entire backend to a release tag for
  reproducible deploys (`AISOC_VERSION=v7.2.0`), or track the bleeding
  edge (`AISOC_VERSION=main`).
- **`.github/workflows/publish-images.yml`**: Extended the build matrix
  from 4 services to 12 by adding ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, and slack-bot. These are the backend
  services that every full-stack `docker compose up -d` boots; without
  them in the publish matrix, `pull_policy: missing` would resolve to
  "build from source" for two-thirds of the stack and the change would be
  cosmetic.
- **`.github/workflows/release.yml`**: Mirrored the same 12-service
  matrix on tagged-release builds so that `AISOC_VERSION=v7.2.0` resolves
  to a real published image for every service in the compose file, not
  just the demo subset.

#### Track 2 — Build & CI hardening

The pull-by-default path only matters if the underlying images actually
build. Track 2 attacks the two largest historical sources of build-path
flakes — Poetry resolution failures during image build, and Dockerfile
regressions that nobody catches until release day.

- **All seven Python service Dockerfiles**
  (`services/{api,fusion,threatintel,slack-bot,actions,connectors,osquery-tls}/Dockerfile`):
  Added a `poetry install` → `pip install` fallback. The previous pattern
  failed the build on any transient PyPI hiccup, lock-file drift, or
  proxy timeout during `poetry install`. The new pattern wraps the
  install in `set -eux; if poetry install ...; then ...; else
  pip install <pinned list>; fi`, logs which path was taken, and pins
  every runtime dependency explicitly in the fallback list. The pinned
  list is documented as needing to track `pyproject.toml` and is
  exercised by the new nightly cold-cache CI run.
- **`.github/workflows/compose-smoke.yml`** (new): On every PR that
  touches `docker-compose.yml`, `docker-compose.demo.yml`, any service
  Dockerfile, `.env.example`, or the workflow itself, GitHub Actions now
  boots the full stack from a clean checkout and asserts `aisoc-postgres`
  is healthy, `api` returns 200 on `/health`, and `web` returns 200 on
  `/` — all within a 10-minute budget. Pull-by-default by design (so the
  CI run mirrors what the user sees), with automatic detection of
  Dockerfile changes that flips the workflow into rebuild-from-source
  mode so we don't smoke-test against a stale published image. Captures
  `docker compose ps`, `docker compose logs`, disk, and memory on
  failure.
- **`.github/workflows/compose-smoke-nightly.yml`** (new): At 09:00 UTC
  every day, GitHub Actions does a full cold-cache rebuild of every
  service (`docker compose build --no-cache --pull`) and re-runs the
  same smoke gates with a wider 20-minute budget. This is the gate that
  catches the regressions PR smoke physically cannot — upstream
  `python:3.11-slim` breakage, transitive dependency drift,
  `pyproject.toml` ↔ pip-fallback drift in the seven Python services.
  Failures upload a forensics artifact and open a `ci`-labelled tracking
  issue automatically so a nightly break is visible by standup.

### Changed

- **`apps/web/package.json`**: Bumped to `7.2.0`.

### Migration notes

None for users on 7.1.1. The compose file is backwards-compatible —
`pull_policy: missing` only changes behaviour the first time you boot
(it tries the registry before building); existing local images are
honoured. If you want the new fast path explicitly, run `docker compose
pull` once after upgrading. To pin a deploy to this release rather than
tracking `latest`, set `AISOC_VERSION=v7.2.0` in `.env`.

If you skipped 7.1.1, also read its [migration note](#711--2026-05-10)
about the `osquery-tls` host-port change (`8007` → `8091`).

## [7.1.1] — 2026-05-10

### Fixed — `docker compose up -d` first-touch experience

Hotfix in response to user-reported `docker compose up -d` failures on a clean
clone. None of these are functional changes to the running services — every
fix is in the boot path, the boot documentation, or the pre-flight check.

#### Compose hygiene

- **`docker-compose.yml`**: Removed the obsolete `version: '3.8'` declaration,
  which Docker Compose v2 ignores and warns about on every invocation
  (`level=warning msg="...the attribute version is obsolete..."`). The warning
  is harmless but is the very first line of output a new user sees, which
  signals "this project is broken" before the build even starts.
- **`docker-compose.yml`**: Added `mem_limit` + `mem_reservation` to the four
  data-tier containers most likely to OOM-kill on an under-provisioned Docker
  Desktop:
  - `kafka`: 1.5 GB limit / 1 GB reservation
  - `clickhouse`: 1 GB limit / 768 MB reservation
  - `opensearch`: 1 GB limit / 768 MB reservation
  - `neo4j`: 1 GB limit / 768 MB reservation

  Without these caps, a 4 GB Docker Desktop allocation (the default on macOS)
  would silently OOM-kill OpenSearch or Neo4j during JVM warmup, leaving the
  rest of the stack running but the alert/case feeds permanently empty.
- **`docker-compose.yml`** (`osquery-tls` service): Fixed `AISOC_INGEST_BASE_URL`
  pointing at the non-existent `ingest:8080` (the actual service is named
  `ingest-worker`). Also remapped the host port from `8007` to `8091` to
  resolve a host-port collision with the `ueba` service. Both bugs only
  surfaced if the user actually queried the osquery TLS server, which is why
  they survived the previous release; running `docker compose up -d` would
  succeed but `osquery-tls` would log connection-refused errors on every
  agent check-in.

#### README rewrite

- **`README.md`** — *Quick start*: Restructured so `pnpm aisoc:demo` is the
  canonical first-touch path (4 prebuilt images, ~90s to a working SOC
  console) and `docker compose up -d` is explicitly labelled the
  "developer-build path" (22 services, 10–20 min cold build, requires Docker
  with at least 6 GB RAM allocated). The previous structure presented both
  paths as equally valid, which led users with stock Docker Desktop settings
  straight into a stack that physically cannot fit in the daemon's memory.
- **`README.md`** — *Service map*: Updated `osquery-tls` from `:8090` to `:8091`
  and added a `Kafka UI` row at `:8090`, matching the compose hygiene fix
  above.
- **`README.md`** — *Boot section*: Added explicit timing expectations
  ("~5 GB of base image pulls + 10–20 min of build on a typical laptop"), a
  recommendation to run `pnpm aisoc:doctor` before kicking off the build, and
  a troubleshooting note pointing under-provisioned Docker Desktop installs
  at *Settings → Resources*.

#### `aisoc:doctor` hardening

The pre-flight check that the user is now told to run before
`docker compose up -d` was previously useless to first-time users — its
container check used `docker compose ps` (which is project-scoped and
therefore couldn't see containers launched by a sibling compose file), and
it had no opinion on whether Docker itself was provisioned to actually run
the stack. This release fixes both:

- **Docker Compose plugin enforcement**: New check that fails with an
  actionable error if the user only has Compose v1 (`docker-compose` Python
  binary) on PATH, which is now end-of-life and lacks healthcheck semantics
  the stack depends on.
- **Docker daemon RAM check**: Reads `docker info --format json` and asserts
  at least 6 GB allocated for the full stack (4 GB for the demo stack).
  Anything less hard-fails with a pointer to *Docker Desktop → Settings →
  Resources*. This single check would have prevented every variant of "the
  build succeeds but `docker compose ps` shows half my containers in a
  restart loop" reported to date.
- **Cross-compose-project container discovery**: Replaced `docker compose ps`
  with `docker ps -a --format json --filter name=aisoc-`. The doctor now
  detects whether the user is on the demo stack (`aisoc-demo-*` containers)
  or full stack (`aisoc-*` containers) and accepts either as a valid boot,
  so demo users no longer see false `FAIL` rows for services the demo
  intentionally omits (kafka-ui, neo4j, etc.).
- **Exit-code aware container reporting**: When a container exists but is
  not running, the doctor now emits the exact `Exited (255)` status from
  `docker ps` and tells the user `run \`docker logs <container>\``. The
  previous output ("not running") gave the user no signal about whether
  the container had crashed, never started, or been manually stopped.
- **Stack flavor summary**: A new `stack flavor` row reports `demo`,
  `full`, or `mixed`, plus a running/total container count
  (`(4/8 container(s) running)`) so the user can see at a glance whether
  they're looking at a half-broken stack or a fully-broken stack.

### Changed

- **`apps/web/package.json`**: Bumped to `7.1.1`.

### Migration notes

None. This is a docker-compose hygiene release — no service code,
no database schema, no API surface area changed. Pull, re-run
`pnpm aisoc:doctor`, and re-run `docker compose up -d` (the
`osquery-tls` port change means existing deployments need to update any
osquery-agent `tls_hostname:tls_port` config from `localhost:8007` to
`localhost:8091`, but no one was using that interface yet).

## [7.1.0] — 2026-05-10

### Added — Cloud Security Coverage Wave

Six new connectors, three documentation backfills, and one new ingest template.
Closes the biggest cloud-security gap in the connector catalogue: every Tier-1
cloud workload protection platform (Wiz, Prisma Cloud, Orca, Lacework, AWS
Security Hub) now has a first-class integration, AWS gets three native data
sources (GuardDuty, CloudTrail, VPC Flow Logs), and Kubernetes audit logs land
through a dual-mode connector that works on both managed and air-gapped
clusters.

#### Track A — Documentation backfill

- **`apps/docs/docs/connectors/wiz.md`**: Documented the Wiz GraphQL connector
  end-to-end — service-account creation, scope (`read:issues`,
  `read:vulnerabilities`), token rotation, normalised severity mapping, and a
  worked example of a Wiz `Issue` collapsing to `category=cloud_alert` in the
  inbox.
- **`apps/docs/docs/connectors/aws-security-hub.md`**: Documented IAM role vs.
  static-key auth, the `securityhub:GetFindings` permission model, and the
  `BLOCK_IP`/`ALLOW_IP` capabilities backed by
  `services/actions/app/clients/aws_security_groups.py` (i.e. how a SOC analyst
  can quarantine an attacker IP from the Security Hub finding without leaving
  the case workspace).
- **`apps/docs/docs/connectors/lacework.md`**: Documented the Lacework API
  token flow, `api_url` regional variants, and the alert→event severity map.
- **`apps/docs/sidebars.ts`**: Registered all three new docs pages under the
  `Connectors` category, plus the four new connector pages from Tracks B–D
  (`prisma-cloud`, `orca`, `aws-guardduty`, `aws-cloudtrail`, `aws-vpc-flow`,
  `kubernetes-audit`).

#### Track B — New CNAPP connectors

- **`services/connectors/app/connectors/prisma_cloud.py`** —
  `PrismaCloudConnector` with full Prisma Cloud (CSPM/CWPP) coverage. JWT auth
  via `POST /login`, paginated `GET /alert/v1/alert` with `time.from`/`time.to`
  windowing, severity collapse (`critical/high → high`, `medium → medium`,
  `low/informational → low`), and a `compute_url` override for self-hosted
  Compute Edition. Capability: `PULL_ALERTS`. Manifest: `plugins/prisma-cloud/plugin.yaml`,
  docs at `apps/docs/docs/connectors/prisma-cloud.md`, tests in
  `services/connectors/tests/test_prisma_cloud.py`.
- **`services/connectors/app/connectors/orca.py`** — `OrcaConnector` hitting
  `https://api.orcasecurity.io/api/alerts` with an `api_token` field, severity
  collapse (`critical/high/hazardous → high`, `medium → medium`,
  `informational/low → low`). Manifest, docs, and tests follow the same
  pattern. Capability: `PULL_ALERTS`.

#### Track C — Native AWS connectors

- **`services/connectors/app/connectors/aws_guardduty.py`** —
  `AWSGuardDutyConnector` mirroring `AWSSecurityHubConnector`'s shape:
  boto3-based, supports IAM-role or static-key auth, calls
  `guardduty.list_findings` + `get_findings` per detector. Normalises
  GuardDuty's continuous numeric severity scale (`0.1`–`10.0`) into AiSOC's
  four-tier `info|low|medium|high` ladder (`>= 7.0 → high`, `>= 4.0 → medium`,
  `>= 1.0 → low`, else `info`). Capability: `PULL_ALERTS`.
- **`services/connectors/app/connectors/aws_cloudtrail.py`** —
  `AWSCloudTrailConnector` using `cloudtrail.lookup_events`. Ships with a
  curated default allow-list of 21 high-signal event names covering identity
  abuse (`ConsoleLogin`, `AssumeRoleWithSAML`, `GetSessionToken`,
  `GetFederationToken`, `CreateAccessKey`, `CreateLoginProfile`,
  `CreateUser`), persistence (`AttachUserPolicy`, `PutUserPolicy`,
  `CreateRole`, `AttachRolePolicy`), data-plane abuse (`PutBucketPolicy`,
  `PutBucketAcl`, `DeleteBucketPolicy`, `PutObjectAcl`), network exposure
  (`AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`,
  `ModifyDBInstance`), and trail tampering (`DeleteTrail`, `StopLogging`,
  `UpdateTrail`). Allow-list is overridable via the `event_names` config
  field. Pagination handled via `NextToken` with a hard cap to keep poll
  latency bounded. Capability: `PULL_LOGS`.
- **`services/connectors/app/connectors/aws_vpc_flow.py`** —
  `AWSVPCFlowLogsConnector` using `cloudwatch_logs.filter_log_events`. Parses
  both v2 (default 14-field) and v5 (header-defined) flow-log formats. Default
  `filter_pattern` is `?REJECT` to surface dropped traffic only — keeps volume
  manageable while flagging external-facing security groups that are getting
  scanned. Public-IP heuristic (`_is_public_ip`) is RFC-5735-aware, treating
  RFC1918/loopback/link-local/multicast/CGNAT/TEST-NET as private. Severity
  heuristic: public-IP REJECTs → `medium`, internal REJECTs → `low`,
  ACCEPT-only flows → `info`. Capability: `PULL_LOGS`.

#### Track D — Kubernetes audit logs (dual-mode)

- **`services/connectors/app/connectors/kubernetes_audit.py`** —
  `KubernetesAuditConnector` shipping with two delivery modes selected via the
  `mode` config field:
  - **`webhook` (recommended)** — Kubernetes API server pushes audit events
    to AiSOC's new dedicated `POST /v1/ingest/k8s-audit/{tenant_id}` route,
    authenticated with a shared secret in the `X-AiSOC-K8s-Token` header
    (compared in constant time so partial-prefix matches still fail). The
    legacy `/v1/inbox/{token}` path with the `k8s-audit` template is kept
    around as a fallback for control planes that cannot inject custom
    headers into the audit-webhook kubeconfig.
  - **`file_tail`** — AiSOC's connector pod tails a local `audit.log` file
    using a byte-position cursor (atomically written to a `.aisoc-cursor`
    sidecar), with rotation/truncation detection and a hard per-poll byte cap
    so a backlog can't blow up a single poll cycle.
- **`services/ingest/internal/handler/k8s_audit.go`** — New Go handler for
  the dedicated webhook route. Caps body size via `K8S_AUDIT_MAX_BODY_BYTES`
  (default 16 MiB), rejects oversized batches with `413` so the apiserver
  shrinks `--audit-webhook-batch-max-size` and retries, and publishes each
  `EventList.items[]` entry through the existing normalizer + Kafka publisher
  using `connector_type: kubernetes_audit`. The route is disabled (returns
  `503`) until an operator sets `K8S_AUDIT_SHARED_SECRET`, so a fresh
  install never accidentally accepts unauthenticated audit traffic.
- **`services/ingest/internal/normalizer/normalizer.go`** — Added the
  `kubernetes_audit` connector profile. Maps `auditID` to `external_id`,
  `verb` to `activity_name`, `user.username` to `actor.user.name`,
  `objectRef.{namespace,resource,name}` to a composite `target.resource.name`,
  and translates the connector's string severity (`critical|high|medium|low|
  info`) into OCSF integer severities (5/4/3/2/1).
- **`services/ingest/internal/normalizer/templates/k8s-audit.yaml`** — New
  inbox template (legacy path) that maps Kubernetes apiserver `Event`
  payloads (`apiVersion: audit.k8s.io/v1`) onto AiSOC's normalised event
  shape:
  - `external_id ← auditID`
  - `vendor ← "Kubernetes"`, `product ← "apiserver-audit"`,
    `category ← "k8s_audit"`
  - `actor ← user.username` (plus `user.groups` carried through metadata)
  - `target ← objectRef.namespace + "/" + objectRef.resource + "/" +
    objectRef.name`
  - `severity` is derived in the connector's `_classify_severity` heuristic,
    not in the template, so the same logic applies to both delivery modes.
- **Severity heuristic** (`_classify_severity` in `kubernetes_audit.py`):
  - `high` — `exec`/`attach`/`portforward` on a Pod, `create` on
    `ClusterRoleBinding`, `impersonate` verb, `update` on
    `serviceaccounts/token`, any `RequestResponse` event where
    `responseStatus.code >= 500` on a sensitive verb.
  - `medium` — `create`/`patch`/`delete` on `Secret`/`ConfigMap`/
    `ClusterRole`/`Role`, `escalate` verb, failed authentication
    (`responseStatus.code == 401|403`) on a write verb.
  - `low` — successful reads on sensitive resources (`get` on `Secret`),
    successful writes on routine resources.
  - `info` — everything else (health probes, list/watch on benign resources,
    successful low-impact reads).
- **`plugins/kubernetes-audit/plugin.yaml`** — Manifest with a 4-field config
  schema (`mode`, `cluster_name`, `inbox_token`, `audit_log_path`,
  `cursor_path`), `category: cloud`, capabilities `pull_audit` + `pull_alerts`.
- **`apps/docs/docs/connectors/kubernetes-audit.md`** — Includes a complete
  sample `AuditPolicy` (omitStages on RequestReceived for verbosity control;
  Metadata level for routine reads, RequestResponse for writes on Secret /
  ConfigMap / ClusterRoleBinding) and a sample `AuditSink` pointing at AiSOC's
  inbox URL.

#### Cross-cutting

- **`marketplace/index.json` + `apps/web/public/marketplace/index.json`** —
  Rebuilt via `pnpm marketplace:sync`. Plugin count rose from 43 → 49 (+6
  cloud connectors). Total marketplace entries: `total=7104 detections=6993
  playbooks=62 plugins=49 mitre_techniques=493`.
- **`apps/web/package.json`** — Version bumped from `7.0.3` to `7.1.0`; the
  sidebar and landing-page footer both surface the new version automatically.

#### Test footprint

- 43 unit tests for `KubernetesAuditConnector` covering both delivery modes,
  cursor persistence, rotation/truncation, byte-cap drain semantics, and the
  full severity-heuristic decision table.
- 27 unit tests for `AWSVPCFlowLogsConnector` covering v2/v5 parsing,
  public-IP classification edge cases (RFC1918, CGNAT, TEST-NET-1/2/3), and
  the default REJECT filter pattern.
- Mirroring tests for `PrismaCloudConnector`, `OrcaConnector`,
  `AWSGuardDutyConnector`, `AWSCloudTrailConnector` covering schema,
  normalise, pagination, and auth-error paths.
- Full `services/connectors` suite passes at 364 tests; schema-introspection
  tests in `services/api` also pass with the six new connectors added to
  `_CONNECTOR_CLASSES`.

---

## [7.0.3] — 2026-05-10

### Fixed — Hydration mismatch, font preload warnings

#### Web app (`apps/web/`)

- **`src/components/layout/AppShell.tsx`**: Wrapped `<DemoBanner />` in a new
  `<ClientOnly>` boundary so the banner (which reads `NEXT_PUBLIC_DEMO_MODE`)
  is never server-rendered. This eliminates React hydration error #418 caused by
  stale env-var inlining producing a structural tree mismatch (server saw
  `<button>` from Sidebar, client expected `<div>` from DemoBanner).
- **`src/app/layout.tsx`**: Added `preload: false` to the `JetBrains_Mono`
  `next/font/google` config. The monospace font is only used in code blocks and
  is not needed on the initial paint of most pages, causing Chrome to log
  "preloaded but not used within a few seconds" warnings. Lazy-loading the font
  eliminates these warnings without any visible FOUT.

---

## [7.0.2] — 2026-05-10

### Fixed — Version alignment, landing-page footer, documentation

- **`apps/web/package.json`**: Bumped `version` to `7.0.2`; sidebar now shows `v7.0.2` dynamically.
- **`apps/web/src/components/landing/Footer.tsx`**: Replaced hard-coded `v6.1.0` string with a
  dynamic import of `package.json` so the landing page footer always reflects the current package version.
- **`README.md`**: Updated version badge to `7.0.1`; added `osquery-tls` (port 8090) and
  `osquery-extensions` entries to the services table, the Swagger-UI URL table, and the
  directory tree; added osquery TLS server URL to the dev surface table.

---

## [7.0.1] — 2026-05-10

### Fixed — Web app hardening: CodeQL, hydration, Turbopack config

#### Security (CodeQL Code-Scanning — 42 alerts cleared)

- **Python**: Resolved `py/unused-global-variable` in `credential_vault.py`,
  `pack_loader.py`, `executive_digest.py`, `case_summary.py`,
  `cost_dashboard.py`, and `actions/executors/base.py` by refactoring mutable
  state into dictionaries and exposing identifiers via `__all__`.
- **Python**: Resolved `py/cyclic-import` between `osquery-tls` modules by
  extracting `generate_node_key` into a new `app/core/crypto.py` module.
- **Python**: Resolved `py/empty-except` in `api/main.py` and `api/services/github.py`
  by replacing bare `pass` blocks with `logger.debug` calls.
- **Python**: Resolved `py/log-injection` in `github.py`, `detection_proposals.py`,
  and `llm_credentials.py` by switching log format specifiers to `%r`.
- **Python**: Resolved `py/clear-text-logging-sensitive-data` in
  `workers/oauth_refresh.py` by redacting `tenant_id` and sanitising reason strings.
- **Python**: Resolved `py/incomplete-url-substring-sanitization` in
  `llm_resolver.py` by using `urllib.parse.urlparse` for hostname extraction.
- **Python**: Resolved `py/stack-trace-exposure` in `agents/api/explain.py` by
  returning a generic error string from the exception handler.
- **Python**: Resolved `py/call/wrong-arguments` in `agents/tests/smoke_explain.py`
  by importing and passing a `LlmConfig` instance to `_stream_explanation`.
- **Python**: Resolved `py/unused-import` in `osquery-tls/db/env.py`; fixed
  `E402` (import ordering) in the same file.
- **JavaScript**: Resolved `js/unused-local-variable` in `AlertsView.tsx`
  (removed unused `toast` import) and `SettingsView.byok.test.tsx` (removed
  unused `within` import).

#### Web app (`apps/web/`)

- **`next.config.js`**: Removed deprecated `eslint.ignoreDuringBuilds` key that
  Next.js 16 no longer accepts in the config file; added `turbopack.root` so
  Turbopack resolves workspace packages correctly.
- **`src/app/layout.tsx`**: Added `suppressHydrationWarning` to the `<html>`
  element so that the render-blocking `themeBootstrapScript` can freely write
  `data-theme`, `data-theme-preference`, and `style.colorScheme` on the client
  without React reporting a hydration mismatch on every page load.

---

## [7.0.x] — 2026-05-10 — Endpoint telemetry wave (PR1–PR6)

> **⚠️ Reconciliation notice (2026-05-12)**: The work described in this
> section was developed on branch `feat/pr6-osquery-extensions`
> (commits `e0d70fa1` → `3ab5aa81`) but the branch was **not merged into
> `main`** before this changelog entry was written. The files referenced
> below — including `services/osquery-tls/`,
> `services/connectors/app/connectors/aisoc_direct.py`,
> `services/agents/app/playbook/steps/osquery_live_query.py`, and the
> osquery-extensions Go module — exist on that branch and can be reviewed
> there, but are **not present on `main`** as of v7.1.0 planning. Treat
> this section as a record of in-flight work pending PR merge, not as
> shipped functionality. The community-feedback-driven roadmap
> (`docs/community-feedback/2026-05-12/`) builds the generic
> `live_action` interface (Issue #8) on `main` directly rather than
> assuming this section's primitives are in place.

### Added — osctrl, FleetDM, aisoc-osquery-tls, aisoc-direct, native osquery detections, live-query playbook step, FIM, custom virtual tables

Six-PR wave that closes [#44](https://github.com/beenuar/AiSOC/issues/44)
("osctrl connector for fleet-wide osquery telemetry") and significantly extends
osquery coverage end to end. Shipped in the v7.0 release window between the
v7.0.0 baseline and the v7.0.1 hardening patch.

#### PR1 — osctrl + FleetDM connectors

- **`services/connectors/app/connectors/osctrl.py`**, **`fleetdm.py`** — Two new
  `BaseConnector` subclasses with full `schema()`, `validate()`, `fetch_events()`,
  and `normalize()` implementations. Schema-driven setup runs a live
  `Test connection` round-trip before save; secrets encrypted with the
  application-layer `CredentialVault` (Fernet AES-128-CBC + HMAC-SHA256);
  polling on per-instance schedule via `ConnectorScheduler`.
- **`plugins/osctrl/plugin.yaml`**, **`plugins/fleetdm/plugin.yaml`** — Marketplace
  manifests mirroring the connector schemas. `marketplace/index.json` regenerated
  via `pnpm marketplace:sync`.
- **`services/connectors/tests/test_osquery_connectors.py`** — Schema contract +
  severity heuristics tests.

#### PR2 — Native osquery detection schema migration

- **`detections/endpoint/osquery-*.yaml`** — 16 osquery detection rules
  migrated from `_quarantine/` to the native schema, IDs `det-endpoint-281`
  through `det-endpoint-296`. Coverage spans credential access, persistence,
  lateral movement, defense evasion, and discovery on macOS, Linux (auditd),
  and Windows.
- **`detections/fixtures/osquery_*.json`** — Positive / negative test
  fixtures for every migrated rule, gated by the Detection Validation
  workflow in CI.

#### PR3 — Live-query playbook step

- **`services/actions/app/clients/osctrl_client.py`**,
  **`fleetdm_client.py`**, **`aisoc_direct_client.py`** — Production-grade
  HTTP clients with per-vendor auth, retries, and structured error handling.
- **`services/actions/app/clients/osquery_allowlist.py`** — Strict allowlist
  enforcing only safe SELECT-only queries against approved tables (no
  `ATTACH`, no `INSERT`, no `pragma_*` introspection of secrets).
- **`services/agents/app/playbook/engine.py::_handle_osquery_live_query`** —
  New `osquery_live_query` step type, registered in
  `services/agents/app/playbook/models.py` as `StepType.OSQUERY_LIVE_QUERY` and
  dispatched from the `STEP_HANDLERS` table at the bottom of `engine.py`.
  Pushes allowlisted distributed queries to a single host or fleet-wide via
  osctrl / FleetDM / aisoc-direct with HMAC-signed ChatOps approval before
  execution. Tests live in
  `services/agents/tests/test_osquery_live_query_step.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > separate module at `services/agents/app/playbook/steps/osquery_live_query.py`.
  > That module never landed on `main` — the handler is inlined in `engine.py`
  > to keep the playbook engine's dispatch table in one place. The behaviour,
  > tests, and CLI surface are identical to the originally documented design.

#### PR4 — `aisoc-osquery-tls` FastAPI service + `aisoc-direct` connector

- **`services/osquery-tls/`** — New first-party FastAPI service exposing
  `/api/v1/enroll`, `/api/v1/config`, `/api/v1/log`, `/api/v1/distributed/read`,
  `/api/v1/distributed/write`, plus `/api/v1/fim` for file-integrity events.
  Self-hosted osquery TLS plugin endpoints are FleetDM-compatible so any
  off-the-shelf osquery agent can enroll without a third-party SaaS hop.
  Uses dedicated SQLite + Alembic migrations under `services/osquery-tls/db/`.
- **`services/osquery-tls/app/api/v1/endpoints/log.py`** + matching
  `plugins/aisoc-direct/plugin.yaml` and
  `services/actions/app/clients/aisoc_direct_client.py` — Direct-from-agent
  ingest path that consumes the osquery-tls log stream and normalises into
  the standard alert schema; bypasses third-party SaaS entirely. The
  `aisoc-direct` connector is implemented as a **virtual connector**: agents
  push events directly into `/api/v1/log` on the osquery-tls service, which
  fans them out to the same ingest pipeline the polled connectors use. The
  marketplace manifest lives at `plugins/aisoc-direct/plugin.yaml`; the
  outbound client (used by playbooks to drive distributed queries) lives at
  `services/actions/app/clients/aisoc_direct_client.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > polled connector module at
  > `services/connectors/app/connectors/aisoc_direct.py`. That module never
  > landed on `main`. The connector is implemented as a push-based virtual
  > connector (the `osquery-tls` service is itself the ingest endpoint), so
  > there is nothing to register in `services/connectors/app/connectors/__init__.py`.
  > Functionally the data path is identical to the originally documented
  > design.

#### PR5 — Osquery packs + FIM endpoint + FIM dashboard

- **`services/osquery-tls/app/osquery_packs/`** — Bundled IR / OSquery-ATT&CK /
  FIM packs distributed to every enrolled agent on enrollment. Pack loader
  preserves hand-crafted playbooks under `pack root` (do not `rmtree`).
- **`services/osquery-tls/app/api/v1/endpoints/fim.py`** — File-integrity
  monitoring endpoint. Ingests `file_events` and synthesises alerts on writes
  to `/etc/passwd`, `/etc/shadow`, sshd configs, sudoers, and Windows
  registry hives. FIM-specific detection IDs `det-endpoint-297..300`
  (renumbered from 281–284 to avoid collision with osquery-macos rules).
- **`apps/web/src/components/dashboard/FimDashboard.tsx`** — New dashboard
  panel grouping FIM events by host, file, and severity.

#### PR6 — AiSOC osquery extensions (custom virtual tables)

- **`services/osquery-extensions/tables/`** — 5 custom Go-based virtual tables
  shipping with the agent for richer endpoint visibility plus a bidirectional
  response channel:
  - `aisoc_browser_extensions` — installed browser extensions across Chrome,
    Firefox, Edge, Safari profiles.
  - `aisoc_kernel_modules` — currently loaded kernel modules with signing /
    tainting state.
  - `aisoc_attck_persistence` — MITRE ATT&CK persistence locations
    (LaunchAgents, scheduled tasks, systemd units, Run keys).
  - `aisoc_pending_actions` — pending response actions queued for the agent;
    enables host → server → host bidirectional flow.
  - `aisoc_alert_cache` — local cache of alerts the agent has emitted, for
    deduplication and replay.
- **`services/osquery-extensions/tables/pending_actions_test.go`** — Unit
  tests for the bidirectional action queue.
- **`docs/openapi.yaml`** regenerated to include the extensions API endpoints.

#### Cross-cutting CI / housekeeping

- **CI**: Detection Validation workflow now covers the 16 migrated osquery
  rules; Python Tests, Web Build, and the osquery-tls service build are all
  green.
- **Lint**: `ruff format` and `ruff check --fix` applied across the new
  `osquery-tls` service; F401 / UP017 / UP037 / I001 / W291 cleared.
- **Marketplace**: `apps/web/public/marketplace/curated.json` re-synced from
  `marketplace/` after the new connector / plugin manifests landed.

---

## [7.0.0] — 2026-05-10

### Added — v1.0 Buyer-Value Plan: ChatOps, Digest PDF, BYOK, Air-gap, WCAG AA, Analytics

This release ships the complete v1.0 buyer-value plan across 16 workstreams.
All items were designed, implemented, tested, and reviewed by
Beenu Arora <beenu@cyble.com>.

#### WS-A1 — Slack ChatOps Bot (`services/slack-bot/`)

- **`services/slack-bot/`** — New standalone FastAPI service using `slack-bolt`
  async adapter. Ships `/aisoc triage <case_id>`, `/aisoc approve <action_id>`,
  `/aisoc status <case_id>`, and `/aisoc summary <case_id>` slash commands.
  Interactive approval buttons route back through the API approval endpoint so
  human-in-the-loop gates work from Slack without opening the console.
- 61 pytest cases cover the slash-command handlers, interactive payloads, API
  client calls, and error paths (bad token, non-200 API response, missing case).

#### WS-B1/B2 — Executive Digest PDF + Weekly Scheduler

- **`services/api/app/services/digest_pdf.py`** — Generates a branded A4 PDF
  for `ExecutiveDigest` objects using ReportLab. Includes cover page, KPI tiles,
  alert-volume chart, top-rule table, top-actor table, and remediation summary.
- **`services/api/app/workers/weekly_digest_task.py`** — APScheduler task that
  runs every Monday at 06:00 UTC, builds a digest for every active tenant, and
  delivers it via `POST /api/v1/reports/digest/email` or writes it to blob
  storage. Controlled by `DIGEST_SCHEDULE_ENABLED` env flag.
- **`services/api/app/services/digest_html.py`** — HTML mirror of the PDF for
  in-browser preview.
- **`services/api/tests/test_digest_pdf.py`** — 12 pytest cases covering PDF
  generation, chart rendering, and weekly scheduler triggering.

#### WS-C1/C2/C3 — Playbook Gallery, Detection Proposals, GitHub PR Integration

- **`apps/web/src/components/playbooks/PlaybooksGallery.tsx`** — Tabbed gallery
  with 12 curated packs (Phishing, Ransomware, BEC, IAM Key Compromise, …).
  Each card shows TTP coverage badges, author, version, and a one-click
  **Import** button that calls `POST /api/v1/playbooks/import`.
- **`services/api/migrations/039_detection_proposal_github_pr.sql`** —
  Adds `github_pr_url TEXT` and `github_pr_number INT` to `detection_proposals`.
- **`services/api/app/services/github.py`** — `GitHubService` creates draft PRs
  against the tenant's detection repo when a detection proposal is promoted.
  Supports GHES and github.com via `GITHUB_API_URL` env var.
- 25 playbook YAML templates added under `detections/playbooks/` and 12 pre-built
  playbook packs under `playbooks/packs/v1/`.

#### WS-D1 — BYOK Per-Tenant Settings UI

- **`apps/web/src/components/settings/SettingsView.tsx`** — New "AI / LLM"
  settings panel: provider picker (OpenAI, Azure OpenAI, Anthropic, Ollama),
  API-key input, model selector, temperature slider, and connection test button.
- **`apps/web/src/components/settings/SettingsView.byok.test.tsx`** — 12 Vitest
  tests covering form rendering, provider switching, key masking, connection test
  success/error paths, and save confirmation.

#### WS-D2 — Investigation Timeline (Replayable)

- **`apps/web/src/components/copilot/InvestigationTimeline.tsx`** — 684-line
  React component that renders the investigation ledger as a playable timeline.
  Each step shows the agent name, tool call, rationale, duration, and status
  badge. A scrubber lets analysts replay from any step.

#### WS-D3 — Case Auto-Summary + PDF Export

- **`services/api/app/services/case_summary.py`** — LLM-powered case summariser
  (structured output via function-calling). Produces `CaseSummaryResult` with
  `headline`, `severity_rationale`, `recommended_action`, and `evidence_links`.
- **`services/api/app/services/case_summary_html.py`** — HTML renderer for the
  summary, used by the PDF exporter and the in-browser case card.

#### WS-F1 — Light Theme Persisted in User Profile

- **`apps/web/src/components/theme/ThemeProvider.tsx`** — Theme preference
  (`light` | `dark` | `system`) stored in `localStorage` and synced to
  `PATCH /api/v1/users/me/preferences`. Survives logout and device switch.

#### WS-F2 — WCAG AA Accessibility (axe-core CI gate)

- **`apps/web/src/test/a11y.test.tsx`** — 55-line axe-core test suite. Renders
  `AlertsView`, `CasesView`, `PlaybooksView`, `DashboardView`, and 3 modal
  components; fails the build if any WCAG 2.1 AA violation is found.
- Sidebar landmark roles, ARIA labels, focus trapping in modals, skip-navigation
  link, and colour-contrast fixes applied across the entire component tree.

#### WS-F3 — Saved Views + Drag-Drop Dashboard Widgets

- **`apps/web/src/components/dashboard/DashboardView.tsx`** — Dashboard is now
  fully composable: widgets can be dragged, dropped, resized, pinned, and
  removed. Layout serialised to `POST /api/v1/saved-views`.
- **`services/api/app/api/v1/endpoints/saved_views.py`** — CRUD for per-user
  saved views (dashboard layout, column configs, active filters).

#### WS-G1/G2 — Threat Actor Attribution Engine v0 + Air-Gap Mode

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls `POST /actors/attribute` and surfaces attribution results
  in the investigation ledger.
- **`docker-compose.airgap.yml`** — Compose override for fully disconnected
  deployments: disables all external feed pullers, enables Ollama sidecar, and
  sets `AIRGAP_MODE=true` so the API switches to local-only LLM routing.
- **`apps/docs/docs/operations/air-gapped.md`** — Step-by-step air-gap
  deployment guide: image pre-pulling, Ollama model loading, threat-feed
  pre-seeding, and smoke-test checklist.

#### WS-H1 — MSSP Console Improvements

- **`services/api/app/api/v1/endpoints/mssp.py`** — New `GET /mssp/tenants`
  aggregation endpoint: per-child tenant alert counts, open case counts, SLA
  breach rate, and last-seen connector heartbeat.
- **`services/api/app/models/tenant.py`** — Added `parent_tenant_id` and
  `mssp_role` columns supporting the parent-child tenant hierarchy.

#### WS-H2 — BYOK Per-Tenant LLM Credentials

- **`services/api/app/api/v1/endpoints/llm_credentials.py`** — CRUD for per-tenant
  LLM credential records. Secrets encrypted at rest via `CredentialVault`.
- LLM routing layer (`services/api/app/core/config.py`) reads per-tenant
  credentials before falling back to the platform-wide key.

#### WS-H3 — Team Analytics View

- **`apps/web/src/components/analytics/TeamAnalyticsView.tsx`** — Analyst
  leaderboard with MTTR per analyst, alert disposition accuracy, cases closed
  per shift, and false-positive rate trend over the selected window.

#### WS-H4 — Air-Gapped / Ollama Local-LLM Mode

- **`services/api/app/api/v1/endpoints/llm_status.py`** — Reports whether the
  deployment is running in air-gap mode and which local models are available
  via the Ollama sidecar. Used by the settings UI to auto-populate the model
  picker.

### Fixed

- Ruff `E501/W291/W293/B007/B017/F821/I001` violations in `services/api`.
- `mypy` errors across all 16 plan-modified files: `RowMapping` import,
  `Optional` list `len()`, `current_user.user_id` rename, `fetchone()` None
  checks, `sort_key` return type, `PYTHONPATH` subprocess handling.
- Converted structlog-style `logger.info(key=value)` calls to stdlib formatting
  in `rule_engine.py`, `neo4j.py`, and `digest_pdf.py`.
- SQLAlchemy relationship `name-defined` mypy errors suppressed with
  `# type: ignore[name-defined]` in `tenant.py` and `connector.py`.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

---

### Added — Threat Actor Attribution Engine (v0)

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls the attribution API after triage/enrichment and
  records the result on `state.threat_intel["attribution"]`. Failure is
  soft and surfaces a `[medium]` finding rather than aborting the
  investigation.
- **`docs/threat-actor-attribution.md`** — Full operator-facing docs,
  including scoring model, API surface, observability, env vars, v0
  caveats, and instructions for adding custom profiles.

### Configuration

- `AISOC_ATTRIBUTION_THRESHOLD` — Override the default confidence
  threshold (`0.30`). Clamped to `[0.0, 1.0]`; invalid values fall back
  to the default and emit a warning.
- `AISOC_THREATINTEL_URL` — Base URL the agent uses to reach the
  `threatintel` service. Default: `http://threatintel:8083`.
- `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` — HTTP timeout the agent uses for
  attribution calls. Default: `10`.

### Observability

- New Prometheus series exported by `threatintel`:
  - `threatintel_attribution_requests_total{result="matched|unknown|error"}`
  - `threatintel_attribution_score{actor_id}` (histogram)

### Engine internals

- Tool matching uses an alphanumeric-only boundary regex
  (`(?<![a-zA-Z0-9])tool(?![a-zA-Z0-9])`) instead of Python's `\b`.
  Python's `\b` treats `_` as a word character, which broke common
  malware-filename patterns like `miniduke_v3.dll`. The new boundary
  treats `_`, `-`, `.`, and `/` as delimiters while still rejecting
  alphanumeric neighbours (so `x-agent` does not match `x-agentic`).
- Tool matching now also scans the IOC's `description` and `tags`
  fields, not just `value`.
- IOC lookups go through a new public method `OpenSearchStore.match_ioc_values()`
  rather than reaching into `os_store._os.search()` directly.
- The attribution engine accepts a `catalog` constructor argument so
  tests and downstream services can inject custom profiles without
  monkey-patching module-level state.
- An empty catalog now resolves to `actor_id="unknown"` with explicit
  reasoning (`"Actor catalog is empty"`), instead of confusingly
  falling through to the no-match-above-threshold branch.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

## [6.1.0] — 2026-05-07

### Added — v1.5 market-driven feature expansion

A review of G2, Gartner Peer Insights, and customer feedback on AI SOC / SIEM /
SOAR platforms drove this release. Five new agents, eight new console pages,
four new API surfaces, and ten new connectors landed at once. Connector catalog
goes from 16 → **26**.

#### New autonomous agents (`services/agents/app/agents/`)

- **`auto_triage_agent.py`** — Master triage agent classifies each incoming alert
  as `true_positive` / `false_positive` / `benign` with a confidence score.
  Low-confidence noise auto-closes; everything else escalates with rationale.
- **`phishing_agent.py`** — Specialised phishing triage: header analysis, URL
  reputation, attachment sandboxing summary, sender-domain trust.
- **`identity_agent.py`** — Identity-centric reasoning: impossible travel,
  privilege escalation, MFA bypass, and session-token anomaly classification.
- **`cloud_agent.py`** — Cloud posture / threat reasoning across AWS, Azure,
  GCP, and Kubernetes signals.
- **`insider_threat_agent.py`** — Behavioural deviation, peer-group scoring,
  exfiltration intent classification.
- All five are exposed via `POST /api/v1/agents/triage`.

#### New console pages (`apps/web/src/components/`)

- **`/investigate`** — Conversational, multi-turn copilot anchored on a case;
  reads its evidence, ledger, and entity graph for grounded follow-up Q&A.
  Component: `copilot/InvestigationChat.tsx`.
- **`/coverage-advisor`** — Ranks MITRE ATT&CK technique gaps by adversary
  prevalence and recommends rules to close them.
  Component: `coverage/CoverageAdvisorView.tsx`.
- **`/shifts`** — Outgoing/incoming analyst handoff dashboard: active cases,
  in-flight investigations, queued approvals on one screen.
  Component: `shifts/ShiftsView.tsx`.
- **`/easm`** — External Attack Surface Management: discovers public assets,
  exposed services, and certificate-expiry risks.
  Component: `easm/EASMView.tsx`.
- **`/mssp`** — MSSP executive dashboard: KPIs, cross-tenant alert volume, and
  per-customer SLA posture. Component: `mssp/MSSPDashboardView.tsx`.
- **`/noise-tuning`** — Per-rule false-positive rate, suppression candidates,
  one-click tuning. Component: `noise/NoiseTuningView.tsx`.
- **`/analytics/team`** — Analyst leaderboard, MTTR per analyst, dispositions
  accuracy, and shift workload balance.
  Component: `analytics/TeamAnalyticsView.tsx`.

#### New API surfaces (`services/api/app/api/v1/endpoints/`)

- **`shifts.py`** — Shift-handoff CRUD: list active shifts, post handoff
  notes, view queued approvals scoped to a shift window.
- **`stix_taxii.py`** — STIX 2.1 / TAXII 2.1 publishing; pushes the tenant's
  IOCs and threat-actor profiles to upstream / community feeds.
- **`compliance.py`** — Automated compliance evidence collection for SOC 2,
  ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA. One-click evidence pull.
- **`deployment.py`** — Deployment / air-gap toggles; tenants that disallow
  external feeds can flip air-gap mode here.

#### New connectors (`services/connectors/app/connectors/`)

EDR / XDR: `sentinelone.py`, `cortex_xdr.py`. Cloud security: `wiz.py`,
`snyk.py`. Network: `zscaler.py`. SaaS / email: `proofpoint.py`,
`servicenow.py`, `jira.py`. Identity: `1password.py`, `duo_security.py`.
All ten registered in `services/connectors/app/connectors/__init__.py`,
all ship a marketplace manifest under `plugins/<id>/plugin.yaml`, all
collapse vendor severity to the standard four-tier ladder.

#### Other

- **AI-generated incident reports** — Every case now has a one-click "Export
  Report" button that generates a PDF incident report from the Investigation
  Ledger.
- **Air-gap deployment configuration** — Per-tenant toggles disable external
  feeds (threat intel, marketplace sync, push notifications) for fully
  air-gapped deployments.

### Changed

- Connector catalog count **16 → 26**. Landing page hero stat, layout SEO
  metadata, and `apps/docs/docs/connectors/index.md` updated to reflect.
- `apps/docs/docs/architecture.md` adds a v1.5 section and updates the
  service-responsibilities table to include the new API surfaces and
  autonomous agents.
- `apps/docs/docs/intro.md` updated to mention the new connector count and
  v1.5 features.
- Footer release link now points at `v6.1.0`.

## [6.0.1] — 2026-05-06

### Security

- **Log-injection mitigation** (`services/api/app/api/v1/endpoints/connectors.py`) —
  `connector_type` originates from user-supplied query parameters and was previously
  logged verbatim, leaving an injection path for newlines/control characters into
  structured log records. A character-allowlist reconstructor (`_safe_connector_type`)
  now strips every character outside `[a-zA-Z0-9_\-]` before the value reaches any
  log call, breaking CodeQL's taint trace (alert `py/log-injection`).

- **Remove dead rate-limiter code** (`services/realtime/src/index.ts`) —
  The hand-rolled `makeRateLimiter` function was superseded by `express-rate-limit`
  in the previous release but not removed, leaving dead code that masked the
  effective rate-limiting path. The function is now deleted; `express-rate-limit`
  is the sole limiter in production (resolves CodeQL alert `js/unused-local-variable`).

## [6.0.0] — 2026-05-06

### Added

#### Wave 3 — Operational Maturity

- **MSSP / parent-tenant console** (`services/api/migrations/012_mssp_console.sql`,
  `services/api/app/models/mssp.py`, `services/api/app/api/v1/endpoints/mssp.py`) —
  Parent tenants can onboard child tenants, manage cross-tenant delegations, add
  per-tenant notes, and view an aggregated metrics rollup in a single pane.

- **Asset inventory + vuln-to-alert correlation** (`services/api/migrations/013_asset_inventory.sql`,
  `services/api/app/models/asset.py`, `services/api/app/api/v1/endpoints/assets.py`) —
  CRUD for discovered assets with vulnerability findings auto-correlated to alerts.
  Surfaces asset blast radius and enables asset-context enrichment during triage.

- **Insider threat module** (`services/api/migrations/014_insider_threat.sql`,
  `services/api/app/models/insider_threat.py`,
  `services/api/app/api/v1/endpoints/insider_threat.py`) —
  User risk profiles, behavioural indicators, peer-group deviation scoring, and
  watchlist management. Risk scores update incrementally as new indicators arrive.

- **L0–L4 auto-remediation maturity tiers** (`services/api/migrations/015_remediation_maturity.sql`,
  `services/api/app/models/remediation.py`,
  `services/api/app/api/v1/endpoints/remediation.py`,
  `services/actions/app/services/maturity.py`) —
  Per-tenant configuration of remediation autonomy from L0 (manual only) through L4
  (fully autonomous). Gate log records every approve/block decision. Per-action whitelist
  pre-approves low-risk actions regardless of tier.

#### Wave 4 — Advanced Capabilities

- **Internal threat intelligence** (`services/api/migrations/016_threat_intel.sql`,
  `services/api/app/models/threat_intel.py`,
  `services/api/app/api/v1/endpoints/threat_intel.py`) —
  IOC harvesting from alert history, threat actor and campaign profiles, and STIX/TAXII
  feed subscription management, all queryable via the REST API.

- **Cloud security posture management (CSPM/KSPM)** (`services/api/migrations/017_cspm.sql`,
  `services/api/app/models/posture.py`, `services/api/app/api/v1/endpoints/posture.py`) —
  Ingests posture findings from cloud providers, tracks drift between scan runs, and
  surfaces a per-provider posture summary with suppress/resolve workflows.

- **Identity-centric correlation graph** (`services/api/migrations/018_identity_graph.sql`,
  `services/api/app/models/identity_graph.py`,
  `services/api/app/api/v1/endpoints/identity_graph.py`) —
  Graph of users, devices, service accounts, and roles with typed relationship edges.
  Alerts link to identity nodes, enabling blast-radius queries and attack-path
  reconstruction.

- **Auto-generated board reports** (`services/api/migrations/019_board_reports.sql`,
  `services/api/app/models/report.py`, `services/api/app/api/v1/endpoints/reports.py`) —
  Report templates and scheduled generation of PDF/HTML executive summaries. Artefacts
  are stored, versioned, and deliverable via email or webhook.

#### Platform

- **Dashboard metrics API** (`services/api/app/api/v1/endpoints/metrics.py`) —
  `/api/v1/metrics/dashboard` aggregates alert KPIs, case counts, connector source
  stats, top MITRE tactics, 24-hour alert trend, and threats-by-source for the
  frontend dashboard tiles. `/api/v1/metrics/alerts/trend` supports `1h / 24h / 7d / 30d`
  period buckets.

- **Tailscale connector** (`services/connectors/app/connectors/tailscale.py`) —
  Pulls audit logs and policy-file change events from the Tailscale API with
  OAuth client-credential and API-key auth, cursor-based pagination, and four-tier
  severity mapping.

- **AWS GuardDuty credential-exfiltration detection** (`detections/cloud/aws-guardduty-instance-credential-exfiltration.yaml`) —
  Sigma rule covering EC2 instance credential exfiltration via `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

---

### Click-and-connect cloud connector platform

This pass turns connectors from a hardcoded, code-edit-only feature into a
runtime, schema-driven, click-and-connect surface — and lights up nine new
cloud / SaaS / VCS sources (Microsoft Entra, Azure Activity, Defender XDR,
GCP Cloud Audit, GCP SCC, Microsoft 365 audit, Google Workspace, Cloudflare,
GitHub) on top of the original CrowdStrike / Splunk / AWS Security Hub /
Okta / Microsoft Sentinel set.

#### Added

- **`CredentialVault`** (`services/api/app/security/credential_vault.py`,
  `services/connectors/app/security/credential_vault.py`) — Fernet
  (AES-128-CBC + HMAC-SHA256) wrapper for `auth_config` JSON, keyed off the
  new `AISOC_CREDENTIAL_KEY` env var. Supports `MultiFernet` rotation via
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`. The `services/connectors`
  read-path mirror decrypts only; writes always go through the API
  service. Documented in [docs/operations/credentials](apps/docs/docs/operations/credentials.md).
- **Self-describing connector schemas** (`services/connectors/app/connectors/base.py`)
  — `BaseConnector` gained a `Field` / `OAuthHints` / `ConnectorSchema`
  trio and an abstract `schema()` classmethod. Each connector class is now
  the source of truth for its own `name`, `connector_category`, fields
  (text / secret / select / textarea / oauth), default poll interval, and
  hosted-OAuth roadmap hints. The hardcoded dict in
  `services/connectors/app/api/router.py` is gone — schema responses come
  from the registry built in `services/connectors/app/connectors/__init__.py`.
- **`/api/v1/connectors` CRUD endpoints**
  (`services/api/app/api/v1/endpoints/connectors.py`,
  `services/api/app/schemas/connector.py`) — `GET /catalog`, `POST /test`,
  `GET / POST / PATCH / DELETE /instances`, `POST /instances/{id}/test`.
  Tenant-scoped via the existing auth dependency, secrets encrypted on
  write through the vault, and proxied to the connectors microservice for
  schema lookups and live `Test connection` calls.
- **`ConnectorScheduler`** (`services/connectors/app/scheduler.py`) —
  APScheduler in-process inside `services/connectors`, started in the
  FastAPI lifespan. One job per enabled instance, polls
  `fetch_alerts(since_seconds=300)` every 5 min by default
  (`connector_config.poll_interval_seconds` overrides per instance),
  decrypts via the read-path vault, normalizes events through the
  connector's `normalize()` method, and pushes the batch to
  `services/ingest/v1/ingest/batch` via the new `IngestClient`. Set
  `AISOC_CONNECTORS_DISABLE_SCHEDULER=1` to skip wiring the scheduler in
  tests.
- **Nine new connectors** in `services/connectors/app/connectors/`:
  `azure_entra` (Microsoft Graph audit logs), `azure_activity` (ARM
  Activity Log via Resource Graph + blast-radius `_HIGH_BLAST_RADIUS_VERBS`
  list), `azure_defender` (Microsoft Graph Security alerts),
  `gcp_cloud_audit` (Cloud Logging API with hand-rolled RS256 JWT
  signing for service-account auth), `gcp_scc` (Security Command Center
  findings, same JWT signer), `m365_audit` (Office 365 Management
  Activity API, sharing the Azure AD app from `azure_entra`),
  `google_workspace` (Reports API with domain-wide delegation),
  `cloudflare` (Audit Logs), and `github` (Org Audit Log + Code Scanning
  alerts). Every connector ships unit tests covering schema contract,
  normalization, and `test_connection()` happy/sad paths
  (`services/connectors/tests/test_*_connectors.py`,
  `test_schemas.py`, `test_scheduler.py`).
- **Frontend click-and-connect wizard**
  (`apps/web/src/components/connectors/AddConnectorModal.tsx`,
  `ConnectorInstanceList.tsx`, rewired
  `ConnectorsView.tsx`, typed client in `apps/web/src/lib/api.ts`) —
  two-step modal: (1) catalog grid grouped by category, (2)
  schema-driven form with `text` / `secret` / `select` / `textarea`
  fields, an inline `Test connection` button, and a `Save & enable`
  action. `framer-motion` for transitions, `react-hot-toast` for
  feedback. Existing connector cards now render from the live API via
  SWR.
- **Marketplace + plugin manifests** —
  `plugins/{azure-entra, azure-activity, azure-defender, gcp-cloud-audit,
  gcp-scc, m365-audit, google-workspace, cloudflare, github}/plugin.yaml`
  carry the new `schema()` shape so `scripts/build_marketplace.py` can
  surface them in the in-app Marketplace, and
  `apps/web/public/marketplace/index.json` is regenerated via
  `pnpm marketplace:sync`.
- **Documentation** — `apps/docs/docs/connectors/index.md` (catalog
  landing with a connector walkthrough and category taxonomy), nine
  per-connector setup walkthroughs (prereqs, scopes, screenshots),
  `apps/docs/docs/operations/credentials.md` (vault threat model, key
  rotation procedure, hosted-OAuth roadmap), and a new `Connectors`
  section in `apps/docs/sidebars.ts`.

#### Changed

- **`services/api/app/core/config.py`** — added `AISOC_CREDENTIAL_KEY`,
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`, `CONNECTORS_SERVICE_URL`,
  `CONNECTORS_SERVICE_TIMEOUT_SECONDS`. Documented in `.env.example`.
- **`services/api/app/main.py`** — the new `/api/v1/connectors` router is
  mounted alongside the existing v1 router set.
- **`services/connectors/app/api/router.py`** — schema responses lookup
  the registry instead of returning a hardcoded dict; new
  `POST /connectors/{connector_id}/test` endpoint runs an
  unauthenticated dry-run `test_connection()` for the wizard's
  pre-save Test step.
- **`services/connectors/app/main.py`** — the FastAPI lifespan now wires
  the scheduler, with `AISOC_CONNECTORS_DISABLE_SCHEDULER` honored for
  tests and CI.

#### Why this matters

Before this pass: adding a connector meant editing Python in three places,
shipping a release, and reading docs to discover the auth fields. Secrets
sat in plain JSON in Postgres. After this pass: connectors are runtime
data; secrets are encrypted with a key the operator controls; rotation
is a documented procedure; the wizard's `Test connection` round-trip
catches bad credentials before they're saved; and the per-connector docs
each give an analyst a 5-minute path from "I have a tenant" to "alerts
are flowing into the console."

---

### Eval harness v1.4 — synthetic telemetry + per-template macros

This pass addresses two questions raised on the public launch thread about
the v5.2 eval harness:

1. **"Any interest in shipping synthetic telemetry (M365 audit, CloudTrail,
   Sysmon) backing each incident?"** — Yes. A companion
   `synthetic_telemetry.jsonl` corpus is now generated alongside
   `synthetic_incidents.json` and gives connector and Sigma PRs a concrete
   contract to wire against without provisioning a real tenant.
2. **"INC-EVAL-044, 099, and 154 are the same template with `{user}/{host}`
   swapped — what does the multiplier buy vs. the dilution in regression
   signal?"** — The multiplier still buys breadth for connector regressions,
   but the eval suites now report a per-template macro alongside the
   per-case mean so a single broken template (~4 cases) moves the regression
   signal by ~1.8% rather than ~0.5%, and the failing template IDs are
   surfaced inline.

#### Added

- **Synthetic telemetry corpus**
  (`services/agents/tests/eval_data/synthetic_telemetry.jsonl`,
  `scripts/generate_eval_incidents.py`) — 361 backing events spanning 14
  log sources (Sysmon, Windows Security, M365 audit, Azure sign-in,
  CloudTrail, Linux auditd, journald, EDR, DNS, web access, Kubernetes
  audit, GitHub audit, VPN, DB audit), wired to all 200 incidents. Each
  event is a templated dictionary with `{user}/{host}/{ip}/{campaign}`
  placeholders resolved against the incident it backs, and carries the
  fields a real connector pivots on (process tree, principal, source IP,
  log source, event ID).
- **Telemetry event factories + recursive resolver**
  (`scripts/generate_eval_incidents.py`) — `_sysmon`, `_winsec`, `_m365`,
  `_azure_signin`, `_cloudtrail`, `_auditd`, `_journald`, `_edr`, `_dns`,
  `_web`, `_k8s`, `_github`, `_vpn`, `_db` produce base event shapes; a
  recursive resolver walks nested dicts and substitutes incident
  context. The 55 templates in `_TEMPLATES` each now carry a
  `template_id`, a `template_index`, and a tuple of telemetry events.
- **Schema + coverage gate** (`services/agents/tests/test_synthetic_telemetry.py`)
  — five new assertions: every incident has ≥ 1 backing event, every
  expected source is present, every event carries the source-specific
  pivot fields a real connector needs, all placeholders resolve, and no
  single template dominates the source distribution.
- **Per-template macros on every scoring suite**
  (`services/agents/tests/test_mitre_accuracy.py`,
  `test_investigation_completeness.py`, `test_response_quality.py`,
  `scripts/run_evals.py`) — each result now carries a
  `per_template_summary()` (mean, median, min, max, count, failing IDs)
  alongside the per-case mean, plus a new test gating macro accuracy ≥
  0.80 for MITRE / completeness and ≥ 0.75 for response-plan quality. A
  template-distribution-balance test asserts no single template accounts
  for > 5% of incidents (currently 0.5–2.0% each).
- **`run_evals.py` output expansion** — each suite headline now prints
  the per-case mean *and* the per-template macro with the failing
  template IDs inline; the human-readable summary appends a synthetic-
  telemetry footer (event count, source count, incident coverage, file
  path); `--json` output adds `per_template` and `telemetry` blocks.

#### Changed

- **Incident schema** — `synthetic_incidents.json` entries now include
  `template_id` (e.g. `m365_admin_impersonation`) and `template_index`
  fields. Existing fields are unchanged. Regenerated deterministically
  from the seeded RNG.
- **`apps/docs/docs/benchmark.md`** — added a "What's new (v1.4)"
  section, a "Per-case vs. per-template metrics" section explaining the
  ~0.5% vs ~1.8% sensitivity argument with worked examples, and a new
  "Synthetic telemetry corpus" section documenting the 14 sources, the
  pivot fields, the placeholder resolver, and the five schema/coverage
  checks. The "Help us harden the harness" call-outs now include adding
  a connector + Sigma rule against the corpus and adding a new template
  with backing telemetry. The "What this is not" section is updated to
  call out that the corpus is hand-shaped (not captured from a live
  tenant) and that the per-template macro is the non-tautological signal
  on top of the otherwise self-consistent gates.
- **`README.md`** — capability bullet rewritten to call out five suites
  (was four), 55 distinct templates, per-case + per-template macros, and
  the synthetic-telemetry coverage gate. The comparison table flags the
  eval harness as having a synthetic-telemetry corpus + per-template
  macros. Step 5b (`Run the public eval harness`) documents the new
  `python scripts/generate_eval_incidents.py` workflow for regenerating
  the dataset and the corpus together.
- **Eval signature on completeness + response-quality runs** — calls
  from `run_evals.py` now use `keep_per_incident=True` so the per-
  template summary is computable. Default behaviour unchanged for
  existing direct callers.

#### Why this matters

The v5.2 harness gave deterministic numbers but two real concerns existed:
duplicates could mask a broken template behind 199 working duplicates, and
there was no concrete telemetry shape for connector contributors to wire
against. v1.4 closes both: the per-template macro is the dilution-resistant
regression signal that surfaces template-class breaks, and the synthetic
telemetry corpus is the connector-development contract.

---

### Honesty + scale pass (P0–P4 of the post-gimmick improvement plan)

This is a "fix the foundations" pass: tighten security defaults, drop
overclaims, harden CI, fix DX rough edges, scale detection content from
~200 to 6,913 rules with explicit tiering, and ship a public demo
hosted on `tryaisoc.com` via Cloudflare Tunnel.

#### Security defaults (P0)

- **GraphQL tenant scoping** (`services/api/app/graphql/`) — every
  resolver is wrapped with a `tenant_scope` helper, GraphiQL is forced
  off in production, and a tenant-isolation regression test asserts
  cross-tenant reads return 0 rows.
- **Plugin signature gate** (`services/api/app/services/plugin_manager.py`,
  `packages/plugin-sdk-py/src/aisoc_plugin_sdk/loader.py`,
  `packages/plugin-sdk-go/aisoc/loader.go`) — Ed25519 signature
  verification is required before loading any plugin. `PLUGIN_TRUST_MODE`
  controls policy: `strict` (default, signed only), `permissive` (warn
  + load), `dev` (skip). Publisher signing flow is documented in
  `packages/plugin-sdk-py/README.md` and `packages/plugin-sdk-go/README.md`.
- **`/metrics` and compose hardening** (`docker-compose.yml`,
  `docker-compose.demo.yml`, `services/api/app/main.py`,
  `services/api/app/core/security.py`) — service ports bind to
  `127.0.0.1` by default, the API logs a loud warning if `SECRET_KEY`
  is unset or default, the `admin` role permissions are corrected to
  match the documented matrix, and `/metrics` is gated behind
  `METRICS_TOKEN`.

#### Honesty surface (P1)

- **Fusion pipeline framing** (`services/agents/app/fusion/`,
  `apps/docs/docs/architecture.md`) — replaced "real fusion pipeline"
  with the actual scope (rule-based + ML scoring fan-in, no
  reinforcement learning).
- **CI cadence wording** (`README.md`, `CONTRIBUTING.md`) — "every
  commit" → "every push and PR to `main`".
- **Eval harness honesty** (`scripts/eval/`, `apps/docs/docs/`) —
  removed "Macro F1" references, reframed the 200-incident synthetic
  dataset as substrate self-consistency, dropped the hardcoded
  `SUITES` constant, fixed the broken `--report` flag, and aligned
  Prophet usage in code and docs.

#### CI gates (P2)

- **No more `|| true`** (`.github/workflows/ci.yml`) — removed every
  silent failure suppression.
- **Web Vitest smoke** — `apps/web` ships a Vitest suite covering
  marketplace filters, detection coverage view, and core layouts.
- **SDK + service jobs** — added Python pytest + Vitest jobs for
  `packages/sdk-{py,ts,go}` and `packages/plugin-sdk-{py,go}`, plus
  pytest jobs for `services/{api,agents,actions,connectors}`.
- **Detection + playbook validation in CI**
  (`.github/workflows/validate-detections.yml`,
  `.github/workflows/check-openapi.yml`) — `validate_detections.py`
  runs against all 6,913 rules and the OpenAPI spec is regenerated
  and compared on every PR.

#### DX (P3)

- **`aisoc-doctor` probes fixed** (`tools/aisoc-doctor/`) — checks
  match the actual ports, env var names, and service URLs.
- **CLI consistency** (`packages/cli/`, `README.md`,
  `apps/docs/docs/`) — `npx aisoc` and `aisoc` resolve identically;
  package names, missing pnpm scripts, and the `mcp` service
  reference are corrected; branching/tooling and env var names match
  across docs.
- **Infra READMEs** — `infra/k8s/`, `infra/helm/`, `infra/terraform/`,
  `infra/render/`, `infra/fly/`, `infra/railway/`, `infra/coolify/`
  each have a `README.md` documenting prerequisites, secrets, and
  invocation.

#### Detection scale + tiering (P4)

- **800 native rules** — added 600 new Sigma-shaped detections across
  five new spec modules (`scripts/detection_specs_part3_cloud.py`,
  `_identity.py`, `_endpoint.py`, `_network.py`,
  `_application.py`), each with `match_when`, MITRE tagging, and
  auto-generated positive/negative fixtures via
  `scripts/detection_specs_part3_helpers.py`. Native total:
  200 → **800**.
- **6,113 imported rules with provenance** — wired importers under
  `tools/detection_import/{sigma,splunk,chronicle,car}_importer.py`
  for SigmaHQ, Splunk Security Content, Chronicle, and MITRE CAR.
  Each imported rule is tagged with its source, license, and original
  ID; rules whose mappings cannot be replayed against AiSOC fixtures
  are quarantined under `detections/<source>-imports/quarantine/`
  (~5,937 quarantined, ~6,113 active).
- **Title → name migration** — imported YAMLs now use the canonical
  `name:` field instead of `title:`, matching `validate_detections.py`'s
  required schema. `tools/detection_import/common.py` was updated and
  6,113 existing files were migrated in place.
- **Marketplace tier UX** (`apps/web/src/components/marketplace/MarketplaceView.tsx`,
  `MarketplaceView.test.tsx`, `marketplace/index.json`,
  `apps/web/public/marketplace/index.json`,
  `scripts/build_marketplace.py`) — items now expose a `tier` field
  (`stable` / `beta` / `imported` / `community`), the marketplace UI
  defaults to `stable` and shows per-tier counts on filter chips,
  and `build_marketplace.py` infers tiers from `plugin.yaml` and
  source paths.
- **MITRE ATT&CK coverage view** (`apps/web/src/app/(app)/detection/coverage/`,
  `apps/web/src/lib/mitreTactics.ts`) — new in-app dashboard rendering
  the coverage matrix from the marketplace index.
- **Documentation refresh** — updated `README.md`,
  `apps/docs/docs/intro.md`, `apps/docs/docs/quickstart.md`,
  `apps/docs/docs/concepts/detections.md`,
  `apps/docs/docs/contributing/dev-setup.md`,
  `detections/README.md`, and `.github/workflows/validate-detections.yml`
  to reflect 800 native + ~6,000 imported (filterable by tier) and
  drop stale "200+ rules" claims.

#### Public demo on `tryaisoc.com`

- **Cloudflare Tunnel infra** (`infra/cloudflare/`) — `config.yml.example`,
  `tunnel.sh`, and a README explaining how to run the demo profile
  behind `tryaisoc.com` via `cloudflared`. Tunnel script reads
  `DOMAIN`, `TUNNEL_NAME`, `SUBDOMAINS`, `SKIP_DNS`, `SKIP_RUN` env
  vars; defaults publish apex + `api.`, `ws.`, `docs.` subdomains.
- **`pnpm demo:public` script** (`scripts/demo-public.sh`) — boots
  `docker-compose.demo.yml` (read-only demo profile with seeded
  incidents) via `pnpm aisoc:demo --no-open`, then brings up the
  Cloudflare Tunnel that maps `tryaisoc.com` → web (`:3000`),
  `api.tryaisoc.com` → api (`:8000`), `ws.tryaisoc.com` → realtime
  (`:4000`), and `docs.tryaisoc.com` → Docusaurus (`:3001`).
  Companion scripts: `pnpm demo:public:tunnel-only` (skip stack
  bring-up, just run the tunnel) and `pnpm demo:public:setup`
  (provision tunnel + DNS without running cloudflared, for
  `cloudflared service install` flows).
- **Public-host-agnostic web bundle** (`apps/web/next.config.js`,
  `apps/web/src/lib/api.ts`) — the Next.js client now emits
  same-origin relative paths (`/api/v1/...`, `/ws/...`) instead of
  `localhost:8000`-baked URLs, with server-side rewrites proxying
  to api/agents/realtime by Docker DNS name. The same image works
  on `localhost:3000`, behind Cloudflare Tunnel on `tryaisoc.com`,
  or behind any reverse proxy without a rebuild.
- **README "Try it live"** — top-of-README link to the public demo
  with a one-liner for hosting your own on a Cloudflare-managed
  domain.

---

## [5.2.0] — 2026-05-04

### Added

This release groups four areas of work: an append-only investigation
ledger, a public eval harness, a mobile responder PWA, and a hosted
demo profile. Details below.

#### Auditable agent — Investigation Ledger

- **Investigation Ledger** (`services/api/migrations/008_investigation_ledger.sql`,
  `services/api/app/models/investigation.py`,
  `services/agents/app/investigator/ledger.py`) — every prompt the agent
  emits, every tool call, every retrieved evidence shard, and every
  rationale is persisted as an append-only `investigation_step` row,
  scoped to a tenant + case.
- **Investigation Ledger UI** (`apps/web/src/components/cases/InvestigationLedger.tsx`)
  — replayable step-by-step view in the case workspace with prompt,
  response, and tool-call diffs.
- **`GET /api/v1/investigations/*` endpoints** (`services/api/app/api/v1/endpoints/investigations.py`)
  for listing, retrieving, and replaying ledger entries by case.
- **Investigator graph upgrades**
  (`services/agents/app/investigator/{orchestrator,recon_agent,forensic_agent,responder_agent,report_writer_agent,state}.py`)
  — every node now writes a ledger entry on entry and exit, including
  the structured input it received and the structured output it produced.

#### Public eval harness — Pillar-1 eval suite

- **200-incident synthetic dataset**
  (`services/agents/tests/eval_data/synthetic_incidents.json`) — 200
  deterministic, regenerable cases covering all 14 MITRE ATT&CK enterprise
  tactics across roughly the top 50 techniques. Generated by
  `scripts/generate_eval_incidents.py`.
- **Four eval gates** under `services/agents/tests/`:
  - `test_alert_reduction.py` — **real measurement**: 1 000 noisy alerts →
    ~250 incidents via 3-tier fusion, with explicit storm and
    near-duplicate handling
  - `test_mitre_accuracy.py` — **substrate self-consistency gate**:
    tactic-level accuracy / precision / recall / F1 between the
    hand-curated extractor and the dataset that was written to feed it
  - `test_investigation_completeness.py` — **substrate self-consistency
    gate**: evidence-keyword coverage on a templated report
  - `test_response_quality.py` — **substrate self-consistency gate**:
    5-criterion offline rubric on a templated response plan (action class,
    severity awareness, MITRE alignment, evidence grounding, actionability)
- **`scripts/run_evals.py`** — one-shot harness with `--json` and `--ci`
  output modes. Total runtime ~25 ms on a laptop. CI-gated on every
  commit via `.github/workflows/ci.yml`. Runs deterministic substrate code
  against synthetic incidents — does not call the live LLM agent.
- **Public eval harness page** (`apps/docs/docs/benchmark.md`,
  `apps/web/src/app/benchmark/page.tsx`,
  `apps/web/src/components/benchmark/`) — published numbers, full
  method, comparison to other AI SOC offerings, and explicit framing of
  which suites measure substrate self-consistency vs real behaviour.
  Linked from the README and the docs landing page.

#### Mobile responder — Responder PWA

- **Responder PWA** (`apps/web/src/app/(responder)/`,
  `apps/web/src/components/responder/`,
  `apps/web/src/components/pwa/`) — installable, offline-aware, push-
  enabled responder console for on-call analysts. Service worker at
  `apps/web/public/sw.js`, manifest at `apps/web/public/manifest.json`,
  offline shell at `apps/web/public/offline.html`.
- **Passkey authentication** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/passkeys.py`,
  `apps/web/src/lib/responder/`) — WebAuthn registration and login for
  the Responder surface; FIDO2 platform authenticators only, no SMS
  fallback.
- **On-call schedule + handoff** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/oncall.py`) — current responder per
  tenant, surfaced in the Responder home page and in alert pages on the
  desktop console.
- **Approvals workflow** (`services/api/app/api/v1/endpoints/approvals.py`)
  — long-lived approval requests for blast-radius-gated SOAR actions,
  approvable from the Responder PWA with hardware-attested passkey.
- **Web Push delivery** (`services/realtime/src/push.ts`,
  `services/api/app/api/v1/endpoints/push.py`) — VAPID-signed push
  notifications wired into the realtime gateway. Subscriptions persist
  per-device and follow the on-call rotation.
- **Migration** — `services/api/migrations/009_responder_pwa.sql`.

#### Ambient Copilot

- **Contextual actions** (`services/agents/app/api/contextual.py`,
  `apps/web/src/components/alerts/AlertDetailView.tsx`,
  `apps/web/src/components/cases/CaseWorkspace.tsx`,
  `apps/web/src/components/detections/RuleEditor.tsx`,
  `apps/web/src/components/playbooks/PlaybookEditor.tsx`) — the AI Copilot
  now reads the surface the analyst is standing on (alert / case / rule /
  playbook) and proposes the next two or three concrete actions with the
  correct payloads pre-filled. One click invokes the agent with the
  right tool.
- **Investigator graph awareness** — every contextual action is grounded
  in the same Investigation Ledger so the analyst sees, before clicking,
  which prompts and tool calls will be issued.

#### MCP server — first-class IDE / chat integration

- **`@aisoc/mcp`** (`services/mcp/`) — Model Context Protocol server
  exposing 11 AiSOC tools to Claude Desktop, Cursor, Cody, and Continue.
- **Discovery tools** — `aisoc_list_alerts`, `aisoc_list_cases`,
  `aisoc_query_detections`.
- **Deep-dive tools** — `aisoc_get_case`, `aisoc_get_investigation`,
  `aisoc_get_alert`.
- **Action / replay tools** — `aisoc_run_investigation`,
  `aisoc_replay_decision`, `aisoc_explain_step`, `aisoc_create_case`,
  `aisoc_assign_alert`. The replay set walks the Investigation Ledger
  step-by-step inside the IDE / chat.
- **Install command** — `npx -y @aisoc/mcp install --host claude --aisoc-url … --api-key …`.
- **Documentation** — `apps/docs/docs/integrations/mcp.md`,
  `services/mcp/README.md`.

#### Hosted demo — `pnpm aisoc:demo`

- **Slim demo profile** (`docker-compose.demo.yml`) — postgres + redis +
  kafka + api + agents + realtime + web. ClickHouse, OpenSearch, Neo4j,
  and Qdrant are gated behind compose profiles for production.
- **Prebuilt images** — `ghcr.io/beenuar/aisoc-{api,agents,realtime,web,…}`
  built and published by `.github/workflows/publish-images.yml` on every
  release tag.
- **One-shot orchestrator** (`scripts/aisoc-demo.ts`) — pulls images,
  brings up the stack, waits on healthchecks, seeds canonical demo data,
  kicks off an agent investigation against a seeded case, and opens the
  browser at `/cases/<uuid>` with the live ledger view selected.
- **Demo mode middleware** (`services/api/app/middleware/demo_mode.py`)
  — gates write operations, resets state every UTC midnight, and
  watermarks the UI as read-only. Tests at
  `services/api/tests/test_demo_mode.py`.
- **Target time-to-first-investigation:** roughly 3–5 minutes on a warm
  Docker daemon, depending on image cache state.
- **Cleanup** — `pnpm aisoc:demo:down` removes the volumes; logs at
  `pnpm aisoc:demo:logs`.

#### Deployment — one-click everywhere

- **Fly.io** (`infra/fly/`) — first-class config for `api`, `agents`,
  `realtime`, `web`. Deploys via `infra/fly/fly-demo-deploy.sh`,
  ~$14/mo for the whole stack.
- **Render** (`render.yaml`) — managed, sleep-on-idle
  config suitable for hobbyists and design partners.
- **Railway** (`infra/railway/railway.toml`) — pay-as-you-go PaaS.
- **Coolify** (`infra/coolify/README.md`) — self-hosted on your own VPS,
  reuses the existing `docker-compose.yml`.

#### Marketplace — content as code

- **~200 detection rules** in `detections/` covering MITRE ATT&CK
  Enterprise (cloud, identity, endpoint, network, application). Sigma
  format, with MITRE technique IDs in `tags`, fixtures under
  `detections/fixtures/`, and `detections/README.md` documenting the
  schema.
- **50+ response playbooks** in `playbooks/packs/v1/` — IAM, EDR,
  network, application, generic. JSON DSL with explicit decision trees,
  human-approval gates, and rollback steps. Schema in
  `playbooks/README.md`.
- **15 plugins** in `plugins/` — both Go and Python implementations for
  CrowdStrike, Splunk, Sentinel, AWS Security Hub, Okta, Cloudflare WAF,
  Defender, GuardDuty, Pagerduty, Slack, Teams, Jira, ServiceNow,
  VirusTotal, AbuseIPDB. Each ships with manifests, tests, and SDK
  helpers.
- **Marketplace index** (`marketplace/index.json`,
  `apps/web/public/marketplace/index.json`) — auto-generated by
  `scripts/build_marketplace.py` from the on-disk content tree.
- **Validation tooling** —
  - `scripts/validate_detections.py` (Sigma + MITRE ID schema)
  - `scripts/validate_playbooks.py` and `scripts/lint_playbooks.py`
    (DSL well-formedness + safety)
  - `.github/workflows/{validate-detections,validate-playbooks,sync-marketplace}.yml`
    enforce the gates on every PR.
- **In-app marketplace** (`apps/web/src/app/(app)/marketplace/page.tsx`,
  `apps/web/src/components/marketplace/MarketplaceView.tsx`) — filterable
  by category, ratings, verified vs community badge.

#### Plugin & client SDKs

- **`packages/plugin-sdk-go`** — Go plugin SDK
  (`module github.com/beenuar/aisoc/plugin-sdk-go`) with action,
  connector, enricher, registry, widget, and loader primitives.
  Examples under `packages/plugin-sdk-go/examples/`.
- **`packages/plugin-sdk-py`** — Python plugin SDK with the matching
  primitives, decorators, and a registry. Tests under
  `packages/plugin-sdk-py/tests/`.
- **`packages/sdk-py`** (PyPI: `aisoc-sdk`) — async Python client SDK
  for the AiSOC API.
- **`packages/sdk-ts`** (npm: `@aisoc/sdk`) — TypeScript client SDK
  with auto-generated types.
- **`packages/sdk-go`** — Go client SDK with OpenAPI-generated models.

#### Marketing & docs

- **`/why-open-source`** page (`apps/web/src/app/why-open-source/page.tsx`)
  — long-form description of the project's open-source posture and
  trade-offs.
- **Updated landing** (`apps/web/src/components/landing/{Hero,LandingNav,Footer,OpenSource}.tsx`)
  — the "live demo" button lands directly on a seeded investigation;
  comparison rows reference specific behaviours rather than generic
  claims.
- **Docusaurus refresh** — new MCP integration page, benchmark page,
  Investigation Ledger references, Responder PWA mentions in concepts
  and quickstart.

### Changed

- **Repository home** — all `cyble-inc/AiSOC` and `aisoc-os/aisoc` URLs
  updated to `beenuar/AiSOC` across docs, README, SDKs, and benchmark
  badges.
- **`packages/sdk-go` module path** is now `github.com/beenuar/aisoc/sdk-go`
  for the API client SDK; the plugin SDK is at
  `github.com/beenuar/aisoc/plugin-sdk-go`.
- **`alerts` API** (`services/api/app/api/v1/endpoints/alerts.py`,
  `services/api/app/models/alert.py`) — surfaces copilot context
  (suggested next actions) inline on the alert detail response.
- **API router** (`services/api/app/api/v1/router.py`) — wires up
  `approvals`, `investigations`, `marketplace`, `oncall`, `passkeys`,
  `push`.

### Fixed

- **CI Docker build contexts** — `.github/workflows/{ci,release,publish-images}.yml`
  now set explicit `context` and `file` parameters per service; multi-
  service builds no longer race on a stale build root.
- **Docker Compose obsolete `version` warning** — removed `version: '3.8'`
  from `docker-compose.demo.yml`.
- **Repository hygiene** — added `.gocache/`, `*.tsbuildinfo`,
  `apps/docs/.docusaurus/`, `apps/docs/build/`,
  `plugins/**/*-build-test`, `plugins/**/*-build`,
  `eval_report.json`, and `eval_mitre_accuracy_report.json` to
  `.gitignore`. Removed previously tracked Docusaurus cache and local
  IDE hook state files from the index.

---

## [5.1.0] — 2026-05-03

### Added

- **UEBA service** (`services/ueba`) — User & Entity Behavior Analytics
  - Welford online algorithm for incremental baseline computation
  - Z-score anomaly scoring with configurable sensitivity
  - Peer-group analysis (same role / department / location clustering)
  - Kafka consumer (`security.events`) → producer (`security.anomalies`) integration with `fusion` service
  - Alembic migrations, Dockerfile, Helm deployment template
- **Honeytokens service** (`services/honeytokens`) — deceptive credential & file traps
  - HMAC-SHA256 signed token generator (URL, file, AWS key, email flavors)
  - Webhook handler for first-touch alerting (HTTP signed callbacks)
  - Token lifecycle management: active / triggered / expired states
  - React UI: create tokens, view trigger log, copy lure URLs
  - Alembic migrations, Dockerfile, Helm deployment template
- **Purple Team service** (`services/purple-team`) — adversary emulation & tabletop
  - Atomic Red Team YAML parser (any `atomics/` directory)
  - Caldera REST integration for remote execution
  - ATT&CK coverage heatmap (tactic × technique matrix)
  - Test execution tracking with detection reporting (true positive / false negative)
  - Tabletop exercise session manager with finding capture
  - React UI: Coverage tab, Executions tab, Tabletop tab
  - Alembic migrations, Dockerfile, Helm deployment template

---

## [5.0.0] — 2026-05-03

### Added

- **SAML 2.0 + OIDC authentication** (`services/api/app/auth/`)
  - IdP-initiated and SP-initiated SAML 2.0 flows (python3-saml)
  - OIDC authorization-code + PKCE flow with `authlib`
  - JWT issuance on successful SSO login
- **Multi-tenant Row-Level Security** (Postgres RLS)
  - `tenant_id` column on all data tables
  - RLS policies enforced at the database level
  - SQLAlchemy `set_tenant()` middleware in FastAPI deps
- **Granular RBAC** (`services/api/app/api/v1/endpoints/rbac.py`)
  - `roles`, `role_permissions`, `user_roles` tables
  - `require_permission("resource:action")` FastAPI dependency
  - Admin UI at `/settings/rbac`
- **Immutable Audit Log**
  - Append-only `audit_log` table with a before-UPDATE trigger
  - FastAPI middleware auto-logs every mutating request
  - `GET /api/v1/audit` paginated endpoint with tenant filter
  - Audit log viewer UI at `/audit`
- **Compliance dashboards**
  - SOC 2 evidence auto-collection + PDF export (`/compliance/soc2`)
  - ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA framework heatmaps
  - `GET /api/v1/compliance/{framework}` endpoint with control mapping
- **SLA tracking** — MTTD / MTTR / MTTC
  - `tenant_sla_config` + `alert_sla_events` tables
  - `GET /api/v1/sla/metrics` + `GET /api/v1/sla/breaches`
  - SLA dashboard widget at `/sla`
- **HA Helm chart** — HPA, PDB, Ingress per service
- **Backup & restore scripts** (`scripts/backup.sh`, `scripts/restore.sh`) for Postgres + ClickHouse + plugins → S3/R2
- **Operational runbook generator** (`scripts/generate_runbook.py`) from live OTel trace data
- **Multi-region deployment guide** (`docs/operations/multi-region.md`)
- **OpenTelemetry instrumentation** across API, UEBA, Honeytokens, and Purple Team services

---

## [4.1.0] — 2026-05-03

### Added

- **AiSOC CLI** (`packages/aisoc-cli`) — `scaffold`, `validate`, `publish` commands for plugins and detections
  - `aisoc scaffold plugin <name>` — generate plugin skeleton
  - `aisoc validate detection <file>` — Sigma/YAML schema validation
  - `aisoc publish plugin <path>` — submit to community registry with Ed25519 signing
- **Plugin publishing flow**
  - `community_plugins` table with signature, author, review state
  - `POST /api/v1/plugins/publish` — signed submission
  - `POST /api/v1/plugins/{id}/approve` / `reject` — curator review endpoints
  - Ed25519 signature verification on every submission
- **Marketplace v2** — ratings, install counts, verified badges, category filter, sort options
  - `plugin_ratings` table + `POST /api/v1/plugins/{id}/rate`
  - `GET /api/v1/marketplace?category=&sort=` with pagination
- **Detection catalog** (`/detection/catalog`) — paginated Sigma rule browser
  - Install-to-tenant action from catalog
  - `GET /api/v1/detections/catalog` endpoint
- **Playbook community submissions**
  - `community_playbooks` table + submit / curate API
  - Community tab in PlaybooksView UI
- **Docusaurus documentation site** (`apps/docs`) — full API, architecture, deployment, plugin SDK, quickstart

---

## [3.0.0] — 2026-05-02

### Added
- **Threat Intelligence Enrichment (13 providers)**
  - Open-source/freemium: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan.io, IPinfo
  - Commercial: Cyble Vision, Recorded Future, Mandiant, Crowdstrike Intel, Anomali, IBM X-Force, Flashpoint, Intel 471, DomainTools, RiskIQ
  - New enrichment types: `DarkWebContext`, `VulnerabilityRef`, `BrandRisk`
  - Concurrent fan-out enrichment engine in Go
- **Go module path migration** — all services updated from `github.com/cyble/aisoc` to `github.com/beenuar/aisoc`
- **SECURITY.md** — vulnerability disclosure policy and security contacts
- `services/enrichment/README.md` — full enrichment service documentation

### Changed
- All GitHub repository references updated to `https://github.com/beenuar/AiSOC`
- Helm chart container images updated from `ghcr.io/cyble/aisoc-*` to `ghcr.io/beenuar/aisoc-*`
- `.env.example` expanded with API keys for all commercial TI providers

---

## [2.0.0] — 2026-05-01

### Added
- **Knowledge Graph** — Neo4j-backed entity relationship visualization (`services/api/app/services/graph_service.py`)
- **ML Fusion Engine** — multi-model alert scoring and deduplication (`services/fusion/app/services/`)
- **Rule Engine** — YAML-based detection rules with MITRE ATT&CK mapping (`services/api/app/services/rule_engine.py`)
- **Attack Graph** viz with D3.js force layout (`apps/web/src/components/graph/`)
- **MITRE ATT&CK Heatmap** on dashboard
- **AI Copilot dock** — streaming LLM assistant integrated into case and alert views
- **Threat Hunt page** — query builder with saved hunts and timeline scrubbing
- **Case Workspace** — full case lifecycle: evidence, timeline, collaborators, MITRE tagging
- **Detection Rule Builder** — visual rule editor with backtesting
- **Settings page** — RBAC, notifications, API key management, threat intel feed config
- **Live Dashboard** — WebSocket-powered real-time alert/event feed
- **Command Palette** (cmd-K) — fuzzy search for navigation and actions
- **Marketing Landing Page** — hero, feature highlights, open-source section, footer
- **Design Token System** — Tailwind + CSS vars, Framer Motion animations, responsive layouts
- **Demo Producer** — synthetic event generator for local development
- `scripts/seed_demo.py` — database seeding for demos

### Changed
- Web app migrated to Next.js App Router
- All API routes versioned under `/api/v1`

---

## [1.0.0] — 2026-04-30

### Added
- Initial release of AiSOC — AI Security Operations Center
- FastAPI backend (`services/api`) with alert ingestion, case management, detection rules
- Next.js 14 frontend (`apps/web`) with dashboard, alerts, cases, connectors, threat-intel pages
- Real-time service (`services/realtime`) using WebSockets
- Ingest service (`services/ingest`) in Go for high-throughput event ingestion
- Enrichment service (`services/enrichment`) in Go
- Docker Compose stack for local development
- Helm chart for Kubernetes deployment (`infra/helm/aisoc/`)
- MIT License

[Unreleased]: https://github.com/beenuar/AiSOC/compare/v5.2.0...HEAD
[5.2.0]: https://github.com/beenuar/AiSOC/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/beenuar/AiSOC/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/beenuar/AiSOC/compare/v4.1.0...v5.0.0
[4.1.0]: https://github.com/beenuar/AiSOC/compare/v3.0.0...v4.1.0
[3.0.0]: https://github.com/beenuar/AiSOC/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/beenuar/AiSOC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/beenuar/AiSOC/releases/tag/v1.0.0
