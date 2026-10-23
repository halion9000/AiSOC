# Migrations

SQL files applied in name order, twice by design: Postgres applies them when the database is first created, and the API's migration runner applies them again at every start (none is recorded yet). **Every file must therefore be safe to run twice** (`IF NOT EXISTS`, `DROP ... IF EXISTS` before `ADD`, `ON CONFLICT`). `tests/test_api_migrations_rerun_postgres.py` checks this for every file.

New tables with a `tenant_id` get the standard isolation policy (copy any of 095 to 097) and row-level security switched on. `tests/test_db_rls_and_grants_postgres.py` fails when a table created from 083 on does not, or when the application role (`aisoc_app`) cannot use it.

## Adding a value to a limited column

Several columns accept only a fixed list (a `CHECK (col IN (...))`). Writing a value the list does not hold fails at the database, and a test that uses a mock database will not notice. This is how the Run script button nearly shipped broken: migration 084 allowed three actions, the feature wrote a fourth, and only a real-database test caught it (fixed by 098).

To add a value:
1. Write a migration that drops the old constraint (`DROP CONSTRAINT IF EXISTS <name>`) and adds the wider one (see `098_vendor_actions_run_script.sql`).
2. Add the value to the contract in `tests/test_db_constraint_contract_postgres.py`. That test lists, for each limited column, the values the code can write (taken from the code's own constants where it has them) and checks the migrated database allows each. It fails if you add the value in code and skip the migration.

Audit of every value-limiting constraint added since 080 (2026-10-23): each column below was checked against the code that writes it; all agree.

| Table.column | Allowed (after the latest migration) | Written by |
|---|---|---|
| `client_aliases.match_source` | manual, suggested (083) | the client mapping routes |
| `vendor_actions.action` | approve, reject, resolve, run_script (084, widened by 098) | the vendor action and Run script routes |
| `vendor_actions.status` | pending, claimed, done, failed (084) | the CORE claim and result routes |
| `connector_run_log.status` | ok, warning, error (086) | the status CORE reports (limited to the same three in the request model) |
| `client_vcio_proposals.status` | suggested, approved, rejected, sent, failed, cleared (096) | the suggestion, decision and CORE result routes |
| `client_vcio_proposals.kind` | recommendation, risk (096) | the suggestion builder |

## What 094 to 098 are for

| File | Adds |
|---|---|
| `094_identity_secure_scores.sql` | The Microsoft Secure Score per client, read through CIPP |
| `095_client_vcio_reviews.sql` | Each client's vCIO Toolbox recommendations and risks (a daily summary from CORE) |
| `096_client_vcio_proposals.sql` | What A.C.O.R.N suggests adding to a client's vCIO Toolbox, and what a person decided |
| `097_client_m365_checks.sql` | Each client's Microsoft 365 baseline checks, read through CIPP (see `docs/M365_CHECKS.md`) |
| `098_vendor_actions_run_script.sql` | Lets the vendor-actions queue carry `run_script` (the Run script button, single and bulk) |
