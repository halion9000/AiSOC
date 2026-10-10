# How Cipher operates AiSOC

Cipher is the security agent in CORE. It works through **purpose-built tools**, each of which sends exactly one kind of request to AiSOC with CORE's own API key (`core-hud`). This page is about the AiSOC side of that: what the key may do, how the tools are kept honest, and how to add one.

## Why purpose-built tools, not "call any endpoint"

What Cipher reads (alert titles, hostnames, usernames, rules drafted by a model from alerts) comes from monitored systems, so from attackers. An agent that can name an arbitrary path can be talked into reading, or doing, anything its key allows. So every tool is a fixed `GET` (the older ones also `POST` and `PATCH`, each approval-gated in CORE) to a fixed path; the only variable parts are validated, URL-encoded ids and a query string built from a whitelist; and every response is limited, with what was cut said ("showing 100 of 412 items"), never silently.

## The key (least privilege, and why some things are left out)

`CORE_KEY_SCOPES` in `app/scripts/bootstrap_production.py`: `alerts:read`, `alerts:write`, `cases:read`, `cases:write`, `connectors:read`, `rules:read` (the detection-engineering tools) and `hunts:read` (hunt definitions). No delete, no playbook execution, no rule **writes**.

* **`lake:query` is deliberately not granted.** It is one permission for hunting's reads **and** its writes (create, run, delete), for arbitrary natural-language queries against telemetry, and for reading what a hunt's runs found. So AiSOC has a separate read-only `hunts:read` (see `roles-and-platform-permissions.md`): it covers hunt hypotheses, saved hunts and saved searches, and nothing else. A run's results (`result_sample`: event rows from the lake) stay behind `lake:query`, so Cipher can read what hunts exist and what the analysts concluded, not the telemetry a hunt returned. The five hunting tools (`aisoc_list_hunts`, `aisoc_get_hunt`, `aisoc_list_saved_hunts`, `aisoc_get_saved_hunt`, `aisoc_list_saved_searches`) each need exactly `hunts:read`, and a test asserts no Cipher tool can reach a run, execute, nl-query, lake, backtest or translate route.
* `rules:read` also guards the routes that *run or backtest* a rule (compute, no writes). Cipher's tools never call those, and the key cannot change a rule.

## Ids: URL-encoding is not enough

An id goes into a URL path. Encoding it does **not** keep it to one path segment: this API's server decodes `%2F` back into `/` before routing, so an id of `<uuid>%2Fruns` reached the real `/hunts/{id}/runs` route (an admin got a 200 from it; Cipher's key was stopped only by a missing scope). So every Cipher tool that takes an alert, case, run, rule, proposal, suggestion or hunt id refuses anything that does not look like an id (starts with a letter or digit; only letters, digits and `. _ - :`; at most 200 characters) **before anything is sent**, and the approval-gated tools refuse it before an approval is created. One rule, in CORE's `aisoc-requests.ts`, with a guard test that fails if a handler reads an id without validating it. Nothing on this side changed: the routes accept what they accept.

## Rolling a new scope out: no key rotation needed

`_ensure_key` used to return "kept-existing" and never touch an existing key's scopes, so a scope added to the list reached only fresh installs and every running deployment got 403s from the new tools until the key was rotated and the new secret handed to CORE. It now **brings an existing key to exactly the wanted scopes in place, keeping the secret**, and says so: a warning in the log (`API key 'core-hud' scopes updated in place (same secret): added ['rules:read'], removed none`) and the status `scopes-updated`. It also takes scopes away (so a scope removed from the list is removed from running keys), and it never touches an inactive key, a key of another name, or a key in another tenant. CORE re-runs this bootstrap, so an upgraded deployment picks the scope up automatically.

## Keeping the two repos honest

Before there was a test, **six of Cipher's seventeen tools were found sending requests AiSOC does not accept** (a wrong field name, a missing body, a filter on a route that has none). Now:

* `tests/test_cipher_tool_contract.py` checks every row of `CIPHER_CALLS`: the route exists, the key's scopes cover the permission it needs, every query name is one the route reads, the body is what the route expects. A tool that only reads must never need a write permission.
* The seventeen read tools (twelve detection engineering, five hunting) are declared in CORE as a table (`hud/src/aisoc-read-tools.ts`). CORE commits a contract file generated from it (`hud/contracts/aisoc-read-tools.json`) and tests that it is current; this repo keeps a copy (`tests/fixtures/core_read_tools.json`) and tests its own table against it, and against CORE's file when the CORE repo is checked out beside this one. A tool changed on one side fails a test until the other side matches. The contract also carries what a mistake here would otherwise hide until a 422: the values a tool allows for a parameter must equal the API's enum (and a parameter the API restricts must not be offered as free text), and a number's clamp must stay inside the API's bounds. (Both were needed: the tuning workbench is paged, which the first version of its tool could not ask for, and its `suggestion` filter is a fixed set that the tool had accepted as free text.)

## Adding a read tool

1. In CORE, add a row to `READ_TOOLS` (path, validated arguments, limits), regenerate the contract file (`UPDATE_AISOC_CONTRACT=1 node --test dist/aisoc-read-tools-contract.test.js`).
2. Copy it to `tests/fixtures/core_read_tools.json` here and add the row to `CIPHER_CALLS`. The tests then tell you if the route is missing, a query name is wrong, or the permission needed is not in `CORE_KEY_SCOPES`.
3. If a scope is needed, add it to `CORE_KEY_SCOPES` **only if it grants nothing but reading** (check what else the permission guards: `lake:query` is the example of one that does not qualify). Existing deployments pick it up the next time bootstrap runs.

## Verifying on a real deployment

The tests use SQLite and stubs; this is the check against the real thing (it was run on Postgres as the restricted role, and it found real mistakes the tests could not).

1. **The key before the upgrade fails, and says why.** With a key that has only the old five scopes: `GET /api/v1/rules` returns `403 {"detail":"API key missing scope: rules:read"}` (and `GET /api/v1/alerts/stats` still returns 200).
2. **Run bootstrap again** (`python -m app.scripts.bootstrap_production --admin-email <the admin's email>`; it needs no password for an existing admin). Expect the log line `API key 'core-hud' scopes updated in place (same secret): added ['rules:read'], removed none` and `core_key_status: scopes-updated` with no new key returned. In the database the `core-hud` key keeps its `key_prefix` and `hashed_key`, and there is still one row.
3. **The same key now works, with the server still running:** `GET /api/v1/rules`, `/detection/coverage`, `/detection/drift` return 200. A third bootstrap reports `kept-existing`.
4. **What was not granted is still refused:** `POST /rules`, `DELETE /rules/{id}`, `GET /hunts` and `POST /nl-query/execute` with that key all return 403 (the last two say `API key missing scope: lake:query`).
5. **Test with data, not an empty database.** An empty library makes every list `[]`, every id lookup a 404 and every coverage check pass vacuously. Seed rules (some `active`, some `testing`/`inactive`, one with a very long body), a proposal and a drafted suggestion, then call each tool. Things only data shows: long text is shortened in a list and is whole in the detail tool; a rule created through the API starts in `testing`, which coverage counts as **not** active; `stale` in the drift inbox is "no triggers yet" and includes a rule that was only just turned on; the id field is `id` for rules and proposals but `suggestion_id` for suggestions.

## What else AiSOC can do (the capability reference)

Cipher has tools for only some areas. `docs/api/aisoc-areas.md` is a generated map of every area (how many reads and changes, what protects them, example operations); Cipher's knowledge file in the CORE repo is a copy, so it can say what AiSOC does even where it has no tool, and must not guess or invent a tool. `docs/api/AISOC_CAPABILITIES.md` is the full per-operation reference. Regenerate both with `python -m app.scripts.export_capabilities --full ../../docs/api/AISOC_CAPABILITIES.md --index ../../docs/api/aisoc-areas.md` (from `services/api`); `--check` and a test fail when they are stale, and a test compares the copy in a CORE checkout beside this repo. The reference describes protection only as far as the routes' dependencies show it; a check inside a handler is not visible.

## Not built yet

Posture and compliance, identity and insider threat, threat intelligence, MSSP and platform operations, and the generated capability reference that would let Cipher know every area of AiSOC. Cipher has no new write tools.
