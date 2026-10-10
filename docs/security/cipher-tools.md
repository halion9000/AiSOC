# How Cipher operates AiSOC

Cipher is the security agent in CORE. It works through **purpose-built tools**, each of which sends exactly one kind of request to AiSOC with CORE's own API key (`core-hud`). This page is about the AiSOC side of that: what the key may do, how the tools are kept honest, and how to add one.

## Why purpose-built tools, not "call any endpoint"

What Cipher reads (alert titles, hostnames, usernames, rules drafted by a model from alerts) comes from monitored systems, so from attackers. An agent that can name an arbitrary path can be talked into reading, or doing, anything its key allows. So every tool is a fixed `GET` (the older ones also `POST` and `PATCH`, each approval-gated in CORE) to a fixed path; the only variable parts are validated, URL-encoded ids and a query string built from a whitelist; and every response is limited, with what was cut said ("showing 100 of 412 items"), never silently.

## The key (least privilege, and why some things are left out)

`CORE_KEY_SCOPES` in `app/scripts/bootstrap_production.py`: `alerts:read`, `alerts:write`, `cases:read`, `cases:write`, `connectors:read` and, for the detection-engineering tools, `rules:read`. No delete, no playbook execution, no rule **writes**.

* **`lake:query` is deliberately not granted.** It is one permission for hunting's reads **and** its writes (create, run, delete) and for arbitrary natural-language queries against telemetry. Giving the key that so Cipher could *read* a hunt would let the key do all of it. Cipher gets hunting reads once AiSOC has a read-only permission for them.
* `rules:read` also guards the routes that *run or backtest* a rule (compute, no writes). Cipher's tools never call those, and the key cannot change a rule.

## Rolling a new scope out: no key rotation needed

`_ensure_key` used to return "kept-existing" and never touch an existing key's scopes, so a scope added to the list reached only fresh installs and every running deployment got 403s from the new tools until the key was rotated and the new secret handed to CORE. It now **brings an existing key to exactly the wanted scopes in place, keeping the secret**, and says so: a warning in the log (`API key 'core-hud' scopes updated in place (same secret): added ['rules:read'], removed none`) and the status `scopes-updated`. It also takes scopes away (so a scope removed from the list is removed from running keys), and it never touches an inactive key, a key of another name, or a key in another tenant. CORE re-runs this bootstrap, so an upgraded deployment picks the scope up automatically.

## Keeping the two repos honest

Before there was a test, **six of Cipher's seventeen tools were found sending requests AiSOC does not accept** (a wrong field name, a missing body, a filter on a route that has none). Now:

* `tests/test_cipher_tool_contract.py` checks every row of `CIPHER_CALLS`: the route exists, the key's scopes cover the permission it needs, every query name is one the route reads, the body is what the route expects. A tool that only reads must never need a write permission.
* The twelve read tools are declared in CORE as a table (`hud/src/aisoc-read-tools.ts`). CORE commits a contract file generated from it (`hud/contracts/aisoc-read-tools.json`) and tests that it is current; this repo keeps a copy (`tests/fixtures/core_read_tools.json`) and tests its own table against it, and against CORE's file when the CORE repo is checked out beside this one. A tool changed on one side fails a test until the other side matches.

## Adding a read tool

1. In CORE, add a row to `READ_TOOLS` (path, validated arguments, limits), regenerate the contract file (`UPDATE_AISOC_CONTRACT=1 node --test dist/aisoc-read-tools-contract.test.js`).
2. Copy it to `tests/fixtures/core_read_tools.json` here and add the row to `CIPHER_CALLS`. The tests then tell you if the route is missing, a query name is wrong, or the permission needed is not in `CORE_KEY_SCOPES`.
3. If a scope is needed, add it to `CORE_KEY_SCOPES` **only if it grants nothing but reading** (check what else the permission guards: `lake:query` is the example of one that does not qualify). Existing deployments pick it up the next time bootstrap runs.

## Not built yet

Hunting (waiting on a read-only hunts permission), posture and compliance, identity and insider threat, threat intelligence, MSSP and platform operations, and the generated capability reference that would let Cipher know every area of AiSOC. Cipher has no new write tools.
