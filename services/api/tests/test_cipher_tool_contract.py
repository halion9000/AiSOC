"""Cipher (CORE's agent) operates AiSOC through 29 tools: 17 written out by hand and 12 read-only detection-engineering tools declared as a table in CORE (hud/src/aisoc-read-tools.ts). Every call they make must be one this API actually accepts.

CORE builds the requests in hud/src/aisoc-requests.ts and pins them in hud/src/aisoc-requests.test.ts. Comparing every call with this API's own
OpenAPI schema on 2026-10-08 found six tools sending requests AiSOC did not understand, which no test on either side had noticed because nothing
ever looked at what was actually sent:

  aisoc_comment_case          sent {content}; this API requires {body}                         -> a 422 on every call
  aisoc_launch_investigation  sent no body; this route requires a JSON object                  -> a 422 on every call
  aisoc_close_investigation   sent no body; this route requires a JSON object                  -> a 422 on every call
  aisoc_snooze_alert          sent duration_hours; this API reads duration_minutes / until     -> duration silently ignored
  aisoc_list_alerts           sent severity/status/limit to /alerts/queue (owner/period/page/
                              page_size only)                                                  -> every filter silently ignored
  aisoc_escalate_alert        sends {reason}; the route takes no body                          -> the reason is not stored

CIPHER_CALLS below is what CORE sends. If this API changes a route Cipher depends on, this fails HERE, not as a confusing error the first time an
analyst agent tries the tool. If CORE changes a request, update this table together with hud/src/aisoc-requests.test.ts.
"""
from __future__ import annotations

import re
import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.main import app
from app.scripts.bootstrap_production import CORE_KEY_SCOPES
from fastapi import HTTPException
from fastapi.routing import APIRoute
from route_introspect import required_permissions

# (tool, METHOD, path relative to /api/v1, query parameter names sent, body)
#   body: None            -> no body is sent
#         ["a", "b"]      -> a JSON object with these keys (an empty list is `{}`)
#   ignored_body: True    -> the route declares no body, so what is sent is knowingly ignored
CIPHER_CALLS = [
    ("aisoc_alert_stats", "GET", "/alerts/stats", [], None, False),
    ("aisoc_list_alerts (triage queue)", "GET", "/alerts/queue", ["page_size", "page"], None, False),
    ("aisoc_list_alerts (filtered)", "GET", "/alerts", ["severity", "status", "page_size", "page"], None, False),
    ("aisoc_get_alert", "GET", "/alerts/{id}", [], None, False),
    ("aisoc_list_cases", "GET", "/cases", ["limit", "status"], None, False),
    ("aisoc_get_case", "GET", "/cases/{id}", [], None, False),
    ("aisoc_list_investigations", "GET", "/investigations", [], None, False),
    ("aisoc_get_investigation", "GET", "/investigations/{id}", [], None, False),
    ("aisoc_connector_catalog", "GET", "/connectors/catalog", [], None, False),
    ("aisoc_connector_health", "GET", "/connectors/health", [], None, False),
    ("aisoc_list_connectors", "GET", "/connectors", [], None, False),
    ("aisoc_claim_alert", "POST", "/alerts/{id}/claim", [], None, False),
    ("aisoc_snooze_alert", "POST", "/alerts/{id}/snooze", [], ["reason", "duration_minutes"], False),
    ("aisoc_comment_case", "POST", "/cases/{id}/comments", [], ["body"], False),
    ("aisoc_launch_investigation", "POST", "/cases/{id}/investigate", [], [], False),
    ("aisoc_update_case", "PATCH", "/cases/{id}", [], ["status"], False),
    ("aisoc_escalate_alert", "POST", "/alerts/{id}/escalate", [], ["reason"], True),
    ("aisoc_close_investigation", "POST", "/investigations/{id}/close", [], ["analyst_note"], False),
    # The read-only tools declared in CORE's hud/src/aisoc-read-tools.ts (detection engineering). Same names, paths and query parameters as that table; a path parameter is written
    # with the route's own name so the lookup below finds exactly that route and not a literal sibling (/detection-proposals/baselines also fits /detection-proposals/{id}).
    ("aisoc_detection_coverage", "GET", "/detection/coverage", [], None, False),
    ("aisoc_detection_drift", "GET", "/detection/drift", [], None, False),
    ("aisoc_detection_confidence", "GET", "/detection/confidence", [], None, False),
    ("aisoc_tuning_summary", "GET", "/detection/tuning/summary", [], None, False),
    ("aisoc_tuning_workbench", "GET", "/detection/tuning", ["severity", "suggestion", "search", "enabled_only", "include_dismissed"], None, False),
    ("aisoc_list_rules", "GET", "/rules", ["category", "rule_language", "include_builtin", "include_packs"], None, False),
    ("aisoc_get_rule", "GET", "/rules/{rule_id}", [], None, False),
    ("aisoc_list_detection_proposals", "GET", "/detection-proposals", ["status", "limit"], None, False),
    ("aisoc_get_detection_proposal", "GET", "/detection-proposals/{proposal_id}", [], None, False),
    ("aisoc_detection_baselines", "GET", "/detection-proposals/baselines", ["suite"], None, False),
    ("aisoc_list_sigma_suggestions", "GET", "/detection-loop/suggestions", [], None, False),
    ("aisoc_get_sigma_suggestion", "GET", "/detection-loop/suggestions/{suggestion_id}", [], None, False),
]
CALL_IDS = [c[0] for c in CIPHER_CALLS]
MAX_PAGE_SIZE_CORE_SENDS = 200  # hud/src/aisoc-requests.ts: MAX_PAGE_SIZE


def _walk(routes, include_prefix=""):
    """This app mounts its routers lazily (_IncludedRouter), which app.routes does not flatten."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield include_prefix + route.path, route
        elif hasattr(route, "original_router"):
            context = getattr(route, "include_context", None)
            yield from _walk(route.original_router.routes, include_prefix + (getattr(context, "prefix", "") or ""))


def _strip(path: str) -> str:
    return re.sub(r"^/api/v1", "", path)


def _matches(template: str, path: str) -> bool:
    return re.fullmatch(re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)), path) is not None


ROUTES = [(_strip(p), r) for p, r in _walk(app.routes)]
SPEC = app.openapi()
COMPONENTS = SPEC["components"]["schemas"]
CORE_KEY = CurrentUser(uuid.uuid4(), uuid.uuid4(), "admin", "core-hud@example.com", scopes=list(CORE_KEY_SCOPES))


def _resolve(schema):
    schema = schema or {}
    while "$ref" in schema:
        schema = COMPONENTS[schema["$ref"].split("/")[-1]]
    if "anyOf" in schema:
        schema = _resolve(schema["anyOf"][0])
    return schema


def _operation(method: str, template: str) -> dict:
    for path, ops in SPEC["paths"].items():  # the route written exactly as the template first: a wildcard can also fit a literal sibling
        if _strip(path) == template and method.lower() in ops:
            return ops[method.lower()]
    for path, ops in SPEC["paths"].items():
        if _matches(template, _strip(path)) and method.lower() in ops:
            return ops[method.lower()]
    raise AssertionError(f"{method} {template}: no such route in this API")


def _route(method: str, template: str) -> APIRoute:
    exact = [r for p, r in ROUTES if p == template and method in r.methods]
    if exact:  # see _operation: the route written exactly as the template wins over a wildcard match
        return exact[0]
    found = [r for p, r in ROUTES if _matches(template, p) and method in r.methods]
    assert found, f"{method} {template}: no such route in this API"
    return found[0]


def _case(name: str):
    return next(c for c in CIPHER_CALLS if c[0] == name)


@pytest.mark.parametrize("name", CALL_IDS)
def test_the_route_exists(name):
    _tool, method, path, *_ = _case(name)
    _route(method, path)
    _operation(method, path)


@pytest.mark.parametrize("name", CALL_IDS)
def test_core_s_key_holds_the_permission_the_route_needs(name):
    """CORE's key is least-privilege on purpose. A route that needs a scope it lacks would be a 403 every time."""
    _tool, method, path, *_ = _case(name)
    for permission in required_permissions(_route(method, path)):
        try:
            CORE_KEY.require_permission(permission)
        except HTTPException as exc:
            raise AssertionError(f"{name} ({method} {path}) needs {permission}, which CORE's key ({CORE_KEY_SCOPES}) lacks: {exc.detail}") from exc


@pytest.mark.parametrize("name", CALL_IDS)
def test_every_query_parameter_sent_is_one_the_route_reads(name):
    """FastAPI silently ignores an unknown query parameter, so a wrong name is a filter that quietly does nothing."""
    _tool, method, path, query, *_ = _case(name)
    accepted = {p["name"] for p in _operation(method, path).get("parameters", []) if p["in"] == "query"}
    assert set(query) <= accepted, f"{name} sends {sorted(set(query) - accepted)}, which {method} {path} ignores (it reads {sorted(accepted)})"


@pytest.mark.parametrize("name", CALL_IDS)
def test_the_body_is_what_the_route_expects(name):
    _tool, method, path, _query, body, ignored = _case(name)
    request_body = _operation(method, path).get("requestBody")
    if request_body is None:
        assert body is None or ignored, f"{name} sends a body ({body}) but {method} {path} takes none; mark it ignored only if that is intended"
        return
    assert not ignored, f"{name} is marked as sending an ignored body, but {method} {path} now declares one: map the fields"
    schema = _resolve(request_body["content"]["application/json"]["schema"])
    if request_body.get("required"):
        assert body is not None, f"{name} sends no body, but {method} {path} requires a JSON body (an empty object is valid): a 422 on every call"
    if body is None:
        return
    fields = set(schema.get("properties", {}))
    assert set(body) <= fields, f"{name} sends {sorted(set(body) - fields)}, which {method} {path} does not read (it reads {sorted(fields)})"
    missing = set(schema.get("required", [])) - set(body)
    assert not missing, f"{name} omits {sorted(missing)}, which {method} {path} requires: a 422 on every call"


@pytest.mark.parametrize("path", ["/alerts/queue", "/alerts"])
def test_the_page_size_cap_is_at_least_what_core_sends(path):
    """CORE clamps page_size to 200; if this API lowered its cap, a large request would be a 422."""
    parameters = _operation("GET", path)["parameters"]
    page_size = next(p for p in parameters if p["name"] == "page_size")
    assert page_size["schema"].get("maximum", 10**9) >= MAX_PAGE_SIZE_CORE_SENDS


def test_the_table_covers_all_twenty_nine_tools():
    tools = {re.sub(r" \(.*\)$", "", name) for name in CALL_IDS}
    assert len(tools) == 29, sorted(tools)


READ_ONLY_TOOLS = [c for c in CIPHER_CALLS if c[1] == "GET"]


@pytest.mark.parametrize("name", [c[0] for c in READ_ONLY_TOOLS])
def test_a_tool_that_only_reads_never_needs_a_permission_that_writes(name):
    """A GET tool must not need `:write`, `:delete`, `:execute` or `lake:query` (which is one permission for hunting's reads, writes and arbitrary queries): CORE's key is least privilege on purpose."""
    _tool, method, path, *_ = _case(name)
    for permission in required_permissions(_route(method, path)):
        assert not permission.endswith((":write", ":delete", ":execute")) and permission != "lake:query", f"{name} ({method} {path}) needs {permission}"


@pytest.mark.parametrize("name", [c[0] for c in READ_ONLY_TOOLS])
def test_a_read_tool_resolves_to_exactly_the_route_it_names(name):
    """The wildcard lookup used to be able to check a different route than the one named; every path here must be found written exactly as it is."""
    _tool, method, path, *_ = _case(name)
    if "{id}" in path:
        pytest.skip("older rows use {id} as a wildcard")
    assert path in {p for p, _ in ROUTES}, f"{method} {path} is not a route of this API as written"


def test_a_tool_that_reads_one_item_cannot_be_confused_with_a_literal_sibling_route():
    """/detection-proposals/baselines and /detection-proposals/{proposal_id} both fit the wildcard; each tool must resolve to its own route."""
    assert _route("GET", "/detection-proposals/baselines").path.endswith("/baselines")
    assert _route("GET", "/detection-proposals/{proposal_id}").path.endswith("{proposal_id}")
    assert _operation("GET", "/detection-proposals/baselines")["operationId"] != _operation("GET", "/detection-proposals/{proposal_id}")["operationId"]


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------
# The shared contract with CORE: hud/contracts/aisoc-read-tools.json in the CORE repo (copied to tests/fixtures/core_read_tools.json). CORE tests its tool table against ITS file;
# this tests THIS table against the copy. A tool changed on one side fails a test until the other side matches, so the two cannot drift apart unnoticed
# (before a table like this existed, six of seventeen tools were found sending requests AiSOC does not accept).
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------
import json  # noqa: E402
from pathlib import Path  # noqa: E402

CONTRACT = json.loads((Path(__file__).parent / "fixtures" / "core_read_tools.json").read_text(encoding="utf-8"))
CORE_CHECKOUT_CONTRACT = Path(__file__).resolve().parents[3].parent / "Jarvis" / "hud" / "contracts" / "aisoc-read-tools.json"


def test_this_table_lists_exactly_the_read_tools_core_declares_with_the_same_path_and_query_names():
    mine = {name: (method, path, query) for name, method, path, query, _body, _ignored in CIPHER_CALLS if name in {r["tool"] for r in CONTRACT}}
    assert set(mine) == {r["tool"] for r in CONTRACT}, f"CORE declares tools this table lacks: {sorted({r['tool'] for r in CONTRACT} - set(mine))}"
    for row in CONTRACT:
        assert mine[row["tool"]] == (row["method"], row["path"], row["query"]), f"{row['tool']}: CORE sends {row['method']} {row['path']} {row['query']}, this table says {mine[row['tool']]}"


def test_every_tool_in_the_contract_is_a_get():
    assert all(r["method"] == "GET" for r in CONTRACT)


def test_the_contract_has_no_tool_listed_twice():
    names = [r["tool"] for r in CONTRACT]
    assert len(names) == len(set(names)) == 12


def test_the_copy_is_the_same_as_the_file_in_the_core_checkout_when_one_is_next_to_this_repo():
    """Only when the CORE repo is checked out beside this one (it is on the machine that develops both); otherwise there is nothing to compare."""
    if not CORE_CHECKOUT_CONTRACT.exists():
        pytest.skip("no CORE checkout next to this repository")
    assert json.loads(CORE_CHECKOUT_CONTRACT.read_text(encoding="utf-8")) == CONTRACT, "tests/fixtures/core_read_tools.json is out of date: copy hud/contracts/aisoc-read-tools.json from the CORE repo and update CIPHER_CALLS"
