"""Cipher (CORE's agent) operates AiSOC through 53 tools: 17 written out by hand and 36 read-only tools (12 detection engineering, 5
hunting, 5 threat intelligence, 11 estate: assets, vulnerabilities, cloud posture, identity graph, client devices) declared as a table in CORE
(hud/src/aisoc-read-tools.ts). Every call they make must be one this API actually accepts.

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
    ("aisoc_list_alerts (filtered)", "GET", "/alerts", ["severity", "status", "search", "source", "page_size", "page"], None, False),
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
    # The read-only tools declared in CORE's hud/src/aisoc-read-tools.ts (detection engineering). Same names, paths and query parameters as
    # that table; a path parameter is written
    # with the route's own name so the lookup below finds exactly that route and not a literal sibling (/detection-proposals/baselines also
    # fits /detection-proposals/{id}).
    ("aisoc_detection_coverage", "GET", "/detection/coverage", [], None, False),
    ("aisoc_detection_drift", "GET", "/detection/drift", [], None, False),
    ("aisoc_detection_confidence", "GET", "/detection/confidence", [], None, False),
    ("aisoc_tuning_summary", "GET", "/detection/tuning/summary", [], None, False),
    (
        "aisoc_tuning_workbench",
        "GET",
        "/detection/tuning",
        ["severity", "suggestion", "search", "enabled_only", "include_dismissed", "page", "page_size"],
        None,
        False,
    ),  # noqa: E501
    ("aisoc_list_rules", "GET", "/rules", ["category", "rule_language", "include_builtin", "include_packs"], None, False),
    ("aisoc_get_rule", "GET", "/rules/{rule_id}", [], None, False),
    ("aisoc_list_detection_proposals", "GET", "/detection-proposals", ["status", "limit"], None, False),
    ("aisoc_get_detection_proposal", "GET", "/detection-proposals/{proposal_id}", [], None, False),
    ("aisoc_detection_baselines", "GET", "/detection-proposals/baselines", ["suite"], None, False),
    ("aisoc_list_sigma_suggestions", "GET", "/detection-loop/suggestions", [], None, False),
    ("aisoc_get_sigma_suggestion", "GET", "/detection-loop/suggestions/{suggestion_id}", [], None, False),
    # Hunting: the DEFINITIONS of hunts (permission hunts:read). GET /hunts/{id}/runs (sampled event rows) is deliberately NOT here: it
    # needs lake:query, which CORE's key does not hold.
    ("aisoc_list_hunts", "GET", "/hunts", ["status", "priority", "limit", "offset"], None, False),
    ("aisoc_get_hunt", "GET", "/hunts/{hunt_id}", [], None, False),
    ("aisoc_list_saved_hunts", "GET", "/saved-hunts", [], None, False),
    ("aisoc_get_saved_hunt", "GET", "/saved-hunts/{hunt_id}", [], None, False),
    ("aisoc_list_saved_searches", "GET", "/hunt/saved", [], None, False),
    # Threat intelligence: INTERNAL data (permission intel:read, the narrow read half of threat_intel:read). GET /enrichment/lookup and POST
    # /enrichment/bulk (indicators sent to outside providers: egress and quota) are deliberately NOT here although they need only
    # threat_intel:read, nor are /threat-intel/feeds (a feed's `config` can hold credentials), MISP health (an outside call) or the TAXII
    # collections (an empty stub).
    ("aisoc_list_iocs", "GET", "/threat-intel/iocs", ["ioc_type", "severity", "is_active", "limit", "offset"], None, False),
    ("aisoc_get_ioc", "GET", "/threat-intel/iocs/{ioc_id}", [], None, False),
    ("aisoc_list_threat_actors", "GET", "/threat-intel/actors", ["is_active", "limit", "offset"], None, False),
    ("aisoc_list_stix_indicators", "GET", "/threatintel/stix/indicators", ["label"], None, False),
    ("aisoc_list_stix_bundles", "GET", "/threatintel/stix/bundles", [], None, False),
    # The estate (permission alerts:read, which CORE's key already holds: no new scope). NOT here on purpose: /insider-threat (per-employee
    # risk scores, indicators and watchlists: HR-sensitive), /compliance (needs reports:read, and GET /compliance/report writes a record)
    # and the effective-permissions resolver.
    (
        "aisoc_list_devices",
        "GET",
        "/devices",
        ["client_id", "search", "missing", "attention", "stale", "not_in_master", "offline", "has_alerts", "page_size", "page"],
        None,
        False,
    ),
    ("aisoc_list_assets", "GET", "/assets", ["asset_type", "criticality", "limit", "offset"], None, False),
    ("aisoc_get_asset", "GET", "/assets/{asset_id}", [], None, False),
    ("aisoc_list_vulnerabilities", "GET", "/assets/vulnerabilities", ["severity", "is_exploited", "limit", "offset"], None, False),
    ("aisoc_get_asset_vulnerabilities", "GET", "/assets/{asset_id}/vulnerabilities", [], None, False),
    ("aisoc_posture_summary", "GET", "/posture/summary", ["cloud_provider"], None, False),
    (
        "aisoc_list_posture_findings",
        "GET",
        "/posture/findings",
        ["cloud_provider", "severity", "status", "rule_id", "limit", "offset"],
        None,
        False,
    ),  # noqa: E501
    ("aisoc_get_posture_finding", "GET", "/posture/findings/{finding_id}", [], None, False),
    ("aisoc_list_posture_scans", "GET", "/posture/scans", ["limit", "offset"], None, False),
    ("aisoc_list_identity_nodes", "GET", "/identity-graph/nodes", ["node_type", "source_system", "limit", "offset"], None, False),
    ("aisoc_get_identity_node", "GET", "/identity-graph/nodes/{node_id}", [], None, False),
    ("aisoc_platform_health", "GET", "/health/services", [], None, False),
    ("aisoc_entity_risk_stats", "GET", "/fusion/entity-risk/stats", ["tenant_id"], None, False),
    ("aisoc_entity_risk_queue", "GET", "/fusion/entity-risk/queue", ["tenant_id", "limit", "promoted_only"], None, False),
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
            raise AssertionError(
                f"{name} ({method} {path}) needs {permission}, which CORE's key ({CORE_KEY_SCOPES}) lacks: {exc.detail}"
            ) from exc


@pytest.mark.parametrize("name", CALL_IDS)
def test_every_query_parameter_sent_is_one_the_route_reads(name):
    """FastAPI silently ignores an unknown query parameter, so a wrong name is a filter that quietly does nothing."""
    _tool, method, path, query, *_ = _case(name)
    accepted = {p["name"] for p in _operation(method, path).get("parameters", []) if p["in"] == "query"}
    assert (
        set(query) <= accepted
    ), f"{name} sends {sorted(set(query) - accepted)}, which {method} {path} ignores (it reads {sorted(accepted)})"


@pytest.mark.parametrize("name", CALL_IDS)
def test_the_body_is_what_the_route_expects(name):
    _tool, method, path, _query, body, ignored = _case(name)
    request_body = _operation(method, path).get("requestBody")
    if request_body is None:
        assert (
            body is None or ignored
        ), f"{name} sends a body ({body}) but {method} {path} takes none; mark it ignored only if that is intended"
        return
    assert not ignored, f"{name} is marked as sending an ignored body, but {method} {path} now declares one: map the fields"
    schema = _resolve(request_body["content"]["application/json"]["schema"])
    if request_body.get("required"):
        assert (
            body is not None
        ), f"{name} sends no body, but {method} {path} requires a JSON body (an empty object is valid): a 422 on every call"
    if body is None:
        return
    fields = set(schema.get("properties", {}))
    assert (
        set(body) <= fields
    ), f"{name} sends {sorted(set(body) - fields)}, which {method} {path} does not read (it reads {sorted(fields)})"
    missing = set(schema.get("required", [])) - set(body)
    assert not missing, f"{name} omits {sorted(missing)}, which {method} {path} requires: a 422 on every call"


@pytest.mark.parametrize("path", ["/alerts/queue", "/alerts"])
def test_the_page_size_cap_is_at_least_what_core_sends(path):
    """CORE clamps page_size to 200; if this API lowered its cap, a large request would be a 422."""
    parameters = _operation("GET", path)["parameters"]
    page_size = next(p for p in parameters if p["name"] == "page_size")
    assert page_size["schema"].get("maximum", 10**9) >= MAX_PAGE_SIZE_CORE_SENDS


def test_the_table_covers_all_fifty_three_tools():
    tools = {re.sub(r" \(.*\)$", "", name) for name in CALL_IDS}
    assert len(tools) == 53, sorted(tools)


READ_ONLY_TOOLS = [c for c in CIPHER_CALLS if c[1] == "GET"]


@pytest.mark.parametrize("name", [c[0] for c in READ_ONLY_TOOLS])
def test_a_tool_that_only_reads_never_needs_a_permission_that_writes(name):
    """A GET tool must not need `:write`, `:delete`, `:execute` or `lake:query` (which is one permission for hunting's reads, writes and
    arbitrary queries): CORE's key is least privilege on purpose."""
    _tool, method, path, *_ = _case(name)
    for permission in required_permissions(_route(method, path)):
        assert (
            not permission.endswith((":write", ":delete", ":execute")) and permission != "lake:query"
        ), f"{name} ({method} {path}) needs {permission}"  # noqa: E501


@pytest.mark.parametrize("name", [c[0] for c in READ_ONLY_TOOLS])
def test_a_read_tool_resolves_to_exactly_the_route_it_names(name):
    """The wildcard lookup used to be able to check a different route than the one named; every path here must be found written exactly as
    it is."""
    _tool, method, path, *_ = _case(name)
    if "{id}" in path:
        pytest.skip("older rows use {id} as a wildcard")
    assert path in {p for p, _ in ROUTES}, f"{method} {path} is not a route of this API as written"


def test_a_tool_that_reads_one_item_cannot_be_confused_with_a_literal_sibling_route():
    """/detection-proposals/baselines and /detection-proposals/{proposal_id} both fit the wildcard; each tool must resolve to its own route."""  # noqa: E501
    assert _route("GET", "/detection-proposals/baselines").path.endswith("/baselines")
    assert _route("GET", "/detection-proposals/{proposal_id}").path.endswith("{proposal_id}")
    assert (
        _operation("GET", "/detection-proposals/baselines")["operationId"]
        != _operation("GET", "/detection-proposals/{proposal_id}")["operationId"]
    )  # noqa: E501


# ------------------------------------------------------------------------------------------------------------------------
# The shared contract with CORE: hud/contracts/aisoc-read-tools.json in the CORE repo (copied to tests/fixtures/core_read_tools.json).
# CORE tests its tool table against ITS file; this tests THIS table against the copy. A tool changed on one side fails a test until the
# other side matches, so the two cannot drift apart unnoticed (before a table like this existed, six of seventeen tools were found sending
# requests AiSOC does not accept).
# ------------------------------------------------------------------------------------------------------------------------
import json  # noqa: E402
from pathlib import Path  # noqa: E402

CONTRACT = json.loads((Path(__file__).parent / "fixtures" / "core_read_tools.json").read_text(encoding="utf-8"))
CORE_CHECKOUT_CONTRACT = Path(__file__).resolve().parents[3].parent / "Jarvis" / "hud" / "contracts" / "aisoc-read-tools.json"


def test_this_table_lists_exactly_the_read_tools_core_declares_with_the_same_path_and_query_names():
    mine = {
        name: (method, path, query) for name, method, path, query, _body, _ignored in CIPHER_CALLS if name in {r["tool"] for r in CONTRACT}
    }  # noqa: E501
    assert set(mine) == {
        r["tool"] for r in CONTRACT
    }, f"CORE declares tools this table lacks: {sorted({r['tool'] for r in CONTRACT} - set(mine))}"  # noqa: E501
    for row in CONTRACT:
        assert mine[row["tool"]] == (
            row["method"],
            row["path"],
            row["query"],
        ), f"{row['tool']}: CORE sends {row['method']} {row['path']} {row['query']}, this table says {mine[row['tool']]}"  # noqa: E501


def test_every_tool_in_the_contract_is_a_get():
    assert all(r["method"] == "GET" for r in CONTRACT)


def test_the_contract_has_no_tool_listed_twice():
    names = [r["tool"] for r in CONTRACT]
    assert len(names) == len(set(names)) == 36


def test_the_copy_is_the_same_as_the_file_in_the_core_checkout_when_one_is_next_to_this_repo():
    """Only when the CORE repo is checked out beside this one (it is on the machine that develops both); otherwise there is nothing to
    compare."""
    if not CORE_CHECKOUT_CONTRACT.exists():
        pytest.skip("no CORE checkout next to this repository")
    assert (
        json.loads(CORE_CHECKOUT_CONTRACT.read_text(encoding="utf-8")) == CONTRACT
    ), "tests/fixtures/core_read_tools.json is out of date: copy hud/contracts/aisoc-read-tools.json from the CORE repo and update CIPHER_CALLS"  # noqa: E501


def _query_parameters(row) -> dict:
    return {p["name"]: p for p in _operation(row["method"], row["path"]).get("parameters", []) if p["in"] == "query"}


_SIMPLE_ALTERNATION = re.compile(r"^\^\(([A-Za-z0-9_-]+(?:\|[A-Za-z0-9_-]+)*)\)\$$")


def _allowed_values(schema):
    """The values the API accepts for a parameter: an OpenAPI enum, or a pattern that is exactly a list of alternatives (^(a|b)$), which
    is how a FastAPI query parameter written with `pattern=` shows up. Anything more elaborate is None (open text)."""
    schema = _resolve(schema)
    if "enum" in schema:
        return set(schema["enum"])
    for option in schema.get("anyOf", []):
        found = _allowed_values(option)
        if found is not None:
            return found
    match = _SIMPLE_ALTERNATION.match(schema.get("pattern", ""))
    return set(match.group(1).split("|")) if match else None


@pytest.mark.parametrize("row", CONTRACT, ids=[r["tool"] for r in CONTRACT])
def test_the_values_a_tool_allows_are_exactly_the_values_the_api_accepts(row):
    """A tool that offers free text for a parameter the API restricts to a set only finds out at AiSOC (a 422); one that allows a different
    set is wrong either way."""
    params = _query_parameters(row)
    for name, values in row["enums"].items():
        api_enum = _allowed_values(params[name]["schema"])
        assert api_enum is not None, f"{row['tool']}.{name} is restricted to {values} by the tool, but {row['path']} accepts any value"
        assert set(api_enum) == set(values), f"{row['tool']}.{name}: the tool allows {sorted(values)}, the API accepts {sorted(api_enum)}"
    for name in row["query"]:
        api_enum = _allowed_values(params[name]["schema"])
        if api_enum is not None:
            assert (
                name in row["enums"]
            ), f"{row['tool']}.{name} is free text in the tool, but the API accepts only {sorted(api_enum)}: declare them in the tool's table"  # noqa: E501


@pytest.mark.parametrize("row", [r for r in CONTRACT if r["numbers"]], ids=[r["tool"] for r in CONTRACT if r["numbers"]])
def test_a_tools_numeric_clamp_never_sends_more_or_less_than_the_api_accepts(row):
    """The tool clamps (so a careless number is not an error); the clamp must stay inside what the API accepts or it would become a 422
    anyway."""
    params = _query_parameters(row)
    for name, bounds in row["numbers"].items():
        schema = _resolve(params[name]["schema"])
        assert schema.get("type") == "integer", f"{row['tool']}.{name} is a number in the tool but {schema.get('type')} in the API"
        if "maximum" in schema:
            assert (
                bounds["max"] <= schema["maximum"]
            ), f"{row['tool']}.{name}: the tool sends up to {bounds['max']}, the API accepts at most {schema['maximum']}"  # noqa: E501
        assert bounds["min"] >= schema.get(
            "minimum", 0
        ), f"{row['tool']}.{name}: the tool sends as low as {bounds['min']}, the API accepts at least {schema.get('minimum', 0)}"  # noqa: E501


def test_the_paged_workbench_can_be_paged_and_the_sizes_match():
    row = next(r for r in CONTRACT if r["tool"] == "aisoc_tuning_workbench")
    assert {"page", "page_size"} <= set(
        row["query"]
    ), "the workbench is paged: without these Cipher sees only the first page and cannot know"  # noqa: E501
    schema = _resolve(_query_parameters(row)["page_size"]["schema"])
    assert schema["maximum"] == row["numbers"]["page_size"]["max"] == 100


HUNTING_TOOLS = ["aisoc_list_hunts", "aisoc_get_hunt", "aisoc_list_saved_hunts", "aisoc_get_saved_hunt", "aisoc_list_saved_searches"]


@pytest.mark.parametrize("name", HUNTING_TOOLS)
def test_a_hunting_tool_needs_exactly_hunts_read_and_nothing_that_queries_telemetry(name):
    """The hunting tools read DEFINITIONS. If one ever needed lake:query it would be reading telemetry (or could be used to run something),
    which CORE's key must not hold."""
    _tool, method, path, *_ = _case(name)
    assert set(required_permissions(_route(method, path))) == {"hunts:read"}, f"{name}: {method} {path}"
    assert "lake:query" not in CORE_KEY_SCOPES and "hunts:read" in CORE_KEY_SCOPES


def test_no_tool_in_the_table_can_reach_a_run_a_result_or_a_query():
    """Run results are event rows from the lake; running is a write. No Cipher tool, hand-written or declared, may name such a route."""
    for name, method, path, *_ in CIPHER_CALLS:
        for forbidden in (
            "/runs",
            "/run",
            "/execute",
            "/nl-query",
            "/lake",
            "/translate",
            "/backtest",
            "/enrichment",
            "/feeds",
            "/misp",
            "/taxii",
            "/insider-threat",
            "/compliance",
            "/effective-permissions",
        ):  # noqa: E501
            assert forbidden not in path, f"{name} ({method} {path}) reaches a route containing {forbidden}"


def test_the_hunt_list_limit_and_offset_the_tool_sends_are_within_what_the_api_accepts():
    params = {p["name"]: _resolve(p["schema"]) for p in _operation("GET", "/hunts")["parameters"] if p["in"] == "query"}
    assert params["limit"]["maximum"] >= 200 and params["limit"]["minimum"] <= 1
    # The API now caps offset at 1,000,000 (an unbounded offset overflowed Postgres: see test_integer_query_params_are_bounded.py). The tool
    # allows offsets up to 100,000, so the cap must stay at or above that; if it is ever lowered below, the tool's bound must follow.
    assert (
        params["offset"]["minimum"] == 0 and params["offset"].get("maximum", float("inf")) >= 100_000
    ), "the tool allows offsets up to 100000; the API's maximum must not be lower"  # noqa: E501


INTEL_TOOLS = ["aisoc_list_iocs", "aisoc_get_ioc", "aisoc_list_threat_actors", "aisoc_list_stix_indicators", "aisoc_list_stix_bundles"]


@pytest.mark.parametrize("name", INTEL_TOOLS)
def test_a_threat_intelligence_tool_needs_exactly_intel_read(name):
    """The intelligence tools read this tenant's own stored intelligence through the NARROW intel:read, split out of threat_intel:read
    (which also guards the feed list and enrichment). The key holds neither threat_intel:read nor threat_intel:write."""
    _tool, method, path, *_ = _case(name)
    assert method == "GET" and set(required_permissions(_route(method, path))) == {"intel:read"}, f"{name}: {method} {path}"
    assert "intel:read" in CORE_KEY_SCOPES and "threat_intel:read" not in CORE_KEY_SCOPES and "threat_intel:write" not in CORE_KEY_SCOPES


@pytest.mark.parametrize("method,path", [("GET", "/enrichment/lookup"), ("POST", "/enrichment/bulk"), ("GET", "/threat-intel/feeds")])
def test_the_routes_that_send_indicators_outside_or_show_feed_credentials_are_out_of_the_keys_reach(method, path):
    """CLOSED (it was a known width for one commit): GET /enrichment/lookup and POST /enrichment/bulk send an indicator to outside
    providers, and GET /threat-intel/feeds shows each feed's free-form `config`, which can hold credentials. They still need
    threat_intel:read, and CORE's key no longer holds it: asserted with the same function every check uses, so an implication added later
    cannot quietly reopen it."""
    from app.core.security import permission_in

    assert set(required_permissions(_route(method, path))) == {"threat_intel:read"}
    assert not permission_in(CORE_KEY_SCOPES, "threat_intel:read"), "CORE's key would reach feeds and enrichment"
    assert all(not permission_in(CORE_KEY_SCOPES, p) for p in required_permissions(_route(method, path)))


def test_no_tool_reaches_the_enrichment_or_feed_routes_either():
    reachable = {(m, p) for _n, m, p, *_ in CIPHER_CALLS}
    assert ("GET", "/enrichment/lookup") not in reachable and ("POST", "/enrichment/bulk") not in reachable
    assert all("/feeds" not in p for _n, _m, p, *_ in CIPHER_CALLS)
    assert (
        "config" in SPEC["components"]["schemas"]["FeedOut"]["properties"]
    ), "FeedOut no longer has a free-form `config`: re-read why feeds are out of reach"  # noqa: E501


ESTATE_TOOLS = [
    "aisoc_list_assets",
    "aisoc_get_asset",
    "aisoc_list_vulnerabilities",
    "aisoc_get_asset_vulnerabilities",
    "aisoc_posture_summary",
    "aisoc_list_posture_findings",
    "aisoc_get_posture_finding",
    "aisoc_list_posture_scans",
    "aisoc_list_identity_nodes",
    "aisoc_get_identity_node",
    "aisoc_list_devices",  # noqa: E501
]


@pytest.mark.parametrize("name", ESTATE_TOOLS)
def test_an_estate_tool_is_a_get_that_needs_exactly_alerts_read_which_the_key_already_holds(name):
    """Assets, vulnerabilities, cloud posture and the identity graph are all alerts:read, so these eleven tools add NO scope and NO width to
    CORE's key."""
    _tool, method, path, *_ = _case(name)
    assert method == "GET" and set(required_permissions(_route(method, path))) == {"alerts:read"}, f"{name}: {method} {path}"
    assert "alerts:read" in CORE_KEY_SCOPES


def test_the_estate_routes_are_gets_with_no_side_effects_in_their_handlers():
    """A scan of each handler's source for a commit, an add, an outbound call or a trigger. Not a proof (a helper could hide one), but it is
    what was checked when these were chosen, and it fails if a handler grows one."""
    import inspect

    marker = re.compile(
        r"commit\(|\.add\(|httpx|requests\.|aiohttp|\.delete\(|flush\(|urlopen|socket|_run_scan|trigger|enqueue|send_|notify|\.post\(", re.I
    )  # noqa: E501
    for name in ESTATE_TOOLS:
        _tool, method, path, *_ = _case(name)
        source = inspect.getsource(_route(method, path).endpoint)
        assert not marker.search(
            source
        ), f"{name}: the handler for {method} {path} now looks like it does something besides read: {marker.search(source).group(0)}"  # noqa: E501


def test_the_sensitive_areas_have_no_tool_and_say_why_in_the_table():
    """Insider threat (per-employee risk scores, indicators, watchlists) and compliance (needs reports:read; GET /compliance/report writes a
    record) are deliberately out of reach."""
    for _n, _m, path, *_ in CIPHER_CALLS:
        assert not path.startswith(("/insider-threat", "/compliance", "/identity/")), path
    source = Path(__file__).read_text(encoding="utf-8")
    assert "HR-sensitive" in source and "writes a record" in source


def test_allowed_values_reads_an_enum_a_pattern_of_alternatives_and_an_optional_pattern():
    assert _allowed_values({"enum": ["a", "b"]}) == {"a", "b"}
    assert _allowed_values({"type": "string", "pattern": "^(addigy|threatmate)$"}) == {"addigy", "threatmate"}
    assert _allowed_values({"anyOf": [{"type": "string", "pattern": "^(x|y-z)$"}, {"type": "null"}]}) == {"x", "y-z"}


def test_allowed_values_treats_anything_more_elaborate_as_open_text():
    for schema in (
        {"type": "string"},
        {"type": "string", "pattern": "^[a-z]+$"},
        {"type": "string", "pattern": "^(a|b.*)$"},
        {"type": "string", "pattern": "(a|b)"},
        {"anyOf": [{"type": "integer"}, {"type": "null"}]},
    ):
        assert _allowed_values(schema) is None, schema


def test_the_devices_filter_values_are_the_ones_the_endpoint_really_accepts():
    row = next(r for r in CONTRACT if r["tool"] == "aisoc_list_devices")
    assert row["enums"] == {"missing": ["addigy", "threatmate", "huntress"]}
    assert _allowed_values(_query_parameters(row)["missing"]["schema"]) == {"addigy", "threatmate", "huntress"}


OPERATIONS_TOOLS = ["aisoc_entity_risk_stats", "aisoc_entity_risk_queue"]


@pytest.mark.parametrize("name", OPERATIONS_TOOLS)
def test_an_entity_risk_tool_is_a_get_that_needs_exactly_alerts_read_which_the_key_already_holds(name):
    """The entity-risk queue and stats are alerts:read: these tools add NO scope and NO width to CORE's key."""
    _tool, method, path, *_ = _case(name)
    assert method == "GET" and set(required_permissions(_route(method, path))) == {"alerts:read"}, f"{name}: {method} {path}"
    assert "alerts:read" in CORE_KEY_SCOPES


def test_the_platform_health_tool_needs_alerts_read_and_reads_service_names_and_status_only():
    """GET /health/services needs alerts:read (which the key already holds); it returns service names, up/down and latency, never a URL."""
    _tool, method, path, *_ = _case("aisoc_platform_health")
    assert method == "GET" and set(required_permissions(_route(method, path))) == {"alerts:read"}
    assert "alerts:read" in CORE_KEY_SCOPES
