"""Cipher (CORE's agent) operates AiSOC through 17 tools. Every call they make must be one this API actually accepts.

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
    for path, ops in SPEC["paths"].items():
        if _matches(template, _strip(path)) and method.lower() in ops:
            return ops[method.lower()]
    raise AssertionError(f"{method} {template}: no such route in this API")


def _route(method: str, template: str) -> APIRoute:
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


def test_the_table_covers_all_seventeen_tools():
    tools = {re.sub(r" \(.*\)$", "", name) for name in CALL_IDS}
    assert len(tools) == 17, sorted(tools)
