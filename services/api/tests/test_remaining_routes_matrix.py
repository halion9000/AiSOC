"""Role x route and API-key-scope matrix for the last groups of login-only routes.

Each of these used to need only a login: a viewer could delete assets, ingest posture
findings, change the insider-threat watchlist, ingest into the knowledge base, trigger
external scans, or install community plugins. The table below is the INTENDED permission
for each route. It is checked against what the code really requires, and against the real
role table for every role.

No other service calls any of these routes (checked), so the only callers are the web
console and the agents service's read-only graph lookups (which hold alerts:read).
"""
import importlib
import re
import uuid

import httpx
import pytest
import respx
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.core.security import ROLE_PERMISSIONS, has_permission
from app.main import app
from route_introspect import required_permissions

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
ID = "00000000-0000-0000-0000-0000000000aa"
R, W, D = "alerts:read", "alerts:write", "alerts:delete"


def m(perm, *names):
    return {n: perm for n in names}


INTENDED = {
    "community": {**m("rules:write", "publish_detection", "install_community_detection"), **m("playbooks:write", "submit_playbook", "install_community_playbook"), **m("settings:write", "install_community_plugin")},
    "graph": {**m(R, "get_attack_path", "get_blast_radius", "get_mitre_coverage", "get_mitre_coverage_compat", "get_entity_neighbors"), **m(W, "upsert_alert_graph", "upsert_case_graph", "upsert_host", "upsert_user")},
    "posture": {**m(R, "list_findings", "get_finding", "list_scans", "get_summary"), **m(W, "ingest_finding", "resolve_finding", "suppress_finding"), **m("settings:write", "cspm_scan"), **m("settings:read", "destination_preview")},
    "assets": {**m(R, "list_assets", "list_vulnerabilities", "get_asset", "list_asset_vulnerabilities"), **m(W, "create_asset", "create_vulnerability", "update_asset"), **m(D, "delete_asset")},
    "identity_graph": {**m(R, "get_alert_identity_links", "list_edges", "list_nodes", "get_node", "get_node_edges"), **m(W, "link_alert_to_identity", "create_edge", "create_node")},
    "insider_threat": {**m(R, "list_indicators", "list_peer_groups", "list_profiles", "get_profile"), **m(W, "update_watchlist", "create_indicator", "acknowledge_indicator", "create_peer_group")},
    "hunts": m("lake:query", "list_hunts", "get_hunt", "list_runs", "update_hunt", "create_hunt", "add_findings", "run_hunt"),
    "saved_hunts": m("lake:query", "delete_saved_hunt", "list_saved_hunts", "get_saved_hunt", "create_saved_hunt", "run_saved_hunt"),
    "knowledge_base": {**m(R, "list_documents", "get_document", "query_kb"), **m("settings:write", "ingest", "delete_document")},
    "compliance": {**m("reports:read", "list_evidence", "get_evidence", "compliance_report"), **m("reports:write", "collect_evidence", "review_evidence")},
    "feedback": {**m(R, "list_overrides_endpoint", "get_override_summary"), **m(W, "submit_alert_override", "apply_redisposition_endpoint")},
    "metrics": m(R, "get_alert_trend", "get_dashboard_metrics", "get_funnel_metrics", "get_soc_metrics"),
    "phishing": {**m(R, "list_submissions", "get_submission"), **m(W, "retriage")},
    "detection_loop": {**m(R, "list_suggestions", "get_suggestion"), **m(W, "suggest_fp_fix")},
    "easm": {**m(R, "list_external_assets", "list_external_asset_drift"), **m("settings:write", "trigger_easm_scan")},
    "oncall": m(R, "list_oncall"),
    "approvals": m(R, "list_approvals", "get_approval"),
    "identity_timeline": {**m(R, "get_timeline"), **m(W, "build_timeline")},
    "effective_permissions": m(R, "list_providers", "get_effective_permissions"),
    "nl_query": m("lake:query", "execute_query", "translate_query"),
    "insights": m(R, "get_soc_insights"),
    "api_keys": m("users:read", "list_api_keys", "get_api_key"),
}

# Deliberately NOT guarded here (personal, public, or harmless to every login). Listed so
# the choice is visible and reviewed, not an oversight.
LEFT_LOGIN_ONLY = {
    "passkeys": "your own credentials",
    "saved_views": "your own saved filters",
    "push": "your own push subscription",
    "oncall (me)": "your own on-call settings",
    "auth (me)": "your own profile",
    "tenants (me)": "your own tenant's identity settings",
    "realtime ticket": "a ticket for your own live connection",
    "phishing submit": "any user may report a suspicious email",
    "community GETs + rate": "public community catalog; rating is harmless",
    "marketplace GETs": "catalog browsing",
    "health": "reachability / pipeline status",
}


def discover():
    rows = []
    for mod_name, handlers in INTENDED.items():
        module = importlib.import_module(f"app.api.v1.endpoints.{mod_name}")
        seen = set()
        for r in module.router.routes:
            if isinstance(r, APIRoute) and r.endpoint.__name__ in handlers:
                seen.add(r.endpoint.__name__)
                for method in sorted(r.methods - {"HEAD", "OPTIONS"}):
                    rows.append((mod_name, r, method, handlers[r.endpoint.__name__]))
        missing = set(handlers) - seen
        assert not missing, f"{mod_name}: handlers in the table that do not exist: {sorted(missing)}"
    return rows


ROWS = discover()
IDS = [f"{meth} {r.path}" for _, r, meth, _ in ROWS]
ROLES = list(ROLE_PERMISSIONS)


@pytest.fixture(autouse=True)
def _reset():
    yield
    app.dependency_overrides.clear()


def _client(user: CurrentUser) -> TestClient:
    async def fake_db():
        yield None

    app.dependency_overrides[deps.get_db] = fake_db
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def _user(role="viewer", scopes=None) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email="t@example.com", scopes=scopes)


def _call(client, method, route):
    path = "/api/v1" + re.sub(r"\{[^}]+\}", ID, route.path)
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        return client.request(method, path, json={}).status_code


def test_the_table_found_every_route():
    assert len(ROWS) >= 98


def test_every_route_requires_exactly_its_intended_permission():
    problems = []
    for mod_name, route, method, perm in ROWS:
        actual = required_permissions(route)
        if actual != [perm]:
            problems.append(f"{mod_name}: {method} {route.path} requires {actual or 'nothing beyond a login'}, intended [{perm}]")
    assert not problems, "\n  " + "\n  ".join(problems)


def test_deleting_an_asset_needs_the_delete_permission_not_just_write():
    """A lead or analyst may edit assets but not delete them; only tenant admins and up can."""
    delete = next(r for mod, r, meth, _ in ROWS if mod == "assets" and meth == "DELETE")
    assert _call(_client(_user("soc_analyst")), "DELETE", delete) == 403
    assert _call(_client(_user("soc_lead")), "DELETE", delete) == 403
    assert _call(_client(_user("tenant_admin")), "DELETE", delete) != 403


def test_a_viewer_can_read_security_data_but_change_none_of_it():
    reads = [(mod, r, meth) for mod, r, meth, perm in ROWS if perm == R and meth == "GET"]
    writes = [(mod, r, meth) for mod, r, meth, perm in ROWS if perm in (W, D, "settings:write", "reports:write", "rules:write", "playbooks:write")]
    assert reads and writes
    viewer = _client(_user("viewer"))
    assert all(_call(viewer, meth, r) not in (401, 403) for _, r, meth in reads[:10])
    assert all(_call(viewer, meth, r) == 403 for _, r, meth in writes)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("mod_name,route,method,perm", ROWS, ids=IDS)
def test_each_role_gets_exactly_what_the_role_table_says(role, mod_name, route, method, perm):
    status = _call(_client(_user(role)), method, route)
    if has_permission(role, perm):
        assert status not in (401, 403), f"{role} holds {perm} and must keep {method} {route.path} (got {status})"
    else:
        assert status == 403, f"{role} lacks {perm}; {method} {route.path} must refuse (got {status})"


@pytest.mark.parametrize("mod_name,route,method,perm", ROWS, ids=IDS)
def test_api_key_scopes_are_enforced(mod_name, route, method, perm):
    unrelated = "connectors:delete" if perm != "connectors:delete" else "cases:delete"
    assert _call(_client(_user("admin", scopes=[unrelated])), method, route) == 403
    assert _call(_client(_user("admin", scopes=[perm])), method, route) not in (401, 403)


def test_the_agents_service_key_can_still_read_the_graph():
    """The agents service looks up attack paths and blast radius with its own read-only key."""
    agents_key = ["alerts:read", "cases:read"]
    for mod, route, method, perm in ROWS:
        if mod == "graph" and method == "GET":
            assert _call(_client(_user("admin", scopes=agents_key)), method, route) not in (401, 403), route.path


def test_core_key_keeps_everything_core_uses():
    """CORE's key (alerts rw, cases rw, connectors:read) must not lose any call it makes."""
    core_scopes = ["alerts:read", "alerts:write", "cases:read", "cases:write", "connectors:read"]
    for mod, route, method, perm in ROWS:
        if mod in ("metrics", "approvals", "insights"):
            assert _call(_client(_user("admin", scopes=core_scopes)), method, route) not in (401, 403), route.path


def test_the_login_only_list_is_documented():
    assert LEFT_LOGIN_ONLY and all(LEFT_LOGIN_ONLY.values())
