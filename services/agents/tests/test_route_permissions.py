"""The agents route->permission table: exact answers, and full coverage of console-facing routes."""
import pytest

from app.core.route_permissions import CONSOLE_FACING_PREFIXES, RULES, required_permission
from app.main import app

CASES = [
    ("GET", "/api/v1/playbooks", "playbooks:read"),
    ("GET", "/api/v1/playbooks/abc", "playbooks:read"),
    ("GET", "/api/v1/playbooks/runs", "playbooks:read"),
    ("GET", "/api/v1/playbooks/runs/r1", "playbooks:read"),
    ("POST", "/api/v1/playbooks", "playbooks:write"),
    ("PUT", "/api/v1/playbooks/abc", "playbooks:write"),
    ("DELETE", "/api/v1/playbooks/abc", "playbooks:write"),
    ("POST", "/api/v1/playbooks/draft-from-nl", "playbooks:write"),
    ("POST", "/api/v1/playbooks/abc/run", "playbooks:execute"),
    ("POST", "/api/v1/hunt/search", "lake:query"),
    ("GET", "/api/v1/hunt/saved", "lake:query"),
    ("DELETE", "/api/v1/hunt/saved/9", "lake:query"),
    ("GET", "/api/v1/hunt-corpus", "lake:query"),
    ("POST", "/api/v1/hunt-corpus/h1/run", "lake:query"),
    ("POST", "/api/v1/hunt-corpus/reload", "settings:write"),
    ("GET", "/api/v1/contextual/actions", "alerts:read"),
    ("POST", "/api/v1/contextual/action", "alerts:read"),
    ("POST", "/api/v1/contextual/action/stream", "alerts:read"),
    ("POST", "/api/v1/explain", "alerts:read"),
    ("POST", "/api/v1/agents/investigate", "cases:write"),
    ("GET", "/api/v1/agents/investigations/r1", "cases:read"),
    ("POST", "/api/v1/cases/c1/investigate", "cases:write"),
    ("POST", "/api/v1/cases/c1/triage", "cases:write"),
    ("GET", "/api/v1/cases/c1/investigations/r1/report.md", "cases:read"),
    ("GET", "/api/v1/investigations", "cases:read"),
    ("POST", "/api/v1/investigations", "cases:write"),
    ("POST", "/api/v1/investigations/r1/close", "cases:write"),
]


@pytest.mark.parametrize("method,path,perm", CASES)
def test_required_permission(method, path, perm):
    assert required_permission(method, path) == perm


def test_unmapped_paths_need_only_a_login():
    assert required_permission("GET", "/api/v1/copilot/ping") is None
    assert required_permission("GET", "/api/v1/playbooks-lookalike") is None


def test_every_permission_the_table_names_is_one_the_API_recognises():
    """A typo here would make the API answer 422 and the agents service fail closed for everyone."""
    import sys
    sys.path.insert(0, "../api")
    names = {perm for _, _, perm in RULES}
    api_known = {"playbooks:read", "playbooks:write", "playbooks:execute", "lake:query", "settings:write", "alerts:read", "cases:read", "cases:write"}
    assert names <= api_known, f"unknown to the API: {names - api_known}"


def test_every_console_facing_route_is_covered_by_a_rule():
    """A new playbook/hunt/investigation route must not slip through with a login only."""
    uncovered = []
    for path, ops in app.openapi()["paths"].items():
        if not path.startswith(CONSOLE_FACING_PREFIXES):
            continue
        for method in ops:
            if method in ("get", "post", "put", "patch", "delete") and required_permission(method, path) is None:
                uncovered.append(f"{method.upper()} {path}")
    assert not uncovered, "console-facing agents routes with no permission rule (add one to app/core/route_permissions.py):\n  " + "\n  ".join(uncovered)


def test_explain_needs_alerts_read_and_nothing_near_it_is_swept_in():
    """/api/v1/explain takes an arbitrary alert payload and runs the LLM; it used to need only a login."""
    assert required_permission("POST", "/api/v1/explain") == "alerts:read"
    assert required_permission("GET", "/api/v1/explain") is None, "only POST /explain is the endpoint"
    for lookalike in ("/api/v1/explain/", "/api/v1/explainer", "/api/v1/explain/x", "/api/v1/x/explain"):
        assert required_permission("POST", lookalike) is None, lookalike
    assert "/api/v1/explain" in CONSOLE_FACING_PREFIXES, "the coverage test must enforce it from now on"

