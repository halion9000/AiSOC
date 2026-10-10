"""GraphQL must enforce the same permissions as REST, and must never ask another service for a different tenant's data.

HISTORY. Both were missing:
 * No resolver checked any permission, so any signed-in user, and any API key however narrow its scopes, could read alerts, cases, detection rules, connectors and playbooks through /graphql that REST refuses them. Demonstrated on real Postgres: a key whose ONLY scope was hunts:read read all 8 detection rules through GraphQL while REST
   returned 403 for the same key on /rules, /connectors, /cases, /alerts and /playbooks.
 * `playbooks` and `playbookRuns` asked the agents service with the API's internal token and NO tenant. For that caller the agents service honours a tenant_id parameter and otherwise returns the unscoped result: every tenant's playbook runs, each with its trigger event (alert data). So any signed-in user of any tenant could
   read every tenant's recent runs. (The REST proxy has always sent the tenant.)
Found by auditing the operations the capability reference lists as "signed in, no permission declared".
"""
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.core.route_introspect import required_permissions, walk_routes
from app.core.security import ROLE_PERMISSIONS, has_permission
from app.db.rls import get_tenant_db
from app.graphql import query as gq
from app.graphql.schema import schema
from app.main import app

TENANT_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
SOME_ID = "00000000-0000-0000-0000-0000000000aa"

# GraphQL field -> (a query that selects it, the permissions it must need, the REST route that serves the same data)
FIELDS = {
    "alert": (f'{{ alert(id: "{SOME_ID}") {{ id }} }}', ("alerts:read",), ("GET", "/api/v1/alerts/{alert_id}")),
    "alerts": ("{ alerts { total } }", ("alerts:read",), ("GET", "/api/v1/alerts")),
    "case": (f'{{ case(id: "{SOME_ID}") {{ id }} }}', ("cases:read",), ("GET", "/api/v1/cases/{case_id}")),
    "cases": ("{ cases { total } }", ("cases:read",), ("GET", "/api/v1/cases")),
    "detectionRules": ("{ detectionRules { total } }", ("rules:read",), ("GET", "/api/v1/rules")),
    "connectors": ("{ connectors { total } }", ("connectors:read",), ("GET", "/api/v1/connectors")),
    "playbooks": ("{ playbooks { id } }", ("playbooks:read",), ("GET", "/api/v1/playbooks")),
    "playbookRuns": ("{ playbookRuns { id } }", ("playbooks:read",), ("GET", "/api/v1/playbooks/runs")),
    "socStats": ("{ socStats { totalAlerts } }", ("alerts:read", "cases:read"), None),
}


@pytest.fixture(autouse=True)
def _clean_overrides():
    yield
    app.dependency_overrides.clear()


def _user(role="viewer", scopes=None, tenant=TENANT_A) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="t@example.com", scopes=scopes)


def _run(user, query):
    async def fake_db():
        yield None

    app.dependency_overrides[get_tenant_db] = fake_db
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False).post("/graphql", json={"query": query})


def _messages(response) -> list[str]:
    return [e.get("message", "") for e in (response.json().get("errors") or [])]


def _denied(response) -> bool:
    return any(m.startswith(("API key missing scope:", "Permission denied:")) for m in _messages(response))


def _allowed_fields(user) -> set[str]:
    return {name for name, (query, _perms, _rest) in FIELDS.items() if not _denied(_run(user, query))}


class TestTheTableIsComplete:
    def test_every_query_field_is_covered_here_so_a_new_resolver_cannot_ship_unchecked(self):
        fields = set(schema._schema.query_type.fields.keys())
        assert fields == set(FIELDS), f"GraphQL fields not covered by this file: {sorted(fields ^ set(FIELDS))}: add them to FIELDS (with the permission they must need)"

    @pytest.mark.parametrize("name", [n for n, f in FIELDS.items() if f[2]])
    def test_each_field_needs_the_same_permission_as_the_rest_route_for_the_same_data(self, name):
        _query, perms, (method, path) = FIELDS[name]
        route = next(r for p, r in walk_routes(app.routes) if p == path and method in r.methods)
        assert tuple(required_permissions(route)) == perms, f"{name} must need what {method} {path} needs"


class TestWhoMayReadWhat:
    def test_a_key_with_no_scopes_at_all_can_read_nothing(self):
        assert _allowed_fields(_user(scopes=[])) == set()

    def test_the_exact_case_a_key_whose_only_scope_is_hunts_read_can_read_nothing(self):
        user = _user(role="admin", scopes=["hunts:read"])
        assert _allowed_fields(user) == set()
        response = _run(user, FIELDS["detectionRules"][0])
        assert "API key missing scope: rules:read" in _messages(response)

    def test_a_key_with_one_scope_reaches_exactly_the_fields_that_scope_allows(self):
        for scope in ("alerts:read", "cases:read", "rules:read", "connectors:read", "playbooks:read"):
            expected = {name for name, (_q, perms, _r) in FIELDS.items() if all(p == scope for p in perms)}
            assert _allowed_fields(_user(role="admin", scopes=[scope])) == expected, scope

    def test_the_stats_need_both_alerts_and_cases(self):
        assert "socStats" not in _allowed_fields(_user(scopes=["alerts:read"]))
        assert "socStats" not in _allowed_fields(_user(scopes=["cases:read"]))
        assert "socStats" in _allowed_fields(_user(scopes=["alerts:read", "cases:read"]))

    def test_a_wildcard_key_reads_everything(self):
        assert _allowed_fields(_user(scopes=["*"])) == set(FIELDS)

    def test_every_role_reads_exactly_the_fields_its_permissions_allow(self):
        for role in ROLE_PERMISSIONS:
            expected = {name for name, (_q, perms, _r) in FIELDS.items() if all(has_permission(role, p) for p in perms)}
            assert _allowed_fields(_user(role=role)) == expected, role

    def test_some_role_is_refused_something_and_some_role_reads_everything(self):
        outcomes = {role: _allowed_fields(_user(role=role)) for role in ROLE_PERMISSIONS}
        assert any(allowed != set(FIELDS) for allowed in outcomes.values()), "no role is refused anything: this test would prove nothing"
        assert any(allowed == set(FIELDS) for allowed in outcomes.values())

    def test_the_refusal_names_what_was_missing(self):
        assert _messages(_run(_user(scopes=["alerts:read"]), "{ connectors { total } }")) == ["API key missing scope: connectors:read"]
        assert any(m.startswith("Permission denied: ") for m in _messages(_run(_user(role="viewer", scopes=None), "{ detectionRules { total } }"))) or has_permission("viewer", "rules:read")

    def test_someone_who_is_not_signed_in_gets_nothing(self):
        app.dependency_overrides.clear()
        response = TestClient(app, raise_server_exceptions=False).post("/graphql", json={"query": FIELDS["alerts"][0]})
        assert response.status_code in (401, 403) and "data" not in response.json()

    def test_a_refused_field_leaks_nothing_and_an_allowed_field_asked_for_alone_still_works(self):
        """(In GraphQL an error in a NON-NULL field nulls the whole `data`, so the two are not returned together: that is the protocol, not a gap.)"""
        user = _user(scopes=["playbooks:read"])
        refused = _run(user, "{ connectors { total } playbooks { id } }")
        assert "API key missing scope: connectors:read" in _messages(refused)
        assert not (refused.json().get("data") or {}).get("connectors")
        ok = _run(user, "{ playbooks { id } }")
        assert ok.json()["data"]["playbooks"] == [] and not _messages(ok)


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Agents:
    """A stand-in for the agents service: it holds EVERY tenant's runs and playbooks and, like the real one for the API's internal caller, returns all of them unless told which tenant (tenant_id)."""

    RUNS = [
        {"id": "run-a1", "playbook_id": "p", "status": "done", "tenant": str(TENANT_A), "trigger_event": {"title": "A's alert"}},
        {"id": "run-b1", "playbook_id": "p", "status": "done", "tenant": str(TENANT_B), "trigger_event": {"title": "B's SECRET alert"}},
    ]
    calls: list[dict] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None, headers=None):
        _Agents.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        tenant = (params or {}).get("tenant_id")
        runs = [r for r in self.RUNS if tenant is None or r["tenant"] == tenant]
        if url.endswith("/runs"):
            return _Response([{k: v for k, v in r.items() if k != "tenant"} for r in runs])
        return _Response([{"id": f"pb-{r['tenant'][:1]}", "name": f"playbook of {r['tenant'][:1]}"} for r in runs])


@pytest.fixture
def agents(monkeypatch):
    _Agents.calls = []
    monkeypatch.setattr(gq.httpx, "AsyncClient", _Agents)
    monkeypatch.setattr(gq, "internal_service_headers", lambda: {"x-internal-token": "service-token"})
    return _Agents


class TestOtherTenantsDataStaysOut:
    def test_a_tenant_reads_only_its_own_playbook_runs_never_the_other_tenants(self, agents):
        response = _run(_user(role="admin", tenant=TENANT_A), "{ playbookRuns { id triggerEvent } }")
        runs = response.json()["data"]["playbookRuns"]
        assert [r["id"] for r in runs] == ["run-a1"]
        assert "SECRET" not in response.text

    def test_the_other_tenant_reads_only_its_own(self, agents):
        runs = _run(_user(role="admin", tenant=TENANT_B), "{ playbookRuns { id } }").json()["data"]["playbookRuns"]
        assert [r["id"] for r in runs] == ["run-b1"]

    def test_the_agents_service_is_always_told_which_tenant_and_it_is_the_authenticated_users(self, agents):
        _run(_user(role="admin", tenant=TENANT_A), "{ playbookRuns(limit: 7) { id } playbooks(enabledOnly: true) { id } }")
        assert len(agents.calls) == 2
        for call in agents.calls:
            assert call["params"]["tenant_id"] == str(TENANT_A)
            assert call["headers"] == {"x-internal-token": "service-token"}
        assert {c["params"].get("limit") for c in agents.calls} == {7, None} and any(c["params"].get("enabled_only") is True for c in agents.calls)

    def test_the_tenant_cannot_be_chosen_by_the_caller(self):
        for name in ("playbooks", "playbookRuns"):
            args = {a for a in schema._schema.query_type.fields[name].args}
            assert not ({"tenantId", "tenant_id", "tenant"} & args), name

    def test_with_no_tenant_nothing_is_sent_to_the_agents_service(self, agents):
        response = _run(_user(role="admin", tenant=None), "{ playbookRuns { id } playbooks { id } }")
        assert agents.calls == [] and response.json()["data"] == {"playbookRuns": [], "playbooks": []}

    def test_a_key_without_the_permission_never_causes_a_call_to_the_agents_service(self, agents):
        _run(_user(scopes=["alerts:read"]), "{ playbookRuns { id } playbooks { id } }")
        assert agents.calls == []


class TestTheCheckItself:
    """Over HTTP the framework rejects an unauthenticated request before any resolver runs, so the check's own refusal of a missing user can only be exercised directly."""

    def test_a_context_with_no_user_is_refused(self):
        from types import SimpleNamespace

        for context in ({}, {"user": None}):
            with pytest.raises(PermissionError, match="Sign in"):
                gq._require(SimpleNamespace(context=context), "alerts:read")

    def test_a_missing_permission_becomes_a_permission_error_with_the_routes_own_message(self):
        from types import SimpleNamespace

        with pytest.raises(PermissionError) as refused:
            gq._require(SimpleNamespace(context={"user": _user(scopes=["alerts:read"])}), "connectors:read")
        assert str(refused.value) == "API key missing scope: connectors:read"
        gq._require(SimpleNamespace(context={"user": _user(scopes=["alerts:read"])}), "alerts:read")

    def test_every_listed_permission_is_required_not_just_the_first(self):
        from types import SimpleNamespace

        with pytest.raises(PermissionError, match="cases:read"):
            gq._require(SimpleNamespace(context={"user": _user(scopes=["alerts:read"])}), "alerts:read", "cases:read")


class TestTheSourceKeepsItsPromise:
    def test_every_query_resolver_calls_the_permission_check_before_anything_else(self):
        import inspect

        source = inspect.getsource(gq.Query)
        resolvers = re.findall(r"@strawberry\.field[^\n]*\n\s+async def (\w+)\(", source)
        assert len(resolvers) == len(FIELDS)
        for name in resolvers:
            body = source.split(f"async def {name}(", 1)[1]
            after_signature = re.split(r"\)\s*(?:->[^\n:]*)?:\n", body, maxsplit=1)[1].lstrip()
            assert after_signature.startswith("_require(info,"), f"{name} does not check a permission first"
