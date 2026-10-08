"""Playbooks are a shared, read-only library plus each tenant's own; a tenant customises a library playbook by cloning it.

Before: every create/update/delete went to ONE global index.json (visible to every tenant, lost on redeploy, "index.json wins over fixtures": anyone able to PUT could override a shipped playbook for EVERY
tenant or delete it), and GET /runs listed every tenant's runs. These tests drive the real middleware and router with the API faked (respx), a controlled library, and an in-memory repository that mirrors
the Postgres one (which is verified separately against real Postgres).
"""
import uuid
from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.api import playbooks as pb_api
from app.core import service_auth
from app.playbook import Playbook, PlaybookRun
from app.playbook import tenant_store as TS
from app.playbook.models import PlaybookStep

API = "http://api:8000"
AUTHZ = f"{API}/api/v1/auth/authorize"
ME = f"{API}/api/v1/auth/me"
TENANT_A = str(uuid.UUID(int=0xA))
TENANT_B = str(uuid.UUID(int=0xB))
INTERNAL = "internal-secret-123"
BEARER = {"Authorization": "Bearer user-token"}
INTERNAL_HEADERS = {"x-internal-token": INTERNAL}
BASE = "/api/v1/playbooks"


def make_playbook(pid, name, enabled=True, steps=2) -> Playbook:
    return Playbook(id=pid, name=name, description=f"{name} desc", tags=["edr"], enabled=enabled, steps=[PlaybookStep(name=f"step {i}", type="notify") for i in range(steps)])


class FakeLibrary:
    """Stands in for PlaybookStore.default(): the shipped, read-only library."""

    def __init__(self):
        self.items = {"lib-isolate": make_playbook("lib-isolate", "Isolate host"), "lib-phish": make_playbook("lib-phish", "Phishing triage", enabled=False)}
        self.before = {k: v.model_dump() for k, v in self.items.items()}

    def list(self, *, enabled_only=False):
        return [p for p in self.items.values() if p.enabled or not enabled_only]

    def get(self, pid):
        return self.items.get(pid)

    # the library must NEVER be mutated through the API: these exist only so a regression is loud
    def create(self, *a, **k):
        raise AssertionError("the API wrote to the shared library")

    update = delete = create


class FakeRepo:
    """Mirrors PostgresPlaybookRepo's behaviour (server ids, immutable fields, a cap, per-tenant isolation)."""

    def __init__(self):
        self.rows: dict[tuple[uuid.UUID, str], Playbook] = {}
        self.created_by: dict[str, uuid.UUID | None] = {}
        self.cap = 200
        self.unavailable = False

    def _check(self):
        if self.unavailable:
            raise TS.PlaybookStoreUnavailable("DATABASE_URL is not configured")

    async def list(self, tenant_id, *, enabled_only=False):
        self._check()
        return [p for (t, _), p in self.rows.items() if t == tenant_id and (p.enabled or not enabled_only)]

    async def get(self, tenant_id, playbook_id):
        self._check()
        return self.rows.get((tenant_id, playbook_id))

    async def create(self, tenant_id, playbook, *, created_by=None):
        self._check()
        if sum(1 for (t, _) in self.rows if t == tenant_id) >= self.cap:
            raise TS.PlaybookLimitReached(f"This tenant already has {self.cap} custom playbooks")
        stored = playbook.model_copy(update={"id": str(uuid.uuid4())})
        self.rows[(tenant_id, stored.id)] = stored
        self.created_by[stored.id] = created_by
        return stored

    async def update(self, tenant_id, playbook_id, data):
        self._check()
        cur = self.rows.get((tenant_id, playbook_id))
        if cur is None:
            return None
        changes = {k: v for k, v in data.items() if k not in TS.IMMUTABLE_FIELDS}
        merged = Playbook.model_validate({**cur.model_dump(mode="json"), **changes, "id": cur.id, "cloned_from": cur.cloned_from})
        self.rows[(tenant_id, playbook_id)] = merged
        return merged

    async def delete(self, tenant_id, playbook_id):
        self._check()
        return self.rows.pop((tenant_id, playbook_id), None) is not None


@pytest.fixture(autouse=True)
def harness(monkeypatch):
    service_auth.clear_cache()
    STATE.installed, STATE.identities, STATE.denied = False, {}, set()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("INTERNAL_TOKEN", INTERNAL)
    monkeypatch.setenv("API_URL", API)
    library, repo = FakeLibrary(), FakeRepo()
    monkeypatch.setattr(pb_api.PlaybookStore, "default", classmethod(lambda cls: library))
    pb_api._runs.clear()
    pb_api._run_owner.clear()

    class FakeEngine:
        async def run(self, playbook, context, dry_run=False):
            return PlaybookRun(playbook, context)

    monkeypatch.setattr(pb_api, "PlaybookEngine", FakeEngine)
    from app.main import app

    app.dependency_overrides[TS.get_playbook_repo] = lambda: repo
    yield SimpleNamespace(library=library, repo=repo)
    app.dependency_overrides.pop(TS.get_playbook_repo, None)
    service_auth.clear_cache()
    pb_api._runs.clear()
    pb_api._run_owner.clear()


STATE = SimpleNamespace(installed=False, identities={}, denied=set())


def _install_fake_api():
    """ONE fake of the API per test, answering by the caller's Authorization header. (respx REPLACES a route registered with the same pattern, so registering a second route for a second tenant makes the
    LAST one answer for everybody: every request, tenant A's included, would be authenticated as the most recently registered tenant, and the isolation tests would be meaningless.)"""
    if STATE.installed:
        return
    STATE.installed = True

    def identity(request):
        return STATE.identities.get(request.headers.get("authorization", ""))

    def authorize(request):
        import json

        who = identity(request)
        if who is None:
            return httpx.Response(401, json={"detail": "invalid credentials"})
        if json.loads(request.content)["permission"] in STATE.denied:
            return httpx.Response(403, json={"detail": "Permission denied"})
        return httpx.Response(200, json={"allowed": True, "tenant_id": who["tenant"], "user_id": who["user"], "role": "admin"})

    def me(request):
        who = identity(request)
        if who is None:
            return httpx.Response(401, json={"detail": "invalid credentials"})
        return httpx.Response(200, json={"id": who["user"], "tenant_id": who["tenant"], "role": "admin"})

    respx.post(AUTHZ).mock(side_effect=authorize)
    respx.get(ME).mock(side_effect=me)


def api_says(tenant=TENANT_A, user=None, denied=(), token="Bearer user-token"):
    """Register that `token` belongs to `tenant` (and which permissions the API refuses everyone)."""
    _install_fake_api()
    user = user or str(uuid.uuid4())
    STATE.identities[token] = {"tenant": tenant, "user": user}
    STATE.denied = set(denied)
    return user


def client() -> TestClient:
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


def as_tenant(tenant):
    """A client authenticated as a user of `tenant`, with its OWN token (the middleware caches identity per credential)."""
    token = f"Bearer tok-{tenant}"
    api_says(tenant=tenant, token=token)
    c = client()
    c.headers.update({"Authorization": token})
    return c


class TestTheSharedLibrary:
    @respx.mock
    def test_the_library_is_listed_read_only_and_tagged(self, harness):
        items = as_tenant(TENANT_A).get(BASE).json()
        library = [p for p in items if p["scope"] == "library"]
        assert {p["id"] for p in library} == {"lib-isolate", "lib-phish"} and all(p["editable"] is False for p in library)

    @respx.mock
    def test_every_tenant_sees_the_same_library(self, harness):
        a = {p["id"] for p in as_tenant(TENANT_A).get(BASE).json()}
        b = {p["id"] for p in as_tenant(TENANT_B).get(BASE).json()}
        assert a == b == {"lib-isolate", "lib-phish"}

    @respx.mock
    @pytest.mark.parametrize("method,body", [("put", {"name": "pwned"}), ("delete", None)])
    def test_a_library_playbook_cannot_be_changed_or_deleted_and_the_error_says_how_to_customise_it(self, harness, method, body):
        """The old store let anyone able to PUT override a shipped playbook for EVERY tenant, or delete it."""
        c = as_tenant(TENANT_A)
        r = getattr(c, method)(f"{BASE}/lib-isolate", **({"json": body} if body else {}))
        assert r.status_code == 403 and "clone" in r.json()["detail"].lower()
        assert harness.library.items["lib-isolate"].model_dump() == harness.library.before["lib-isolate"]  # untouched
        assert harness.repo.rows == {}

    @respx.mock
    def test_the_library_is_identical_after_a_tenant_customises_a_copy(self, harness):
        c = as_tenant(TENANT_A)
        clone = c.post(f"{BASE}/lib-isolate/clone").json()
        c.put(f"{BASE}/{clone['id']}", json={"name": "Our isolate", "description": "changed", "steps": []})
        assert {k: v.model_dump() for k, v in harness.library.items.items()} == harness.library.before
        assert as_tenant(TENANT_B).get(f"{BASE}/lib-isolate").json()["description"] == "Isolate host desc"


class TestCloning:
    @respx.mock
    def test_cloning_copies_a_library_playbook_into_the_tenant(self, harness):
        r = as_tenant(TENANT_A).post(f"{BASE}/lib-isolate/clone")
        assert r.status_code == 201
        c = r.json()
        assert c["scope"] == "tenant" and c["editable"] is True
        assert c["id"] != "lib-isolate" and uuid.UUID(c["id"])
        assert c["name"] == "Isolate host (custom)" and c["cloned_from"] == "lib-isolate"
        assert [s["name"] for s in c["steps"]] == ["step 0", "step 1"] and c["tags"] == ["edr"] and c["description"] == "Isolate host desc"

    @respx.mock
    def test_a_clone_starts_disabled_even_if_the_original_is_enabled(self, harness):
        """It is a response playbook the tenant has not reviewed: going live is a deliberate act."""
        assert harness.library.items["lib-isolate"].enabled is True
        assert as_tenant(TENANT_A).post(f"{BASE}/lib-isolate/clone").json()["enabled"] is False

    @respx.mock
    def test_a_clone_can_be_named(self, harness):
        assert as_tenant(TENANT_A).post(f"{BASE}/lib-isolate/clone", json={"name": "  Payroll isolate  "}).json()["name"] == "Payroll isolate"

    @respx.mock
    def test_a_clone_appears_for_its_owner_only(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        clone = a.post(f"{BASE}/lib-isolate/clone").json()
        assert clone["id"] in {p["id"] for p in a.get(BASE).json()}
        assert clone["id"] not in {p["id"] for p in b.get(BASE).json()}
        assert b.get(f"{BASE}/{clone['id']}").status_code == 404

    @respx.mock
    def test_two_tenants_customise_the_same_library_playbook_independently(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        ca, cb = a.post(f"{BASE}/lib-isolate/clone").json(), b.post(f"{BASE}/lib-isolate/clone").json()
        a.put(f"{BASE}/{ca['id']}", json={"name": "A's version"})
        assert b.get(f"{BASE}/{cb['id']}").json()["name"] == "Isolate host (custom)"
        assert a.get(f"{BASE}/{ca['id']}").json()["name"] == "A's version"

    @respx.mock
    def test_a_tenant_can_clone_its_own_custom_playbook_and_provenance_follows(self, harness):
        c = as_tenant(TENANT_A)
        first = c.post(f"{BASE}/lib-isolate/clone").json()
        second = c.post(f"{BASE}/{first['id']}/clone").json()
        assert second["cloned_from"] == first["id"] and second["id"] != first["id"]

    @respx.mock
    def test_cloning_something_that_does_not_exist_or_belongs_to_another_tenant_is_a_404(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        mine = a.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert b.post(f"{BASE}/{mine}/clone").status_code == 404
        assert b.post(f"{BASE}/nope/clone").status_code == 404
        assert len(harness.repo.rows) == 1  # nothing was created for B

    @respx.mock
    def test_the_per_tenant_limit_is_a_409(self, harness):
        harness.repo.cap = 1
        c = as_tenant(TENANT_A)
        assert c.post(f"{BASE}/lib-isolate/clone").status_code == 201
        r = c.post(f"{BASE}/lib-phish/clone")
        assert r.status_code == 409 and "1 custom playbooks" in r.json()["detail"]

    @respx.mock
    def test_who_made_the_clone_is_recorded(self, harness):
        user = api_says(tenant=TENANT_A)
        c = client()
        c.headers.update(BEARER)
        pid = c.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert harness.repo.created_by[pid] == uuid.UUID(user)


class TestCreatingAndEditingOwnPlaybooks:
    @respx.mock
    def test_create_assigns_a_fresh_id_ignores_a_chosen_one_and_cannot_claim_provenance(self, harness):
        r = as_tenant(TENANT_A).post(BASE, json={"id": "lib-isolate", "name": "Mine", "cloned_from": "lib-phish", "steps": []})
        assert r.status_code == 201
        created = r.json()
        assert created["id"] != "lib-isolate" and uuid.UUID(created["id"])  # cannot shadow a library id
        assert created["cloned_from"] is None and created["scope"] == "tenant"

    @respx.mock
    def test_a_created_playbook_never_shadows_the_library_entry(self, harness):
        c = as_tenant(TENANT_A)
        c.post(BASE, json={"id": "lib-isolate", "name": "Impostor"})
        assert c.get(f"{BASE}/lib-isolate").json()["name"] == "Isolate host" and c.get(f"{BASE}/lib-isolate").json()["scope"] == "library"

    @respx.mock
    def test_update_changes_editable_fields_and_cannot_rewrite_identity_or_provenance(self, harness):
        c = as_tenant(TENANT_A)
        pid = c.post(f"{BASE}/lib-isolate/clone").json()["id"]
        r = c.put(f"{BASE}/{pid}", json={"name": "Renamed", "enabled": True, "id": "evil", "cloned_from": "evil", "scope": "library", "editable": False})
        body = r.json()
        assert r.status_code == 200 and body["name"] == "Renamed" and body["enabled"] is True
        assert body["id"] == pid and body["cloned_from"] == "lib-isolate" and body["scope"] == "tenant" and body["editable"] is True

    @respx.mock
    def test_an_invalid_update_is_a_422_and_changes_nothing(self, harness):
        c = as_tenant(TENANT_A)
        pid = c.post(f"{BASE}/lib-isolate/clone").json()["id"]
        r = c.put(f"{BASE}/{pid}", json={"steps": "not a list"})
        assert r.status_code == 422
        assert c.get(f"{BASE}/{pid}").json()["name"] == "Isolate host (custom)"

    @respx.mock
    def test_another_tenant_cannot_update_or_delete_it(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        pid = a.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert b.put(f"{BASE}/{pid}", json={"name": "pwn"}).status_code == 404
        assert b.delete(f"{BASE}/{pid}").status_code == 404
        assert a.get(f"{BASE}/{pid}").json()["name"] == "Isolate host (custom)"

    @respx.mock
    def test_a_foreign_id_is_indistinguishable_from_an_unknown_one(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        pid = a.post(f"{BASE}/lib-isolate/clone").json()["id"]
        for method, kwargs in (("get", {}), ("put", {"json": {"name": "x"}}), ("delete", {})):
            foreign = getattr(b, method)(f"{BASE}/{pid}", **kwargs)
            unknown = getattr(b, method)(f"{BASE}/{uuid.uuid4()}", **kwargs)
            assert (foreign.status_code, foreign.text) == (unknown.status_code, unknown.text), method

    @respx.mock
    def test_the_owner_can_delete_it_and_deleting_again_is_a_404(self, harness):
        c = as_tenant(TENANT_A)
        pid = c.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert c.delete(f"{BASE}/{pid}").status_code == 204
        assert c.delete(f"{BASE}/{pid}").status_code == 404 and c.get(f"{BASE}/{pid}").status_code == 404

    @respx.mock
    def test_enabled_only_filters_both_library_and_own(self, harness):
        c = as_tenant(TENANT_A)
        c.post(f"{BASE}/lib-isolate/clone")  # a disabled clone
        listed = c.get(f"{BASE}?enabled_only=true").json()
        assert {p["id"] for p in listed} == {"lib-isolate"}


class TestRunning:
    @respx.mock
    def test_a_library_and_an_own_playbook_can_both_run(self, harness):
        c = as_tenant(TENANT_A)
        own = c.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert c.post(f"{BASE}/lib-isolate/run", json={}).status_code == 202
        assert c.post(f"{BASE}/{own}/run", json={}).status_code == 202

    @respx.mock
    def test_another_tenants_playbook_cannot_be_run(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        pid = a.post(f"{BASE}/lib-isolate/clone").json()["id"]
        assert b.post(f"{BASE}/{pid}/run", json={}).status_code == 404
        assert pb_api._runs == {}

    @respx.mock
    def test_the_run_acts_for_the_authenticated_tenant_not_one_the_client_put_in_the_context(self, harness, monkeypatch):
        seen = []

        class SpyEngine:
            async def run(self, playbook, context, dry_run=False):
                seen.append(dict(context))
                return PlaybookRun(playbook, context)

        monkeypatch.setattr(pb_api, "PlaybookEngine", SpyEngine)
        r = as_tenant(TENANT_A).post(f"{BASE}/lib-isolate/run", json={"context": {"tenant_id": TENANT_B, "host": "web-01"}})
        assert r.status_code == 202
        assert seen[0]["tenant_id"] == TENANT_A and seen[0]["host"] == "web-01"  # the client's claim is overridden

    @respx.mock
    def test_dry_run_is_passed_through(self, harness, monkeypatch):
        flags = []

        class SpyEngine:
            async def run(self, playbook, context, dry_run=False):
                flags.append(dry_run)
                return PlaybookRun(playbook, context)

        monkeypatch.setattr(pb_api, "PlaybookEngine", SpyEngine)
        as_tenant(TENANT_A).post(f"{BASE}/lib-isolate/run", json={"dry_run": True})
        assert flags == [True]

    @respx.mock
    def test_running_something_that_does_not_exist_is_a_404(self, harness):
        assert as_tenant(TENANT_A).post(f"{BASE}/nope/run", json={}).status_code == 404


class TestRunsAreScopedToTheirTenant:
    """GET /runs listed EVERY tenant's runs and /runs/{id} returned any of them (a run's context is alert data, hostnames, results)."""

    @respx.mock
    def test_a_tenant_lists_only_its_own_runs(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        ra = a.post(f"{BASE}/lib-isolate/run", json={}).json()["run_id"]
        rb = b.post(f"{BASE}/lib-isolate/run", json={}).json()["run_id"]
        assert [r["run_id"] for r in a.get(f"{BASE}/runs").json()] == [ra]
        assert [r["run_id"] for r in b.get(f"{BASE}/runs").json()] == [rb]

    @respx.mock
    def test_another_tenants_run_is_a_404_indistinguishable_from_an_unknown_one(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        run = a.post(f"{BASE}/lib-isolate/run", json={}).json()["run_id"]
        foreign, unknown = b.get(f"{BASE}/runs/{run}"), b.get(f"{BASE}/runs/{uuid.uuid4()}")
        assert (foreign.status_code, foreign.json()) == (unknown.status_code, unknown.json()) == (404, {"detail": "Playbook run not found"})
        assert a.get(f"{BASE}/runs/{run}").status_code == 200

    @respx.mock
    def test_a_run_with_no_recorded_owner_is_hidden_from_an_authenticated_caller(self, harness):
        pr = PlaybookRun(harness.library.items["lib-isolate"], {})
        pb_api._runs["ownerless"] = pr
        c = as_tenant(TENANT_A)
        assert c.get(f"{BASE}/runs/ownerless").status_code == 404 and c.get(f"{BASE}/runs").json() == []  # fail closed

    @respx.mock
    def test_the_owner_keeps_access_after_the_run_completes(self, harness):
        """The background task REPLACES the placeholder with the real run; the owner record must outlive that."""
        c = as_tenant(TENANT_A)
        run = c.post(f"{BASE}/lib-isolate/run", json={}).json()["run_id"]
        assert pb_api._run_owner[run] == TENANT_A and c.get(f"{BASE}/runs/{run}").status_code == 200

    def test_the_apis_own_proxy_can_scope_by_naming_a_tenant_or_see_all(self, harness):
        pb_api._runs["ra"], pb_api._runs["rb"] = PlaybookRun(harness.library.items["lib-isolate"], {}), PlaybookRun(harness.library.items["lib-isolate"], {})
        pb_api._run_owner["ra"], pb_api._run_owner["rb"] = TENANT_A, TENANT_B
        c = client()
        assert len(c.get(f"{BASE}/runs", headers=INTERNAL_HEADERS).json()) == 2
        assert len(c.get(f"{BASE}/runs?tenant_id={TENANT_A}", headers=INTERNAL_HEADERS).json()) == 1
        assert c.get(f"{BASE}/runs/rb?tenant_id={TENANT_A}", headers=INTERNAL_HEADERS).status_code == 404

    @respx.mock
    def test_an_authenticated_caller_cannot_widen_their_view_by_naming_a_tenant(self, harness):
        a, b = as_tenant(TENANT_A), as_tenant(TENANT_B)
        a.post(f"{BASE}/lib-isolate/run", json={})
        assert b.get(f"{BASE}/runs?tenant_id={TENANT_A}").json() == []  # ignored: B only ever sees B's


class TestTheApisOwnProxyAndDevelopment:
    def test_the_proxy_creates_and_clones_into_the_tenant_it_names(self, harness):
        c = client()
        made = c.post(f"{BASE}?tenant_id={TENANT_A}", json={"name": "via proxy"}, headers=INTERNAL_HEADERS)
        cloned = c.post(f"{BASE}/lib-isolate/clone?tenant_id={TENANT_B}", headers=INTERNAL_HEADERS)
        assert made.status_code == 201 and cloned.status_code == 201
        assert {t for (t, _) in harness.repo.rows} == {uuid.UUID(TENANT_A), uuid.UUID(TENANT_B)}

    def test_without_a_tenant_nothing_can_be_saved(self, harness):
        c = client()
        for r in (c.post(BASE, json={"name": "x"}, headers=INTERNAL_HEADERS), c.post(f"{BASE}/lib-isolate/clone", headers=INTERNAL_HEADERS)):
            assert r.status_code == 400 and "tenant is required" in r.json()["detail"]
        assert harness.repo.rows == {}

    def test_in_development_the_library_works_and_saving_needs_a_tenant(self, harness, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "development")
        c = client()
        assert {p["id"] for p in c.get(BASE).json()} == {"lib-isolate", "lib-phish"}
        assert c.post(f"{BASE}/lib-isolate/clone").status_code == 400

    def test_the_listing_via_the_proxy_includes_the_named_tenants_playbooks(self, harness):
        c = client()
        mine = c.post(f"{BASE}?tenant_id={TENANT_A}", json={"name": "A's"}, headers=INTERNAL_HEADERS).json()["id"]
        assert mine in {p["id"] for p in c.get(f"{BASE}?tenant_id={TENANT_A}", headers=INTERNAL_HEADERS).json()}
        assert mine not in {p["id"] for p in c.get(f"{BASE}?tenant_id={TENANT_B}", headers=INTERNAL_HEADERS).json()}


class TestPermissions:
    @respx.mock
    @pytest.mark.parametrize("method,path,perm,body", [
        ("post", f"{BASE}/lib-isolate/clone", "playbooks:write", None),
        ("post", BASE, "playbooks:write", {"name": "x"}),
        ("post", f"{BASE}/lib-isolate/run", "playbooks:execute", {}),
        ("get", BASE, "playbooks:read", None),
        ("get", f"{BASE}/runs", "playbooks:read", None),
    ])
    def test_each_route_asks_the_api_for_the_right_permission_and_is_refused_without_it(self, harness, method, path, perm, body):
        api_says(tenant=TENANT_A, denied={perm})
        c = client()
        r = getattr(c, method)(path, headers=BEARER, **({"json": body} if body is not None else {}))
        assert r.status_code == 403
        assert harness.repo.rows == {} and pb_api._runs == {}

    def test_the_clone_route_has_a_permission_rule(self):
        from app.core.route_permissions import RULES

        needed = [perm for pattern, methods, perm in RULES if pattern.match("/api/v1/playbooks/abc/clone") and (methods is None or "POST" in methods)]
        assert needed and needed[0] == "playbooks:write"


class TestWhenTheDatabaseIsUnavailable:
    @respx.mock
    def test_the_library_still_works_and_saving_says_why_it_cannot(self, harness):
        harness.repo.unavailable = True
        c = as_tenant(TENANT_A)
        assert {p["id"] for p in c.get(BASE).json()} == {"lib-isolate", "lib-phish"}  # the shared library is unaffected
        assert c.get(f"{BASE}/lib-isolate").status_code == 200 and c.post(f"{BASE}/lib-isolate/run", json={}).status_code == 202
        for r in (c.post(f"{BASE}/lib-isolate/clone"), c.post(BASE, json={"name": "x"})):
            assert r.status_code == 503 and "cannot be stored" in r.json()["detail"]
