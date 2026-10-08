"""The agents service acts for the AUTHENTICATED caller's tenant, never for a tenant named in the request body.

Investigate, triage, explain and the agents router took `tenant_id` from the request body (default "default"). Any caller could name any tenant: the service then loaded THAT tenant's stored LLM credential
(spending another tenant's API key), ran work under it, and (for triage) read that tenant's runs back, since get_triage's isolation was "the caller MUST pass the same tenant_id the run was launched with".
The web console reaches this service through rewrites that bypass the API, so the body was the only tenant signal. The middleware now learns the caller's identity from the API (/auth/authorize now returns
tenant_id, user_id and role) and records it in request.state.caller; handlers take the tenant from there.
These tests drive the REAL middleware and handlers, with the API faked via respx.
"""
import uuid
from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api import explain as explain_mod
from app.api import investigate as inv
from app.api import router as router_mod
from app.api import triage as tri
from app.core import caller as caller_mod
from app.core import service_auth

API = "http://api:8000"
AUTHZ = f"{API}/api/v1/auth/authorize"
ME = f"{API}/api/v1/auth/me"
TENANT_A = str(uuid.UUID(int=0xA))
VICTIM = str(uuid.UUID(int=0xBAD))
INTERNAL = "internal-secret-123"


@pytest.fixture(autouse=True)
def production(monkeypatch):
    service_auth.clear_cache()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("INTERNAL_TOKEN", INTERNAL)
    monkeypatch.setenv("API_URL", API)
    inv._runs.clear()
    tri._triage_runs.clear()
    yield
    service_auth.clear_cache()
    inv._runs.clear()
    tri._triage_runs.clear()


def api_says(tenant=TENANT_A, user="user-1", role="admin", with_identity=True):
    """Fake the API: every Bearer token is valid and (optionally) says who it is. Routes with a permission rule are verified through /auth/authorize, routes without one through /auth/me."""

    def authorize(request):
        body = {"allowed": True}
        if with_identity:
            body.update({"tenant_id": tenant, "user_id": user, "role": role})
        return httpx.Response(200, json=body)

    def me(request):
        body = {"id": user, "email": "u@example.test"}
        if with_identity:
            body.update({"tenant_id": tenant, "role": role})
        return httpx.Response(200, json=body)

    respx.post(AUTHZ).mock(side_effect=authorize)
    respx.get(ME).mock(side_effect=me)


def client() -> TestClient:
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


BEARER = {"Authorization": "Bearer user-token"}
INTERNAL_HEADERS = {"x-internal-token": INTERNAL}


class TestTheHelper:
    def state(self, caller):
        return SimpleNamespace(state=SimpleNamespace(**({"caller": caller} if caller is not None else {})))

    def test_no_caller_means_nothing_is_enforcing_so_the_body_is_used(self):
        assert caller_mod.authenticated_tenant(self.state(None)) is None
        assert caller_mod.resolve_tenant("claimed", None) == "claimed" and caller_mod.resolve_tenant(None, None) == "default"

    def test_an_internal_caller_is_trusted_to_name_the_tenant(self):
        assert caller_mod.authenticated_tenant(self.state({"kind": "internal"})) is None

    def test_a_user_caller_yields_its_own_tenant(self):
        assert caller_mod.authenticated_tenant(self.state({"kind": "user", "tenant_id": TENANT_A})) == TENANT_A

    def test_a_user_whose_tenant_is_unknown_is_refused_not_defaulted(self):
        with pytest.raises(HTTPException) as err:
            caller_mod.authenticated_tenant(self.state({"kind": "user", "tenant_id": None}))
        assert err.value.status_code == 403

    def test_the_authenticated_tenant_always_wins_and_a_different_claim_is_logged(self, monkeypatch):
        seen = []
        monkeypatch.setattr(caller_mod.logger, "warning", lambda event, **kw: seen.append((event, kw)))
        assert caller_mod.resolve_tenant(VICTIM, TENANT_A) == TENANT_A
        assert seen == [("agents.tenant_override", {"claimed": VICTIM, "authenticated": TENANT_A})]
        seen.clear()
        for harmless in (None, "", "default", TENANT_A):
            assert caller_mod.resolve_tenant(harmless, TENANT_A) == TENANT_A
        assert seen == []  # only a genuinely DIFFERENT claim is logged


class TestTheMiddlewareLearnsWhoIsCalling:
    @respx.mock
    def test_a_bearer_caller_gets_the_identity_the_api_reported(self):
        api_says(tenant=TENANT_A, user="u-7", role="soc_lead")
        client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x"}, headers=BEARER)
        assert service_auth.identity_for("Bearer user-token") == {"tenant_id": TENANT_A, "user_id": "u-7", "role": "soc_lead"}

    @respx.mock
    def test_the_me_endpoint_form_is_understood_too(self):
        respx.get(ME).mock(return_value=httpx.Response(200, json={"id": "u-9", "tenant_id": TENANT_A, "role": "admin"}))
        import asyncio

        assert asyncio.run(service_auth.check_with_api("Bearer t", None)) == "ok"
        assert service_auth.identity_for("Bearer t") == {"tenant_id": TENANT_A, "user_id": "u-9", "role": "admin"}

    def test_caller_for_classifies_internal_and_user(self):
        assert service_auth.caller_for({"x-internal-token": INTERNAL}) == {"kind": "internal"}
        service_auth._remember_identity("Bearer x", httpx.Response(200, json={"tenant_id": TENANT_A}), 1e18)
        assert service_auth.caller_for({"authorization": "Bearer x"}) == {"kind": "user", "tenant_id": TENANT_A, "user_id": None, "role": None}

    @respx.mock
    def test_identity_is_cached_with_the_verified_decision_so_the_api_is_not_asked_every_time(self):
        api_says()
        c = client()
        for _ in range(3):
            c.post("/api/v1/cases/c1/investigate", json={"alert_summary": "x"}, headers=BEARER)
        assert respx.calls.call_count == 1

    @respx.mock
    def test_a_verified_credential_whose_identity_expired_is_not_trusted_and_asks_the_api_again(self):
        api_says()
        c = client()
        c.post("/api/v1/cases/c1/investigate", json={"alert_summary": "x"}, headers=BEARER)
        service_auth._identities.clear()  # the identity is gone but the verified decision remains
        c.post("/api/v1/cases/c1/investigate", json={"alert_summary": "x"}, headers=BEARER)
        assert respx.calls.call_count == 2


class TestInvestigate:
    @pytest.fixture
    def launched(self, monkeypatch):
        seen = []

        async def fake_run(run_id, case_id, req):
            seen.append(req.tenant_id)

        monkeypatch.setattr(inv, "_run_and_store", fake_run)
        return seen

    @respx.mock
    def test_a_logged_in_caller_naming_another_tenant_runs_under_their_own(self, launched):
        api_says(tenant=TENANT_A)
        r = client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x", "tenant_id": VICTIM}, headers=BEARER)
        assert r.status_code == 200 and launched == [TENANT_A]  # NOT the victim

    @respx.mock
    def test_omitting_the_tenant_no_longer_means_default(self, launched):
        api_says(tenant=TENANT_A)
        client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x"}, headers=BEARER)
        assert launched == [TENANT_A]

    def test_the_apis_own_proxy_is_trusted_to_name_the_tenant(self, launched):
        client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x", "tenant_id": "tenant-from-the-api"}, headers=INTERNAL_HEADERS)
        assert launched == ["tenant-from-the-api"]

    def test_in_development_nothing_is_enforced_and_the_body_is_used(self, launched, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "development")
        client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x", "tenant_id": "dev-tenant"})
        assert launched == ["dev-tenant"]

    @respx.mock
    def test_a_logged_in_caller_whose_tenant_is_unknown_is_refused_and_nothing_runs(self, launched):
        api_says(with_identity=False)  # an API that does not say who the caller is
        r = client().post("/api/v1/cases/c1/investigate", json={"alert_summary": "x", "tenant_id": VICTIM}, headers=BEARER)
        assert r.status_code == 403 and "tenant could not be determined" in r.json()["detail"]
        assert launched == [] and inv._runs == {}

    @respx.mock
    def test_the_legacy_alert_adapter_also_forwards_the_caller(self, monkeypatch):
        api_says(tenant=TENANT_A)
        respx.get(f"{API}/api/v1/alerts/a-1").mock(return_value=httpx.Response(200, json={"id": "a-1", "caseId": "c-9", "title": "t", "tenantId": TENANT_A}))
        got = {}

        async def fake_launch(*, case_id, body, background_tasks, request):
            got["tenant"] = caller_mod.authenticated_tenant(request)
            return SimpleNamespace(run_id="r", case_id=case_id, status="running", message="m")

        monkeypatch.setattr(inv, "launch_investigation", fake_launch)
        client().post("/api/v1/agents/investigate", json={"alertId": "a-1"}, headers=BEARER)
        assert got["tenant"] == TENANT_A


class TestTriage:
    @respx.mock
    def test_launch_runs_under_the_callers_tenant_and_records_it(self, monkeypatch):
        api_says(tenant=TENANT_A)
        seen = []

        async def fake_run(run_id, case_id, state, topology, tenant_id):
            seen.append(tenant_id)

        monkeypatch.setattr(tri, "_run_router_and_store", fake_run)
        r = client().post("/api/v1/cases/c1/triage", json={"alert_summary": "x", "tenant_id": VICTIM}, headers=BEARER)
        assert r.status_code == 200
        assert seen == [TENANT_A] and tri._triage_runs[r.json()["run_id"]]["tenant_id"] == TENANT_A

    @respx.mock
    def test_naming_the_victims_tenant_no_longer_returns_the_victims_run(self):
        """THE original hole: get_triage's isolation was 'the caller must pass the tenant the run was launched with', so naming it returned the run."""
        tri._triage_runs["run-v"] = {"run_id": "run-v", "tenant_id": VICTIM, "status": "completed", "secret": "victim-findings"}
        api_says(tenant=TENANT_A)
        r = client().get(f"/api/v1/triage/run-v?tenant_id={VICTIM}", headers=BEARER)
        assert r.status_code == 404 and "victim-findings" not in r.text

    @respx.mock
    def test_a_caller_reads_their_own_run_without_naming_a_tenant(self):
        tri._triage_runs["run-a"] = {"run_id": "run-a", "tenant_id": TENANT_A, "status": "completed"}
        api_says(tenant=TENANT_A)
        r = client().get("/api/v1/triage/run-a", headers=BEARER)
        assert r.status_code == 200 and r.json()["run_id"] == "run-a"

    def test_the_apis_proxy_still_reads_a_run_by_naming_its_tenant(self):
        tri._triage_runs["run-p"] = {"run_id": "run-p", "tenant_id": "t-9", "status": "completed"}
        assert client().get("/api/v1/triage/run-p?tenant_id=t-9", headers=INTERNAL_HEADERS).status_code == 200
        assert client().get("/api/v1/triage/run-p?tenant_id=other", headers=INTERNAL_HEADERS).status_code == 404


class TestExplain:
    @respx.mock
    def test_the_llm_credential_is_resolved_for_the_callers_tenant_not_the_named_one(self, monkeypatch):
        """The body tenant flowed into resolve_llm_config, which loads THAT tenant's stored LLM credential: a caller could spend another tenant's API key."""
        api_says(tenant=TENANT_A)
        asked = []

        async def fake_resolve(tenant_ref):
            asked.append(tenant_ref)
            raise RuntimeError("stop here: only the tenant that was asked for matters")

        monkeypatch.setattr(explain_mod, "resolve_llm_config", fake_resolve)
        client().post("/api/v1/explain", json={"alert": {"id": "a1", "title": "t"}, "tenant_id": VICTIM}, headers=BEARER)
        assert asked == [TENANT_A]


class TestAgentsRouter:
    @respx.mock
    def test_start_investigation_uses_the_callers_tenant(self, monkeypatch):
        api_says(tenant=TENANT_A)
        seen = []

        async def fake_run(run_id, state):
            seen.append(str(state.tenant_id))

        monkeypatch.setattr(router_mod, "_run_investigation", fake_run)
        r = client().post("/api/v1/investigations", json={"incident_id": str(uuid.uuid4()), "tenant_id": VICTIM, "alert_summary": "x"}, headers=BEARER)
        assert r.status_code == 200, r.text
        assert seen == [TENANT_A]

    @respx.mock
    def test_a_caller_whose_tenant_is_not_a_uuid_is_refused(self, monkeypatch):
        api_says(tenant="not-a-uuid")
        seen = []

        async def fake_run(run_id, state):
            seen.append(1)

        monkeypatch.setattr(router_mod, "_run_investigation", fake_run)
        r = client().post("/api/v1/investigations", json={"incident_id": str(uuid.uuid4()), "tenant_id": VICTIM, "alert_summary": "x"}, headers=BEARER)
        assert r.status_code == 403 and seen == []


class TestWebSocket:
    @respx.mock
    def test_the_stream_runs_under_the_callers_tenant(self, monkeypatch):
        api_says(tenant=TENANT_A)
        seen = []

        async def fake_stream(*, case_id, alert_summary, raw_alert, tenant_id, run_id=None):
            seen.append(tenant_id)
            yield {"type": "done"}

        monkeypatch.setattr(inv, "_investigate_stream", fake_stream)
        from app.main import app

        with TestClient(app).websocket_connect(f"/api/v1/investigations/r1/stream?case_id=c1&alert_summary=x&tenant_id={VICTIM}", headers=BEARER) as ws:
            ws.receive_text()
        assert seen == [TENANT_A]

    @respx.mock
    def test_a_logged_in_caller_whose_tenant_is_unknown_is_refused(self, monkeypatch):
        api_says(with_identity=False)
        seen = []

        async def fake_stream(**kw):
            seen.append(1)
            yield {}

        monkeypatch.setattr(inv, "_investigate_stream", fake_stream)
        from app.main import app

        with pytest.raises(WebSocketDisconnect) as err:
            with TestClient(app).websocket_connect("/api/v1/investigations/r1/stream?case_id=c1&alert_summary=x", headers=BEARER) as ws:
                ws.receive_text()
        assert err.value.code == 4403 and seen == []


class TestInvestigationRunsAreVisibleOnlyToTheirTenant:
    """Runs were stored WITHOUT a tenant and no read route checked one: GET /investigations/{id}, the three report downloads, the case-scoped alias, the legacy read, the agents router read and the WebSocket
    tail all returned a run to whoever knew its id. (The paths are reachable directly; the console routes some of them elsewhere.)"""

    OWN, FOREIGN, UNKNOWN = "run-own", "run-victim", "run-nobody"

    @pytest.fixture(autouse=True)
    def runs(self):
        def make(rid, tenant):
            run = {"run_id": rid, "case_id": "c", "status": "completed", "report_md": f"# report for {tenant}", "report_html": f"<p>report for {tenant}</p>", "audit_log": [], "alert_id": "a"}
            if tenant is not None:
                run["tenant_id"] = tenant
            return run

        router_mod._runs.clear()
        for store in (inv._runs, router_mod._runs):  # both handlers answer /investigations/{id}: whichever is first must be safe
            store[self.OWN] = make(self.OWN, TENANT_A)
            store[self.FOREIGN] = make(self.FOREIGN, VICTIM)
            store["run-legacy"] = make("run-legacy", None)  # a run with no recorded tenant
        yield
        router_mod._runs.clear()

    ROUTES = [
        "/api/v1/investigations/{id}",
        "/api/v1/investigations/{id}/report.md",
        "/api/v1/investigations/{id}/report.html",
        "/api/v1/investigations/{id}/report.pdf",
        "/api/v1/cases/c/investigations/{id}/report.md",
        "/api/v1/agents/investigations/{id}",
    ]

    @respx.mock
    @pytest.mark.parametrize("route", ROUTES)
    def test_another_tenants_run_is_a_404_on_every_read_route(self, route):
        api_says(tenant=TENANT_A)
        r = client().get(route.format(id=self.FOREIGN), headers=BEARER)
        assert r.status_code == 404, route
        assert "victim" not in r.text and VICTIM not in r.text

    @respx.mock
    @pytest.mark.parametrize("route", ROUTES)
    def test_a_foreign_run_is_indistinguishable_from_one_that_does_not_exist(self, route):
        api_says(tenant=TENANT_A)
        c = client()
        foreign = c.get(route.format(id=self.FOREIGN), headers=BEARER)
        unknown = c.get(route.format(id=self.UNKNOWN), headers=BEARER)
        assert (foreign.status_code, foreign.json()) == (unknown.status_code, unknown.json()), route  # no oracle for which run ids exist

    @respx.mock
    @pytest.mark.parametrize("route", [r for r in ROUTES if not r.endswith(".pdf")])
    def test_a_tenant_still_reads_its_own_runs(self, route):
        api_says(tenant=TENANT_A)
        r = client().get(route.format(id=self.OWN), headers=BEARER)
        assert r.status_code == 200, (route, r.text)

    @respx.mock
    def test_the_report_content_is_the_owners_own(self):
        api_says(tenant=TENANT_A)
        assert client().get(f"/api/v1/investigations/{self.OWN}/report.md", headers=BEARER).text == f"# report for {TENANT_A}"

    @respx.mock
    @pytest.mark.parametrize("route", ROUTES)
    def test_a_run_with_no_recorded_tenant_is_not_shown_to_an_authenticated_caller(self, route):
        api_says(tenant=TENANT_A)
        assert client().get(route.format(id="run-legacy"), headers=BEARER).status_code == 404, route  # fail closed

    @pytest.mark.parametrize("route", [r for r in ROUTES if not r.endswith(".pdf")])
    def test_the_apis_proxy_can_still_read_any_run(self, route):
        assert client().get(route.format(id=self.FOREIGN), headers=INTERNAL_HEADERS).status_code == 200, route

    @pytest.mark.parametrize("route", [r for r in ROUTES if not r.endswith(".pdf")])
    def test_in_development_nothing_is_scoped(self, route, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "development")
        assert client().get(route.format(id=self.FOREIGN)).status_code == 200, route

    @respx.mock
    def test_the_websocket_will_not_tail_another_tenants_run(self):
        api_says(tenant=TENANT_A)
        from app.main import app

        with pytest.raises(WebSocketDisconnect) as err:
            with TestClient(app).websocket_connect(f"/api/v1/investigations/{self.FOREIGN}/stream", headers=BEARER) as ws:
                ws.receive_text()
        assert err.value.code == 4404

    @respx.mock
    def test_the_websocket_tails_the_owners_own_run(self):
        api_says(tenant=TENANT_A)
        from app.main import app

        with TestClient(app).websocket_connect(f"/api/v1/investigations/{self.OWN}/stream", headers=BEARER) as ws:
            assert '"done"' in ws.receive_text()


class TestRunsRecordTheirOwner:
    @respx.mock
    def test_a_launched_investigation_records_the_callers_tenant_and_the_owner_can_read_it_back(self, monkeypatch):
        api_says(tenant=TENANT_A)

        async def fake_run(run_id, case_id, req):
            pass

        monkeypatch.setattr(inv, "_run_and_store", fake_run)
        c = client()
        run_id = c.post("/api/v1/cases/c1/investigate", json={"alert_summary": "x", "tenant_id": VICTIM}, headers=BEARER).json()["run_id"]
        assert inv._runs[run_id]["tenant_id"] == TENANT_A  # recorded for the caller, not the body's claim
        router_mod._runs[run_id] = dict(inv._runs[run_id])
        assert c.get(f"/api/v1/investigations/{run_id}", headers=BEARER).status_code == 200
        api_says(tenant=VICTIM)
        service_auth.clear_cache()
        assert c.get(f"/api/v1/investigations/{run_id}", headers=BEARER).status_code == 404  # and nobody else can

    @respx.mock
    def test_the_agents_router_keeps_the_owner_after_the_run_completes_and_after_it_fails(self, monkeypatch):
        """_run_investigation REPLACES the whole record on completion and on failure; it must not drop the tenant, or the owner is locked out of their own finished run."""
        api_says(tenant=TENANT_A)
        outcomes = iter(["ok", "boom"])

        async def fake_full(state):
            if next(outcomes) == "boom":
                raise RuntimeError("investigation failed")
            return SimpleNamespace(to_dict=lambda: {"verdict": "benign"})

        monkeypatch.setattr(router_mod, "run_full_investigation", fake_full)
        c = client()
        ids = [c.post("/api/v1/investigations", json={"incident_id": str(uuid.uuid4()), "tenant_id": VICTIM, "alert_summary": "x"}, headers=BEARER).json()["run_id"] for _ in range(2)]
        for rid, status in zip(ids, ("completed", "failed"), strict=True):
            assert router_mod._runs[rid]["status"] == status and router_mod._runs[rid]["tenant_id"] == TENANT_A
            assert c.get(f"/api/v1/investigations/{rid}", headers=BEARER).status_code == 200  # the owner can still read it
            inv._runs.pop(rid, None)


class TestTheGapsMutationFound:
    @respx.mock
    def test_an_owner_can_poll_their_investigation_while_it_is_still_running(self, monkeypatch):
        """The background task rewrites the record (with the owner) on completion, so a test that lets it finish never sees the RUNNING window: the launch itself must record the owner, or the owner is locked
        out of polling their own in-flight run."""
        api_says(tenant=TENANT_A)

        async def never_completes(run_id, state):
            pass

        monkeypatch.setattr(router_mod, "_run_investigation", never_completes)
        c = client()
        run_id = c.post("/api/v1/investigations", json={"incident_id": str(uuid.uuid4()), "tenant_id": VICTIM, "alert_summary": "x"}, headers=BEARER).json()["run_id"]
        assert router_mod._runs[run_id]["status"] == "running" and router_mod._runs[run_id]["tenant_id"] == TENANT_A
        assert c.get(f"/api/v1/investigations/{run_id}", headers=BEARER).status_code == 200

    def test_the_investigate_modules_own_get_is_guarded_even_though_the_agents_router_shadows_its_path(self):
        """GET /api/v1/investigations/{id} is registered by BOTH routers and the first one wins, so the investigate module's version is unreachable over HTTP today. It is still live code, so it is exercised
        directly: if the routes are ever reordered it must not become an unguarded read."""
        import asyncio

        def req(caller):
            return SimpleNamespace(state=SimpleNamespace(caller=caller))

        inv._runs["mine"] = {"tenant_id": TENANT_A, "status": "running"}
        inv._runs["theirs"] = {"tenant_id": VICTIM, "status": "running"}
        mine = asyncio.run(inv.get_investigation("mine", req({"kind": "user", "tenant_id": TENANT_A})))
        assert mine["status"] == "running"
        with pytest.raises(HTTPException) as err:
            asyncio.run(inv.get_investigation("theirs", req({"kind": "user", "tenant_id": TENANT_A})))
        assert err.value.status_code == 404
        assert asyncio.run(inv.get_investigation("theirs", req({"kind": "internal"})))["tenant_id"] == VICTIM  # the API's proxy sees all
        assert asyncio.run(inv.get_investigation("theirs", req(None)))["tenant_id"] == VICTIM  # development: nothing enforced
