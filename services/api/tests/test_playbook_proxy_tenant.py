"""The API's playbook proxy tells the agents service WHICH tenant it is acting for: always the authenticated user's, never anything the client sent.

Playbooks are a shared read-only library plus each tenant's own (the agents service owns them). The API calls it with the INTERNAL token, which carries no tenant, so the tenant has to be named explicitly
on every call, or the agents service has no way to scope the request. Also: a 4xx from the agents service (e.g. "library playbooks are read-only, clone it") is passed through to the caller; 5xx stays generic.
"""
import uuid

import httpx
import pytest
import respx
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.v1 import deps
from app.api.v1.endpoints import playbooks as pb

TENANT = uuid.uuid4()
OTHER = uuid.uuid4()


def user(role="admin", tenant=TENANT):
    return deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role=role, email="a@example.test")


@pytest.fixture
def seen(monkeypatch):
    calls = []

    async def fake_proxy(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return {"ok": True}

    monkeypatch.setattr(pb, "_proxy", fake_proxy)
    return calls


def http(role="admin", tenant=TENANT) -> TestClient:
    app = FastAPI()
    app.include_router(pb.router)
    app.dependency_overrides[deps.get_current_user] = lambda: user(role, tenant)
    return TestClient(app, raise_server_exceptions=False)


class FakeRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


@pytest.mark.anyio
class TestEveryHandlerNamesTheAuthenticatedTenant:
    async def test_list(self, seen):
        await pb.list_playbooks(user(), enabled_only=True)
        assert seen == [("GET", "", {"params": {"enabled_only": True, "tenant_id": str(TENANT)}})]

    async def test_create(self, seen):
        await pb.create_playbook(FakeRequest({"name": "x", "tenant_id": str(OTHER)}), user())
        (_m, _p, kw), = seen
        assert kw["params"] == {"tenant_id": str(TENANT)}  # a tenant smuggled into the BODY is not what is named

    async def test_runs(self, seen):
        await pb.list_runs(user(), limit=5)
        assert seen[0][2]["params"] == {"limit": 5, "tenant_id": str(TENANT)}

    async def test_one_run(self, seen):
        await pb.get_run("run-1", user())
        assert seen[0][:2] == ("GET", "/runs/run-1") and seen[0][2]["params"] == {"tenant_id": str(TENANT)}

    async def test_get(self, seen):
        await pb.get_playbook("pb-1", user())
        assert seen[0][:2] == ("GET", "/pb-1") and seen[0][2]["params"] == {"tenant_id": str(TENANT)}

    async def test_update(self, seen):
        await pb.update_playbook("pb-1", FakeRequest({"name": "n"}), user())
        assert seen[0][:2] == ("PUT", "/pb-1") and seen[0][2]["params"] == {"tenant_id": str(TENANT)} and seen[0][2]["json"] == {"name": "n"}

    async def test_delete(self, seen):
        await pb.delete_playbook("pb-1", user())
        assert seen[0][:2] == ("DELETE", "/pb-1") and seen[0][2]["params"] == {"tenant_id": str(TENANT)}

    async def test_run(self, seen):
        await pb.run_playbook("pb-1", FakeRequest({"context": {"tenant_id": str(OTHER)}}), user())
        assert seen[0][:2] == ("POST", "/pb-1/run") and seen[0][2]["params"] == {"tenant_id": str(TENANT)}

    async def test_clone(self, seen):
        await pb.clone_playbook("pb-1", FakeRequest({"name": "Mine"}), user())
        assert seen[0][:2] == ("POST", "/pb-1/clone") and seen[0][2]["params"] == {"tenant_id": str(TENANT)} and seen[0][2]["json"] == {"name": "Mine"}

    @pytest.mark.parametrize("body", [ValueError("no body"), ["not", "a", "dict"], None])
    async def test_clone_tolerates_a_missing_or_odd_body(self, seen, body):
        await pb.clone_playbook("pb-1", FakeRequest(body), user())
        assert seen[0][2]["json"] == {}

    async def test_two_users_in_different_tenants_name_different_tenants(self, seen):
        await pb.list_playbooks(user(tenant=TENANT))
        await pb.list_playbooks(user(tenant=OTHER))
        assert [c[2]["params"]["tenant_id"] for c in seen] == [str(TENANT), str(OTHER)]


class TestTheCloneRoute:
    def test_it_is_mounted_on_the_real_api(self):
        from app.main import app

        assert {m.upper() for m in app.openapi()["paths"]["/api/v1/playbooks/{playbook_id}/clone"]} == {"POST"}

    def test_it_requires_playbooks_write(self, seen):
        from app.core.security import ROLE_PERMISSIONS, has_permission

        denied = [r for r in sorted(ROLE_PERMISSIONS) if not has_permission(r, "playbooks:write")]
        allowed = [r for r in sorted(ROLE_PERMISSIONS) if has_permission(r, "playbooks:write")]
        assert allowed and denied  # meaningful in both directions
        for role in denied:
            assert http(role).post("/playbooks/pb-1/clone").status_code == 403, role
        assert seen == []  # no refused caller reached the agents service
        for role in allowed:
            assert http(role).post("/playbooks/pb-1/clone", json={}).status_code == 201, role

    def test_a_malformed_playbook_id_is_refused_before_it_reaches_the_agents_service(self, seen):
        assert http().post("/playbooks/..%2F..%2Fx/clone").status_code in (404, 422)
        assert http().post("/playbooks/bad id!/clone").status_code == 422
        assert seen == []


@pytest.mark.anyio
class TestWhatTheCallerIsTold:
    """_proxy against a faked agents service."""

    @respx.mock
    async def test_a_4xx_explanation_is_passed_through(self):
        respx.put(url__regex=r".*/api/v1/playbooks/lib-1.*").mock(return_value=httpx.Response(403, json={"detail": "Shared library playbooks are read-only. Clone it into your tenant to customise it."}))
        with pytest.raises(HTTPException) as err:
            await pb._proxy("PUT", "/lib-1", json={"name": "x"})
        assert err.value.status_code == 403 and "Clone it" in err.value.detail

    @respx.mock
    async def test_a_validation_error_list_is_passed_through(self):
        respx.post(url__regex=r".*/api/v1/playbooks.*").mock(return_value=httpx.Response(422, json={"detail": [{"loc": ["steps"], "msg": "bad"}]}))
        with pytest.raises(HTTPException) as err:
            await pb._proxy("POST", "", json={})
        assert err.value.status_code == 422 and err.value.detail == [{"loc": ["steps"], "msg": "bad"}]

    @respx.mock
    @pytest.mark.parametrize("response", [httpx.Response(404, text="<html>not json</html>"), httpx.Response(400, json={}), httpx.Response(400, json=["a list, not an object"])])
    async def test_an_unreadable_4xx_falls_back_to_the_generic_message(self, response):
        respx.get(url__regex=r".*/api/v1/playbooks.*").mock(return_value=response)
        with pytest.raises(HTTPException) as err:
            await pb._proxy("GET", "/x")
        assert err.value.detail == "Upstream service error"

    @respx.mock
    @pytest.mark.parametrize("status_code", [500, 502, 503])
    async def test_a_5xx_never_leaks_what_the_upstream_said(self, status_code):
        respx.get(url__regex=r".*/api/v1/playbooks.*").mock(return_value=httpx.Response(status_code, json={"detail": "Traceback: password=hunter2 at /app/secret.py"}))
        with pytest.raises(HTTPException) as err:
            await pb._proxy("GET", "/x")
        assert err.value.status_code == status_code and err.value.detail == "Upstream service error"

    @respx.mock
    async def test_204_is_none_and_success_is_the_json(self):
        respx.delete(url__regex=r".*/api/v1/playbooks.*").mock(return_value=httpx.Response(204))
        respx.get(url__regex=r".*/api/v1/playbooks.*").mock(return_value=httpx.Response(200, json={"a": 1}))
        assert await pb._proxy("DELETE", "/x") is None
        assert await pb._proxy("GET", "/x") == {"a": 1}

    @respx.mock
    async def test_the_tenant_really_travels_to_the_agents_service(self):
        route = respx.get(url__regex=r".*/api/v1/playbooks.*").mock(return_value=httpx.Response(200, json=[]))
        await pb.list_playbooks(user(), enabled_only=False)
        assert route.calls[0].request.url.params["tenant_id"] == str(TENANT)

    @respx.mock
    async def test_an_unreachable_agents_service_is_a_503(self):
        respx.get(url__regex=r".*/api/v1/playbooks.*").mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(HTTPException) as err:
            await pb._proxy("GET", "")
        assert err.value.status_code == 503
