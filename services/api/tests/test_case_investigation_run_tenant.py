"""GET /cases/{case_id}/investigations/{run_id} only returns a run that belongs to the caller's tenant.

The handler proxies the read to the agents service with the INTERNAL token, which the agents service trusts without scoping (the API is supposed to have authorised the caller), and then returned whatever
came back: any user who knew a run id could read any tenant's investigation. The check belongs here, where the caller's tenant is known.
"""
import uuid

import httpx
import pytest
from fastapi import HTTPException

from app.api.v1 import deps
from app.api.v1.endpoints import cases as cases_ep

MINE, THEIRS = uuid.uuid4(), uuid.uuid4()


def user(tenant=MINE):
    return deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant, role="admin", email="a@example.test")


@pytest.fixture
def agents(monkeypatch):
    """Fake the agents service: a dict of run_id -> (status, json)."""
    store: dict = {}
    calls = []

    async def fake_proxy(method, path, **kwargs):
        calls.append((method, path))
        run_id = path.rsplit("/", 1)[-1]
        status, body = store.get(run_id, (404, {"detail": "Investigation run not found"}))
        return httpx.Response(status, json=body)

    monkeypatch.setattr(cases_ep, "_agents_proxy", fake_proxy)
    store["calls"] = calls
    return store


async def read(run_id, who=None):
    return await cases_ep.case_investigation_run("case-1", run_id, who or user())


@pytest.mark.anyio
async def test_a_tenant_reads_its_own_run(agents):
    agents["r1"] = (200, {"run_id": "r1", "tenant_id": str(MINE), "status": "completed"})
    assert (await read("r1"))["status"] == "completed"


@pytest.mark.anyio
async def test_another_tenants_run_is_a_404(agents):
    agents["r2"] = (200, {"run_id": "r2", "tenant_id": str(THEIRS), "status": "completed", "report_md": "victim secrets"})
    with pytest.raises(HTTPException) as err:
        await read("r2")
    assert err.value.status_code == 404 and "victim" not in str(err.value.detail)


@pytest.mark.anyio
async def test_a_foreign_run_answers_exactly_like_an_unknown_one(agents):
    """No oracle for which run ids exist."""
    agents["foreign"] = (200, {"tenant_id": str(THEIRS)})
    with pytest.raises(HTTPException) as foreign:
        await read("foreign")
    with pytest.raises(HTTPException) as unknown:
        await read("does-not-exist")
    assert (foreign.value.status_code, foreign.value.detail) == (unknown.value.status_code, unknown.value.detail)


@pytest.mark.anyio
@pytest.mark.parametrize("body", [{"run_id": "x"}, {"run_id": "x", "tenant_id": None}, {"run_id": "x", "tenant_id": ""}, ["not", "a", "dict"], "a string", 7])
async def test_a_run_with_no_recorded_owner_or_an_odd_shape_is_refused(agents, body):
    agents["odd"] = (200, body)
    with pytest.raises(HTTPException) as err:
        await read("odd")
    assert err.value.status_code == 404  # fail closed


@pytest.mark.anyio
async def test_agents_errors_still_pass_through(agents):
    agents["boom"] = (502, {"detail": "upstream"})
    with pytest.raises(HTTPException) as err:
        await read("boom")
    assert err.value.status_code == 502


@pytest.mark.anyio
async def test_the_comparison_is_by_value_not_by_type(agents):
    agents["u"] = (200, {"tenant_id": str(MINE).upper().lower()})
    assert (await read("u"))["tenant_id"] == str(MINE)  # a UUID object vs its string form compares equal


@pytest.mark.anyio
async def test_the_run_id_cannot_inject_path_syntax(agents):
    with pytest.raises(HTTPException):
        await read("../../secrets?x=1#frag")
    assert all("/../" not in path and "?" not in path and "#" not in path for _m, path in agents["calls"])
