"""A caller that says which tenant it acts for cannot reach another tenant's action, and a re-submitted id cannot return another tenant's record.

approve, reject and get looked an action up by its id alone, and submitting an id that already existed returned the stored record (target, rationale, parameters) whatever tenant
submitted it. Callers that name no tenant (the Slack bot) behave as before.
"""

import uuid

import pytest
from app.models.action import ActionPrincipal, ActionStatus
from fastapi.testclient import TestClient

from tests.test_action_approval_lifecycle import FakeExecutor, make_app, make_request, seed, stored  # noqa: F401
from app.models.action import ActionType
from app.services.executor_registry import EXECUTOR_REGISTRY


@pytest.fixture
def env(tmp_path, monkeypatch):
    from tests.test_action_approval_lifecycle import db_path as _unused  # noqa: F401
    from sqlalchemy import create_engine
    from app.db import Base
    from app.models.action_record import ActionRecord

    path = tmp_path / "actions.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine, tables=[ActionRecord.__table__])
    engine.dispose()
    executor = FakeExecutor()
    monkeypatch.setitem(EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, executor)
    return path, TestClient(make_app(path)), executor


def test_get_with_the_right_tenant_works_and_with_another_is_a_404(env):
    path, client, _ = env
    request = make_request()
    action_id = seed(path, request=request)
    assert client.get(f"/actions/{action_id}").status_code == 200  # no tenant named: unchanged
    assert client.get(f"/actions/{action_id}", params={"tenant_id": str(request.tenant_id)}).status_code == 200
    other = client.get(f"/actions/{action_id}", params={"tenant_id": str(uuid.uuid4())})
    assert other.status_code == 404 and "another tenant" not in other.text  # not an oracle for "exists elsewhere"


def test_approve_with_another_tenant_neither_executes_nor_changes_the_action(env):
    path, client, executor = env
    request = make_request()
    action_id = seed(path, request=request)
    res = client.post(f"/actions/{action_id}/approve", params={"tenant_id": str(uuid.uuid4())})
    assert res.status_code == 404
    assert executor.calls == 0
    assert stored(path, action_id).status == ActionStatus.AWAITING_APPROVAL.value
    ok = client.post(f"/actions/{action_id}/approve", params={"tenant_id": str(request.tenant_id)})
    assert ok.status_code == 200 and executor.calls == 1


def test_reject_with_another_tenant_leaves_the_action_awaiting_approval(env):
    path, client, _ = env
    request = make_request()
    action_id = seed(path, request=request)
    assert client.post(f"/actions/{action_id}/reject", params={"tenant_id": str(uuid.uuid4())}).status_code == 404
    assert stored(path, action_id).status == ActionStatus.AWAITING_APPROVAL.value
    assert client.post(f"/actions/{action_id}/reject", params={"tenant_id": str(request.tenant_id)}).status_code == 200


def test_an_approver_of_another_tenant_cannot_approve(env):
    path, client, executor = env
    request = make_request()
    action_id = seed(path, request=request)
    outsider = ActionPrincipal(user_id="eve", tenant_id=uuid.uuid4(), permissions=["actions:execute:high"]).model_dump(mode="json")
    res = client.post(f"/actions/{action_id}/approve", json=outsider)
    assert res.status_code == 403
    assert executor.calls == 0 and stored(path, action_id).status == ActionStatus.AWAITING_APPROVAL.value


def test_resubmitting_an_existing_id_as_another_tenant_does_not_return_the_stored_record(env):
    path, client, executor = env
    original = make_request()
    seed(path, request=original)
    clash = original.model_copy(update={"tenant_id": uuid.uuid4(), "target": "someone-elses-host"})
    res = client.post("/actions", json=clash.model_dump(mode="json"))
    assert res.status_code == 409
    assert "web-01" not in res.text and original.rationale not in res.text
    assert executor.calls == 0


def test_resubmitting_the_same_id_as_the_same_tenant_still_returns_the_existing_record(env):
    path, client, _ = env
    original = make_request()
    seed(path, request=original)
    res = client.post("/actions", json=original.model_dump(mode="json"))
    assert res.status_code == 200 and res.json()["id"] == str(original.id)
