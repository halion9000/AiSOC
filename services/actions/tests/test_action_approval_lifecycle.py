"""Approving and rejecting a response action: the record stays truthful, and an action runs at most once.

Three defects, all in services/actions/app/api/router.py:
  1. reject_action had NO status check, so rejecting an action that had ALREADY RUN rewrote its status to "rejected": the record of a response action that really executed (a host isolated, an account
     disabled) said it had been refused.
  2. approve_action left the status at "awaiting_approval" for the whole duration of `await executor.execute(...)`, so a second approval arriving meanwhile passed the check and executed the action AGAIN
     (two host isolations, two account disables).
  3. approve_action did not handle an executor exception (unlike submit_action): a 500 that left the action stuck awaiting approval; and unlike submit it dropped `rollback_data` and `error`, so an approved
     action could not be rolled back.
"""
import asyncio
import uuid
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import router as router_module
from app.models.action import ActionStatus, ActionType
from app.security.authz import require_service_auth
from app.services.executor_registry import EXECUTOR_REGISTRY


class FakeExecutor:
    def __init__(self, *, status=ActionStatus.COMPLETED, raises=None, gate=None, error=None):
        self.calls = 0
        self._status, self._raises, self._gate, self._error = status, raises, gate, error

    async def execute(self, request):
        self.calls += 1
        if self._gate is not None:
            await self._gate.wait()
        if self._raises is not None:
            raise self._raises
        return SimpleNamespace(status=self._status, output={"isolated": request.target}, rollback_data={"undo": "release_host"}, error=self._error)


def make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[require_service_auth] = lambda: None
    return app


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    router_module._actions.clear()
    yield
    router_module._actions.clear()


def seed(status=ActionStatus.AWAITING_APPROVAL, action_type=ActionType.ISOLATE_HOST, **extra) -> str:
    action_id = str(uuid.uuid4())
    router_module._actions[action_id] = {
        "id": action_id, "action_type": action_type.value, "target": "web-01", "status": status, "blast_radius": "high", "gate_reason": "needs approval",
        "incident_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()), "rationale": "contain the host", "requested_by_user_id": None, **extra,
    }
    return action_id


def register(monkeypatch, executor, action_type=ActionType.ISOLATE_HOST):
    monkeypatch.setitem(EXECUTOR_REGISTRY, action_type, executor)
    return executor


class TestReject:
    def test_an_action_awaiting_approval_can_be_rejected(self):
        aid = seed()
        r = TestClient(make_app()).post(f"/actions/{aid}/reject")
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        assert router_module._actions[aid]["status"] == ActionStatus.REJECTED

    @pytest.mark.parametrize("status", [ActionStatus.COMPLETED, ActionStatus.FAILED, ActionStatus.ROLLED_BACK, ActionStatus.REJECTED, ActionStatus.RUNNING, ActionStatus.APPROVED, ActionStatus.PENDING])
    def test_an_action_in_any_other_state_cannot_be_rejected_and_is_left_exactly_as_it_was(self, status):
        aid = seed(status=status, output={"isolated": "web-01"}, rollback_data={"undo": "release_host"})
        before = dict(router_module._actions[aid])
        r = TestClient(make_app()).post(f"/actions/{aid}/reject")
        assert r.status_code == 400
        assert "not awaiting approval" in r.json()["detail"]
        assert router_module._actions[aid] == before  # a completed action is NOT rewritten to "rejected"

    def test_rejecting_an_unknown_action_is_a_404(self):
        assert TestClient(make_app()).post(f"/actions/{uuid.uuid4()}/reject").status_code == 404


class TestApprove:
    def test_an_approved_action_runs_once_and_keeps_its_output_and_rollback_data(self, monkeypatch):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed()
        r = TestClient(make_app()).post(f"/actions/{aid}/approve")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"
        assert body["output"] == {"isolated": "web-01"}
        assert body["rollback_data"] == {"undo": "release_host"}, "the approve path used to drop rollback_data, so an approved action could not be rolled back"
        assert executor.calls == 1

    def test_an_executors_own_error_is_kept(self, monkeypatch):
        register(monkeypatch, FakeExecutor(status=ActionStatus.FAILED, error="firewall API said no"))
        aid = seed()
        body = TestClient(make_app()).post(f"/actions/{aid}/approve").json()
        assert body["status"] == "failed" and body["error"] == "firewall API said no"

    def test_an_executor_that_raises_is_recorded_as_failed_not_a_500_that_leaves_the_action_stuck(self, monkeypatch):
        register(monkeypatch, FakeExecutor(raises=RuntimeError("edr unreachable")))
        aid = seed()
        r = TestClient(make_app()).post(f"/actions/{aid}/approve")
        assert r.status_code == 200
        assert r.json()["status"] == "failed" and r.json()["error"] == "execution failed (RuntimeError)"
        assert router_module._actions[aid]["status"] == ActionStatus.FAILED  # not left "awaiting_approval"

    def test_no_executor_for_the_action_type_is_a_recorded_failure(self, monkeypatch):
        monkeypatch.delitem(EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, raising=False)
        aid = seed()
        body = TestClient(make_app()).post(f"/actions/{aid}/approve").json()
        assert body["status"] == "failed" and body["error"] == "No executor available"

    @pytest.mark.parametrize("status", [ActionStatus.COMPLETED, ActionStatus.REJECTED, ActionStatus.RUNNING, ActionStatus.FAILED])
    def test_an_action_that_is_not_awaiting_approval_cannot_be_approved_and_is_not_executed(self, monkeypatch, status):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed(status=status)
        r = TestClient(make_app()).post(f"/actions/{aid}/approve")
        assert r.status_code == 400
        assert executor.calls == 0

    def test_approving_an_unknown_action_is_a_404(self):
        assert TestClient(make_app()).post(f"/actions/{uuid.uuid4()}/approve").status_code == 404

    def test_a_refused_approver_leaves_the_action_awaiting_and_unclaimed(self, monkeypatch):
        """Authorisation happens BEFORE the action is claimed: a refusal must not strand it in "running"."""
        executor = register(monkeypatch, FakeExecutor())
        monkeypatch.setattr(router_module, "get_settings", lambda: SimpleNamespace(AISOC_ACTIONS_REQUIRE_PRINCIPAL=True))
        aid = seed()
        r = TestClient(make_app()).post(f"/actions/{aid}/approve")
        assert r.status_code == 403
        assert router_module._actions[aid]["status"] == ActionStatus.AWAITING_APPROVAL
        assert executor.calls == 0


class TestAnActionRunsAtMostOnce:
    def test_a_second_approval_while_the_first_is_executing_is_refused_and_does_not_execute_again(self, monkeypatch):
        """The race: two approvals close together. Both used to pass the status check and both executed the action."""
        gate = asyncio.Event()
        executor = register(monkeypatch, FakeExecutor(gate=gate))
        aid = seed()

        async def scenario():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()), base_url="http://test") as client:
                first = asyncio.create_task(client.post(f"/actions/{aid}/approve"))
                await asyncio.sleep(0.05)  # let the first approval reach the executor and block there
                mid_flight = router_module._actions[aid]["status"]
                second = asyncio.create_task(client.post(f"/actions/{aid}/approve"))
                rejected_mid_flight = asyncio.create_task(client.post(f"/actions/{aid}/reject"))
                await asyncio.sleep(0.1)
                # If the action was NOT claimed, the second approval is ALSO blocked inside the executor and is not finished yet. Release the gate either way, so a failure is a clear
                # assertion below rather than a deadlock.
                second_answered_while_first_was_executing = second.done()
                gate.set()
                return await first, await second, await rejected_mid_flight, mid_flight, second_answered_while_first_was_executing

        first, second, rejected_mid_flight, mid_flight, answered = asyncio.run(scenario())
        assert answered, "the second approval was not refused immediately: it is executing the action too"
        assert mid_flight == ActionStatus.RUNNING  # claimed while executing
        assert second.status_code == 400 and "running" in second.json()["detail"]
        assert rejected_mid_flight.status_code == 400  # and it cannot be rejected out from under the executor either
        assert first.status_code == 200 and first.json()["status"] == "completed"
        assert executor.calls == 1, "the action was executed more than once"

    def test_many_simultaneous_approvals_execute_exactly_once(self, monkeypatch):
        gate = asyncio.Event()
        executor = register(monkeypatch, FakeExecutor(gate=gate))
        aid = seed()

        async def scenario():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()), base_url="http://test") as client:
                tasks = [asyncio.create_task(client.post(f"/actions/{aid}/approve")) for _ in range(10)]
                await asyncio.sleep(0.1)
                gate.set()
                return [r.status_code for r in await asyncio.gather(*tasks)]

        codes = asyncio.run(scenario())
        assert sorted(codes) == [200] + [400] * 9
        assert executor.calls == 1
