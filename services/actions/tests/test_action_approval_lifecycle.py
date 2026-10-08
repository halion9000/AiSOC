"""Response actions are stored durably, run at most once, and keep a truthful record.

The actions service kept every action in a process-local dict. Consequences, all fixed here:
  1. A restart lost pending approvals, ChatOps approval links and the record of what had run. Actions are now rows in `response_actions` (migration 055); these tests run against a real file-backed SQLite
     database and use a SECOND app on a brand-new engine as "the service restarted" (and as "another replica").
  2. approve_action rebuilt the request from a record that had dropped `parameters`, `requested_by`, `principal` and `auto_rollback`, so every action that needed approval executed WITHOUT its parameters.
     The complete original request is now stored and approval uses it.
  3. reject_action had no status check: rejecting an action that had ALREADY RUN rewrote its status to "rejected".
  4. approve_action left the status at "awaiting_approval" while the executor ran, so a second approval also executed the action (two host isolations). The claim is now one atomic conditional UPDATE.
  5. approve_action did not handle an executor exception (a 500 that left the action stuck) and dropped rollback_data and error.
  6. Submitting the same action id twice overwrote the record and executed the action twice; it now returns the existing record without executing again.
  7. Without a configured database the routes answer 503: they must not silently fall back to memory.
"""
import asyncio
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app import db as db_module
from app.api import router as router_module
from app.core import config as config_module
from app.db import Base, get_db, get_session_provider
from app.models.action import ActionRequest, ActionStatus, ActionType
from app.models.action_record import ActionRecord
from app.security.authz import require_service_auth
from app.security.chatops_token import mint_token
from app.services.executor_registry import EXECUTOR_REGISTRY

PARAMS = {"vendor": "crowdstrike", "duration_minutes": 30, "reason_code": "ransomware"}
SECRET = "chatops-test-secret-0123456789abcdef"


class FakeExecutor:
    def __init__(self, *, status=ActionStatus.COMPLETED, raises=None, gate=None, error=None):
        self.calls = 0
        self.requests: list[ActionRequest] = []
        self._status, self._raises, self._gate, self._error = status, raises, gate, error

    async def execute(self, request):
        self.calls += 1
        self.requests.append(request)
        if self._gate is not None:
            await self._gate.wait()
        if self._raises is not None:
            raise self._raises
        return SimpleNamespace(status=self._status, output={"isolated": request.target}, rollback_data={"undo": "release_host"}, error=self._error)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "actions.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine, tables=[ActionRecord.__table__])
    engine.dispose()
    return path


def make_app(db_path) -> FastAPI:
    """One 'service process': its own engine over the shared database."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    app = FastAPI()
    app.state.sessions_opened = 0  # how many database sessions this "process" has opened

    async def session():
        app.state.sessions_opened += 1
        async with factory() as s:
            yield s

    @asynccontextmanager
    async def scope():
        app.state.sessions_opened += 1
        async with factory() as s:
            yield s

    app.include_router(router_module.router)
    app.dependency_overrides[require_service_auth] = lambda: None
    app.dependency_overrides[get_db] = session
    app.dependency_overrides[get_session_provider] = lambda: scope
    return app


def make_request(action_type=ActionType.ISOLATE_HOST, **over) -> ActionRequest:
    fields = dict(
        incident_id=uuid.uuid4(), tenant_id=uuid.uuid4(), action_type=action_type, target="web-01", parameters=dict(PARAMS), requested_by="soc-bot",
        rationale="contain the host", auto_rollback=True, rollback_after_seconds=600,
    )
    fields.update(over)
    return ActionRequest(**fields)


def seed(db_path, status=ActionStatus.AWAITING_APPROVAL, action_type=ActionType.ISOLATE_HOST, *, result=None, requested_by_user_id=None, request=None) -> str:
    request = request or make_request(action_type)
    engine = create_engine(f"sqlite:///{db_path}")
    with Session(engine) as s:
        s.add(
            ActionRecord(
                id=request.id, tenant_id=request.tenant_id, incident_id=request.incident_id, action_type=action_type.value, target=request.target, status=status.value, blast_radius="high",
                gate_reason="needs approval", rationale=request.rationale, requested_by_user_id=requested_by_user_id, request=request.model_dump(mode="json"), result=result or {},
            )
        )
        s.commit()
    engine.dispose()
    return str(request.id)


def stored(db_path, action_id) -> ActionRecord | None:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            row = s.get(ActionRecord, uuid.UUID(action_id))
            if row is not None:
                s.expunge(row)
            return row
    finally:
        engine.dispose()


def count_rows(db_path) -> int:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with Session(engine) as s:
            return s.query(ActionRecord).count()
    finally:
        engine.dispose()


def register(monkeypatch, executor, action_type=ActionType.ISOLATE_HOST):
    monkeypatch.setitem(EXECUTOR_REGISTRY, action_type, executor)
    return executor


def submit_json(request: ActionRequest) -> dict:
    return request.model_dump(mode="json")


class TestReject:
    def test_an_action_awaiting_approval_can_be_rejected(self, db_path):
        aid = seed(db_path)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/reject")
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        assert stored(db_path, aid).status == "rejected"

    @pytest.mark.parametrize("status", [ActionStatus.COMPLETED, ActionStatus.FAILED, ActionStatus.ROLLED_BACK, ActionStatus.REJECTED, ActionStatus.RUNNING, ActionStatus.APPROVED, ActionStatus.PENDING])
    def test_an_action_in_any_other_state_cannot_be_rejected_and_is_left_exactly_as_it_was(self, db_path, status):
        aid = seed(db_path, status=status, result={"output": {"isolated": "web-01"}, "rollback_data": {"undo": "release_host"}})
        before = stored(db_path, aid)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/reject")
        assert r.status_code == 400
        assert "not awaiting approval" in r.json()["detail"] and status.value in r.json()["detail"]
        after = stored(db_path, aid)
        assert (after.status, after.result, after.updated_at) == (before.status, before.result, before.updated_at)  # a completed action is NOT rewritten to "rejected"

    def test_rejecting_an_unknown_or_malformed_id_is_a_404(self, db_path):
        client = TestClient(make_app(db_path))
        assert client.post(f"/actions/{uuid.uuid4()}/reject").status_code == 404
        assert client.post("/actions/not-a-uuid/reject").status_code == 404


class TestApprove:
    def test_an_approved_action_runs_once_and_keeps_its_output_and_rollback_data(self, db_path, monkeypatch):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed(db_path)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"
        assert body["output"] == {"isolated": "web-01"}
        assert body["rollback_data"] == {"undo": "release_host"}, "the approve path used to drop rollback_data, so an approved action could not be rolled back"
        assert executor.calls == 1
        assert stored(db_path, aid).result["rollback_data"] == {"undo": "release_host"}

    def test_the_executor_receives_the_ORIGINAL_request_parameters_and_all(self, db_path, monkeypatch):
        """THE high-stakes defect: approval rebuilt the request from a record that had dropped these fields, so every action that needed approval ran without its parameters."""
        executor = register(monkeypatch, FakeExecutor())
        original = make_request(parameters=dict(PARAMS), requested_by="soc-bot", auto_rollback=True, rollback_after_seconds=600)
        aid = seed(db_path, request=original)
        TestClient(make_app(db_path)).post(f"/actions/{aid}/approve")
        (received,) = executor.requests
        assert received.parameters == PARAMS
        assert received.requested_by == "soc-bot"
        assert received.auto_rollback is True and received.rollback_after_seconds == 600
        assert received.model_dump() == original.model_dump()  # not one field differs from what was submitted

    def test_the_approver_is_recorded(self, db_path, monkeypatch):
        register(monkeypatch, FakeExecutor())
        aid = seed(db_path, requested_by_user_id="requester-1")
        approver = {"user_id": "approver-9", "permissions": ["*"]}
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve", json=approver)
        assert r.status_code == 200, r.text
        assert r.json()["approved_by_user_id"] == "approver-9"
        assert stored(db_path, aid).approved_by_user_id == "approver-9"

    def test_an_approver_may_not_be_the_requester(self, db_path, monkeypatch):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed(db_path, requested_by_user_id="same-person")
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve", json={"user_id": "same-person", "permissions": ["*"]})
        assert r.status_code == 403
        assert executor.calls == 0 and stored(db_path, aid).status == "awaiting_approval"

    def test_an_executors_own_error_is_kept(self, db_path, monkeypatch):
        register(monkeypatch, FakeExecutor(status=ActionStatus.FAILED, error="firewall API said no"))
        aid = seed(db_path)
        body = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve").json()
        assert body["status"] == "failed" and body["error"] == "firewall API said no"

    def test_an_executor_that_raises_is_recorded_as_failed_not_a_500_that_leaves_the_action_stuck(self, db_path, monkeypatch):
        register(monkeypatch, FakeExecutor(raises=RuntimeError("edr unreachable")))
        aid = seed(db_path)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve")
        assert r.status_code == 200
        assert r.json()["status"] == "failed" and r.json()["error"] == "execution failed (RuntimeError)"
        assert stored(db_path, aid).status == "failed"  # not left "awaiting_approval" or "running"

    def test_no_executor_for_the_action_type_is_a_recorded_failure(self, db_path, monkeypatch):
        monkeypatch.delitem(EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, raising=False)
        aid = seed(db_path)
        body = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve").json()
        assert body["status"] == "failed" and body["error"] == "No executor available"

    @pytest.mark.parametrize("status", [ActionStatus.COMPLETED, ActionStatus.REJECTED, ActionStatus.RUNNING, ActionStatus.FAILED])
    def test_an_action_that_is_not_awaiting_approval_cannot_be_approved_and_is_not_executed(self, db_path, monkeypatch, status):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed(db_path, status=status)
        assert TestClient(make_app(db_path)).post(f"/actions/{aid}/approve").status_code == 400
        assert executor.calls == 0

    def test_approving_an_unknown_action_is_a_404(self, db_path):
        assert TestClient(make_app(db_path)).post(f"/actions/{uuid.uuid4()}/approve").status_code == 404

    def test_a_refused_approver_leaves_the_action_awaiting_and_unclaimed(self, db_path, monkeypatch):
        """Authorisation happens BEFORE the action is claimed: a refusal must not strand it in "running"."""
        executor = register(monkeypatch, FakeExecutor())
        monkeypatch.setattr(router_module, "get_settings", lambda: SimpleNamespace(AISOC_ACTIONS_REQUIRE_PRINCIPAL=True))
        aid = seed(db_path)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/approve")
        assert r.status_code == 403
        assert stored(db_path, aid).status == "awaiting_approval"
        assert executor.calls == 0


class TestAnActionRunsAtMostOnce:
    def test_a_second_approval_while_the_first_is_executing_is_refused_and_does_not_execute_again(self, db_path, monkeypatch):
        gate = asyncio.Event()
        executor = register(monkeypatch, FakeExecutor(gate=gate))
        aid = seed(db_path)

        async def scenario():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app(db_path)), base_url="http://test") as client:
                first = asyncio.create_task(client.post(f"/actions/{aid}/approve"))
                await asyncio.sleep(0.2)  # let the first approval claim the action and block in the executor
                mid_flight = stored(db_path, aid).status
                second = asyncio.create_task(client.post(f"/actions/{aid}/approve"))
                rejected = asyncio.create_task(client.post(f"/actions/{aid}/reject"))
                await asyncio.sleep(0.2)
                answered = second.done()  # if the action was NOT claimed, the second approval is ALSO blocked in the executor
                gate.set()
                return await first, await second, await rejected, mid_flight, answered

        first, second, rejected, mid_flight, answered = asyncio.run(scenario())
        assert mid_flight == "running"
        assert answered, "the second approval was not refused immediately: it is executing the action too"
        assert second.status_code == 400 and "running" in second.json()["detail"]
        assert rejected.status_code == 400  # it cannot be rejected out from under the executor either
        assert first.status_code == 200 and first.json()["status"] == "completed"
        assert executor.calls == 1, "the action was executed more than once"

    def test_approvals_through_DIFFERENT_processes_execute_exactly_once(self, db_path, monkeypatch):
        """Six independent apps (six engines, as six replicas would be) approve the same action at once. The claim is one atomic UPDATE in the database, so only one can win; an in-process flag could not do this."""
        gate = asyncio.Event()
        executor = register(monkeypatch, FakeExecutor(gate=gate))
        aid = seed(db_path)

        async def scenario():
            clients = [httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app(db_path)), base_url="http://test") for _ in range(6)]
            try:
                tasks = [asyncio.create_task(c.post(f"/actions/{aid}/approve")) for c in clients]
                await asyncio.sleep(0.5)
                gate.set()
                return [r.status_code for r in await asyncio.gather(*tasks)]
            finally:
                for c in clients:
                    await c.aclose()

        codes = asyncio.run(scenario())
        assert sorted(codes) == [200] + [400] * 5, codes
        assert executor.calls == 1


class TestSubmitting:
    def test_an_action_needing_approval_is_stored_with_its_complete_request(self, db_path):
        request = make_request()
        r = TestClient(make_app(db_path)).post("/actions", json=submit_json(request))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "awaiting_approval"
        row = stored(db_path, str(request.id))
        assert row.status == "awaiting_approval" and row.target == "web-01" and row.action_type == "isolate_host"
        assert ActionRequest.model_validate(row.request).model_dump() == request.model_dump()  # the whole request, parameters included

    def test_an_auto_approved_action_executes_once_and_the_outcome_is_stored(self, db_path, monkeypatch):
        executor = register(monkeypatch, FakeExecutor(), ActionType.NOTIFY_SLACK)
        request = make_request(ActionType.NOTIFY_SLACK, target="#soc")
        r = TestClient(make_app(db_path)).post("/actions", json=submit_json(request))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "completed" and r.json()["output"] == {"isolated": "#soc"}
        assert executor.calls == 1
        assert stored(db_path, str(request.id)).status == "completed"

    def test_submitting_the_same_id_again_returns_the_existing_record_and_does_not_execute_again(self, db_path, monkeypatch):
        """It used to overwrite the record AND run the action a second time (a client retry would isolate the host twice)."""
        executor = register(monkeypatch, FakeExecutor(), ActionType.NOTIFY_SLACK)
        request = make_request(ActionType.NOTIFY_SLACK, target="#soc")
        client = TestClient(make_app(db_path))
        first = client.post("/actions", json=submit_json(request)).json()
        second = client.post("/actions", json=submit_json(request))
        assert second.status_code == 200 and second.json() == first
        assert executor.calls == 1 and count_rows(db_path) == 1

    def test_a_failing_auto_executor_is_recorded(self, db_path, monkeypatch):
        register(monkeypatch, FakeExecutor(raises=RuntimeError("slack down")), ActionType.NOTIFY_SLACK)
        request = make_request(ActionType.NOTIFY_SLACK, target="#soc")
        body = TestClient(make_app(db_path)).post("/actions", json=submit_json(request)).json()
        assert body["status"] == "failed" and body["error"] == "execution failed (RuntimeError)"

    def test_a_denied_submission_stores_nothing(self, db_path, monkeypatch):
        monkeypatch.setattr(router_module, "authorize_action", lambda request: (_ for _ in ()).throw(router_module.ActionAuthzError("no permission")))
        r = TestClient(make_app(db_path)).post("/actions", json=submit_json(make_request()))
        assert r.status_code == 403 and count_rows(db_path) == 0


class TestItSurvivesARestart:
    def test_a_pending_action_can_be_approved_by_another_process_with_its_original_parameters(self, db_path, monkeypatch):
        executor = register(monkeypatch, FakeExecutor())
        request = make_request()
        TestClient(make_app(db_path)).post("/actions", json=submit_json(request))  # process A submits; it is awaiting approval
        r = TestClient(make_app(db_path)).post(f"/actions/{request.id}/approve")  # process B (a restarted service, or another replica) approves
        assert r.status_code == 200 and r.json()["status"] == "completed"
        assert executor.requests[0].parameters == PARAMS

    def test_the_record_is_readable_after_a_restart(self, db_path):
        request = make_request()
        TestClient(make_app(db_path)).post("/actions", json=submit_json(request))
        got = TestClient(make_app(db_path)).get(f"/actions/{request.id}")
        assert got.status_code == 200
        assert got.json()["id"] == str(request.id) and got.json()["status"] == "awaiting_approval" and got.json()["target"] == "web-01"

    def test_a_rejection_survives_a_restart(self, db_path):
        aid = seed(db_path)
        TestClient(make_app(db_path)).post(f"/actions/{aid}/reject")
        assert TestClient(make_app(db_path)).get(f"/actions/{aid}").json()["status"] == "rejected"

    def test_get_of_an_unknown_action_is_a_404(self, db_path):
        assert TestClient(make_app(db_path)).get(f"/actions/{uuid.uuid4()}").status_code == 404


class TestTheServedRecord:
    def test_a_stored_outcome_can_never_override_the_identity_and_status_of_the_action(self, db_path):
        """The served record is the identity columns plus the outcome. If outcome keys could win, a result containing "status" or "id" would falsify what the API reports."""
        aid = seed(db_path, result={"status": "completed", "id": "not-the-id", "target": "elsewhere", "action_type": "block_ip", "output": {"ok": True}})
        body = TestClient(make_app(db_path)).get(f"/actions/{aid}").json()
        assert body["id"] == aid and body["status"] == "awaiting_approval" and body["target"] == "web-01" and body["action_type"] == "isolate_host"
        assert body["output"] == {"ok": True}  # while real outcome fields are still served


class TestWithoutADatabase:
    def test_the_routes_answer_503_instead_of_silently_falling_back_to_memory(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "")
        config_module.get_settings.cache_clear()
        monkeypatch.setattr(db_module, "_factory", None)
        monkeypatch.setattr(db_module, "_engine", None)
        app = FastAPI()
        app.include_router(router_module.router)
        app.dependency_overrides[require_service_auth] = lambda: None  # (the real get_db is NOT overridden)
        try:
            client = TestClient(app)
            for method, path in (("get", f"/actions/{uuid.uuid4()}"), ("post", f"/actions/{uuid.uuid4()}/approve"), ("post", f"/actions/{uuid.uuid4()}/reject")):
                r = getattr(client, method)(path)
                assert r.status_code == 503, (method, path, r.status_code)
                assert "DATABASE_URL" in r.json()["detail"]
            assert client.post("/actions", json=submit_json(make_request())).status_code == 503
            # the public ChatOps callback: a forged link is still just refused (it never reaches the store) ...
            assert client.get("/chatops/callback?token=" + "a" * 40).status_code in (400, 503)
            assert client.get("/chatops/callback").status_code == 422
        finally:
            config_module.get_settings.cache_clear()


class TestChatOpsResponses:
    """The first ChatOps response to an action is recorded atomically in the database, so a replayed or double-clicked link is deduped even across a restart."""

    @pytest.fixture(autouse=True)
    def chatops(self, monkeypatch):
        monkeypatch.setattr(router_module, "get_settings", lambda: SimpleNamespace(AISOC_CHATOPS_RESPONSE_SECRET=SECRET, AISOC_ACTIONS_REQUIRE_PRINCIPAL=False))
        self.timeline: list[dict] = []

        async def fake_timeline(**kwargs):
            self.timeline.append(kwargs)

        monkeypatch.setattr(router_module, "post_timeline_event", fake_timeline)
        router_module._chatops_replied.clear()
        yield
        router_module._chatops_replied.clear()

    def link(self, action_id: str, choice="acknowledge") -> str:
        return "/chatops/callback?token=" + mint_token(
            action_id=uuid.UUID(action_id), case_id=uuid.uuid4(), tenant_id=uuid.uuid4(), choice=choice, user_ref="alice", secret=SECRET, ttl_seconds=900
        )

    def test_the_first_response_is_recorded_and_completes_the_action(self, db_path):
        aid = seed(db_path, status=ActionStatus.AWAITING_APPROVAL, action_type=ActionType.CHATOPS_VERIFY)
        r = TestClient(make_app(db_path)).get(self.link(aid))
        assert r.status_code == 200
        row = stored(db_path, aid)
        assert row.status == "completed" and row.chatops_responded_at is not None
        assert row.result["output"]["user_choice"] == "acknowledge" and row.result["output"]["user_ref"] == "alice"
        assert len(self.timeline) == 1

    def test_a_second_click_is_deduped(self, db_path):
        aid = seed(db_path, action_type=ActionType.CHATOPS_VERIFY)
        client = TestClient(make_app(db_path))
        link = self.link(aid)
        client.get(link)
        again = client.get(link)
        assert again.status_code == 200 and "already recorded" in again.text.lower()
        assert len(self.timeline) == 1  # not posted to the case timeline twice

    def test_a_replayed_link_is_still_deduped_after_a_restart(self, db_path):
        """The in-memory dedupe set was lost on restart, so a replayed link was accepted and posted to the timeline a second time."""
        aid = seed(db_path, action_type=ActionType.CHATOPS_VERIFY)
        link = self.link(aid)
        TestClient(make_app(db_path)).get(link)
        router_module._chatops_replied.clear()  # a restart empties the process's own memory
        again = TestClient(make_app(db_path)).get(link)  # served by a different process
        assert "already recorded" in again.text.lower()
        assert len(self.timeline) == 1

    def test_a_response_for_an_action_with_no_stored_row_still_works_and_is_deduped_in_process(self, db_path):
        aid = str(uuid.uuid4())  # nothing stored under this id
        client = TestClient(make_app(db_path))
        link = self.link(aid)
        assert client.get(link).status_code == 200
        assert "already recorded" in client.get(link).text.lower()
        assert len(self.timeline) == 1
        assert count_rows(db_path) == 0  # and it did not invent a row

    def test_a_forged_or_malformed_link_never_opens_a_database_session(self, db_path):
        """The callback is a PUBLIC route. A plain Depends(get_db) resolved before the route ran, i.e. before the signature was checked, so an unauthenticated request reached the database layer."""
        aid = seed(db_path, action_type=ActionType.CHATOPS_VERIFY)
        app = make_app(db_path)
        client = TestClient(app)
        assert client.get(self.link(aid) + "x").status_code == 400  # tampered signature
        assert client.get("/chatops/callback?token=" + "a" * 40).status_code == 400  # not a token at all
        assert client.get("/chatops/callback").status_code == 422  # no token
        assert app.state.sessions_opened == 0
        assert client.get(self.link(aid)).status_code == 200  # a genuine link opens exactly one
        assert app.state.sessions_opened == 1

    def test_a_tampered_link_is_refused_and_records_nothing(self, db_path):
        aid = seed(db_path, action_type=ActionType.CHATOPS_VERIFY)
        r = TestClient(make_app(db_path)).get(self.link(aid) + "x")
        assert r.status_code == 400
        assert stored(db_path, aid).chatops_responded_at is None and self.timeline == []


class TestStuckActions:
    """An action left in 'running' means the service stopped between claiming it and recording its outcome: it may or may not have executed, so it is never re-run. These let an operator find and settle it."""

    def test_stuck_actions_can_be_listed_by_status_and_age(self, db_path):
        stuck = seed(db_path, status=ActionStatus.RUNNING)
        fresh = seed(db_path, status=ActionStatus.RUNNING)
        seed(db_path, status=ActionStatus.COMPLETED)
        engine = create_engine(f"sqlite:///{db_path}")
        with Session(engine) as s:  # make one of the two running actions old
            from datetime import UTC, datetime, timedelta

            s.get(ActionRecord, uuid.UUID(stuck)).updated_at = datetime.now(UTC) - timedelta(hours=2)
            s.commit()
        engine.dispose()
        client = TestClient(make_app(db_path))
        everything_running = {a["id"] for a in client.get("/actions?status=running").json()["items"]}
        assert everything_running == {stuck, fresh}
        only_stuck = [a["id"] for a in client.get("/actions?status=running&older_than_seconds=900").json()["items"]]
        assert only_stuck == [stuck]  # the one claimed moments ago is not stuck, just running

    def test_listing_can_be_scoped_to_a_tenant(self, db_path):
        mine = make_request()
        seed(db_path, status=ActionStatus.RUNNING, request=mine)
        seed(db_path, status=ActionStatus.RUNNING)
        items = TestClient(make_app(db_path)).get(f"/actions?status=running&tenant_id={mine.tenant_id}").json()["items"]
        assert [a["id"] for a in items] == [str(mine.id)]
        assert TestClient(make_app(db_path)).get("/actions?tenant_id=not-a-uuid").json()["items"] == []

    @pytest.mark.parametrize("outcome", ["completed", "failed"])
    def test_an_operator_can_record_what_actually_happened(self, db_path, monkeypatch, outcome):
        executor = register(monkeypatch, FakeExecutor())
        aid = seed(db_path, status=ActionStatus.RUNNING)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": outcome, "note": "checked the EDR console: host is isolated", "resolved_by": "hal"})
        assert r.status_code == 200 and r.json()["status"] == outcome
        res = stored(db_path, aid).result["resolution"]
        assert res["note"] == "checked the EDR console: host is isolated" and res["resolved_by"] == "hal" and res["outcome"] == outcome and res["resolved_at"]
        assert executor.calls == 0, "resolving must NEVER execute the action"

    @pytest.mark.parametrize("status", [ActionStatus.AWAITING_APPROVAL, ActionStatus.COMPLETED, ActionStatus.FAILED, ActionStatus.REJECTED, ActionStatus.APPROVED])
    def test_only_a_running_action_can_be_resolved_and_others_are_left_untouched(self, db_path, status):
        aid = seed(db_path, status=status, result={"output": {"x": 1}})
        before = stored(db_path, aid)
        r = TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": "completed", "note": "trying to rewrite history"})
        assert r.status_code == 400 and "running" in r.json()["detail"]
        after = stored(db_path, aid)
        assert (after.status, after.result) == (before.status, before.result)

    def test_the_outcome_must_be_completed_or_failed(self, db_path):
        aid = seed(db_path, status=ActionStatus.RUNNING)
        for bad in ("rejected", "running", "awaiting_approval"):
            assert TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": bad, "note": "nope nope"}).status_code == 400
        assert TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": "bogus", "note": "nope nope"}).status_code == 422
        assert stored(db_path, aid).status == "running"

    def test_a_note_is_required(self, db_path):
        aid = seed(db_path, status=ActionStatus.RUNNING)
        assert TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": "failed"}).status_code == 422
        assert TestClient(make_app(db_path)).post(f"/actions/{aid}/resolve", json={"outcome": "failed", "note": "x"}).status_code == 422

    def test_resolving_an_unknown_action_is_a_404(self, db_path):
        assert TestClient(make_app(db_path)).post(f"/actions/{uuid.uuid4()}/resolve", json={"outcome": "failed", "note": "no such action"}).status_code == 404

    def test_two_operators_resolving_at_once_exactly_one_wins(self, db_path):
        aid = seed(db_path, status=ActionStatus.RUNNING)

        async def scenario():
            clients = [httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app(db_path)), base_url="http://test") for _ in range(5)]
            try:
                rs = await asyncio.gather(*[c.post(f"/actions/{aid}/resolve", json={"outcome": "completed" if i % 2 else "failed", "note": f"operator {i}"}) for i, c in enumerate(clients)])
                return sorted(r.status_code for r in rs)
            finally:
                for c in clients:
                    await c.aclose()

        assert asyncio.run(scenario()) == [200, 400, 400, 400, 400]
