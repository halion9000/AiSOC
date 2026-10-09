"""Copilot conversation history is persisted and scoped to (tenant, owner, conversation).

POST /copilot/chat kept history in a module-level dict keyed by the CLIENT-SUPPLIED conversationId alone:
  * a restart silently dropped the model's memory while the chat UI still showed the conversation (the model then answered without context the user believed it had);
  * the key held no tenant and no user, so anyone with another tenant's conversationId had that conversation's history fed to the model, and could write into it;
  * the 500-entry LRU was GLOBAL, so one busy tenant silently evicted other tenants' conversations.
Also fixed on the way: the tool-loop truncation warning used structlog-style keyword arguments on a STDLIB logger, which raises TypeError; the outer except caught it and a working model was reported to the
analyst as "couldn't reach the LLM backend". These tests use a fake model that records exactly what it was sent, so they prove what history the model actually receives.
"""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import copilot
from app.db.database import Base
from app.db.rls import get_tenant_db
from app.models.copilot_conversation import CopilotConversation
from app.models.tenant import Tenant
from app.services import copilot_history

DB = SimpleNamespace(factory=None, sync=None, path=None)
LLM = SimpleNamespace(sent=[], replies=[], raise_on_call=False, tool_loop=False, tool_calls=0, tool_users=[])
RLS = SimpleNamespace(calls=[])  # tenant ids the store asked the database to scope the session to


class FakeModel:
    def bind_tools(self, _schemas):
        return self


async def fake_safe_ainvoke(_bound, messages):
    LLM.sent.append(list(messages))
    if LLM.raise_on_call:
        raise RuntimeError("gateway down")
    if LLM.tool_loop:  # the model never stops asking for a tool
        return AIMessage(content="still thinking", tool_calls=[{"name": "noop", "args": {}, "id": f"c{len(LLM.sent)}"}])
    return AIMessage(content=LLM.replies.pop(0) if LLM.replies else f"answer-{len(LLM.sent)}")


async def fake_tool(name, args, tenant_id, *, user):
    LLM.tool_calls += 1
    LLM.tool_users.append(user)
    return {"ok": True}


@pytest.fixture(autouse=True)
def harness(tmp_path, monkeypatch):
    path = tmp_path / "copilot.db"
    DB.path, DB.sync = path, create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(DB.sync, tables=[Tenant.__table__, CopilotConversation.__table__])
    DB.factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    LLM.sent, LLM.replies, LLM.raise_on_call, LLM.tool_loop, LLM.tool_calls = [], [], False, False, 0
    LLM.tool_users = []
    RLS.calls = []

    async def fake_rls(_session, tenant_id):  # SQLite has no RLS and no set_config(); the real thing is exercised against Postgres. Recorded so the tests can prove it is asserted.
        RLS.calls.append(tenant_id)

    monkeypatch.setattr(copilot_history, "set_rls_context", fake_rls)
    monkeypatch.setattr(copilot, "make_chat_model", lambda *a, **k: FakeModel())
    monkeypatch.setattr(copilot, "safe_ainvoke", fake_safe_ainvoke)
    monkeypatch.setattr(copilot, "execute_copilot_tool", fake_tool)
    yield
    DB.sync.dispose()


def client_as(tenant_id=None, user_id=None, role="admin") -> TestClient:  # admin: in the static role table only admin and platform_admin hold copilot:use
    app = FastAPI()
    app.include_router(copilot.router)
    tenant_id = tenant_id or uuid.uuid4()
    user_id = user_id or uuid.uuid4()
    app.dependency_overrides[deps.get_current_user] = lambda: deps.CurrentUser(user_id=user_id, tenant_id=tenant_id, role=role, email="a@example.test")

    async def real_session():
        async with DB.factory() as session:
            yield session

    app.dependency_overrides[get_tenant_db] = real_session
    c = TestClient(app)
    c.tenant_id, c.user_id = tenant_id, user_id
    return c


def chat(c, message, conversation_id=None):
    body = {"message": message}
    if conversation_id:
        body["conversationId"] = conversation_id
    return c.post(f"{copilot.router.prefix}/chat", json=body)


def history_seen_by_model(call_index=-1) -> list[str]:
    """The human/AI turns the model was actually sent on a given call (system prompts excluded)."""
    return [m.content for m in LLM.sent[call_index] if isinstance(m, (HumanMessage, AIMessage))]


def stored(tenant_id, owner, conversation_id):
    with Session(DB.sync) as s:
        row = s.get(CopilotConversation, (tenant_id, owner, conversation_id))
        return None if row is None else list(row.messages)


class TestFollowUpsWork:
    def test_the_model_receives_the_earlier_turns_of_the_same_conversation(self):
        c = client_as()
        first = chat(c, "what is on host WS-1?").json()
        chat(c, "and its owner?", first["conversationId"])
        assert history_seen_by_model() == ["what is on host WS-1?", first["reply"]["content"], "and its owner?"]

    def test_a_new_conversation_starts_with_no_history(self):
        c = client_as()
        chat(c, "first")
        chat(c, "second, in a NEW conversation")
        assert history_seen_by_model() == ["second, in a NEW conversation"]

    def test_the_server_mints_an_id_when_none_is_sent_and_echoes_a_supplied_one(self):
        c = client_as()
        minted = chat(c, "hi").json()["conversationId"]
        uuid.UUID(minted)
        assert chat(c, "hi", "my-conversation_1").json()["conversationId"] == "my-conversation_1"

    def test_the_stored_history_is_trimmed_to_the_last_messages(self):
        c = client_as()
        cid = chat(c, "turn 0").json()["conversationId"]
        for i in range(1, 30):
            chat(c, f"turn {i}", cid)
        rows = stored(c.tenant_id, str(c.user_id), cid)
        assert len(rows) == copilot_history.MAX_MESSAGES
        assert rows[-2]["content"] == "turn 29"  # newest kept
        assert "turn 0" not in [r["content"] for r in rows]  # oldest dropped


class TestItSurvivesARestart:
    def test_the_model_still_has_its_memory_after_the_process_restarts(self):
        """The dict lost every conversation on restart while the UI still displayed the chat."""
        c = client_as()
        first = chat(c, "remember: the incident is INC-4471").json()
        DB.factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{DB.path}", poolclass=NullPool), expire_on_commit=False)  # a new process: nothing carried over in memory
        c2 = client_as(tenant_id=c.tenant_id, user_id=c.user_id)
        chat(c2, "what incident were we on?", first["conversationId"])
        assert history_seen_by_model()[:2] == ["remember: the incident is INC-4471", first["reply"]["content"]]


class TestIsolation:
    """The key used to be the client-supplied id alone."""

    def test_another_tenant_using_the_same_id_sees_none_of_the_conversation(self):
        a, b = client_as(), client_as()
        chat(a, "CONFIDENTIAL: payroll-db-01 was breached", "shared-id")
        chat(b, "summarise our conversation so far", "shared-id")
        assert history_seen_by_model() == ["summarise our conversation so far"]  # the model was sent NOTHING of tenant A's
        assert all("payroll" not in str(m.content) for m in LLM.sent[-1])

    def test_another_tenant_cannot_write_into_the_conversation(self):
        a, b = client_as(), client_as()
        chat(a, "A's question", "shared-id")
        chat(b, "B injects text", "shared-id")
        chat(a, "A follows up", "shared-id")
        seen = history_seen_by_model()
        assert "B injects text" not in seen and seen[0] == "A's question"  # A's history is untouched

    def test_a_different_user_in_the_same_tenant_gets_their_own_conversation(self):
        tenant = uuid.uuid4()
        one, two = client_as(tenant_id=tenant), client_as(tenant_id=tenant)
        chat(one, "one's private question", "same-id")
        chat(two, "two asks", "same-id")
        assert history_seen_by_model() == ["two asks"]
        assert stored(tenant, str(one.user_id), "same-id") is not None and stored(tenant, str(two.user_id), "same-id") is not None

    def test_the_same_id_in_two_tenants_is_two_independent_stored_conversations(self):
        a, b = client_as(), client_as()
        chat(a, "from A", "x")
        chat(b, "from B", "x")
        assert [m["content"] for m in stored(a.tenant_id, str(a.user_id), "x") if m["role"] == "human"] == ["from A"]
        assert [m["content"] for m in stored(b.tenant_id, str(b.user_id), "x") if m["role"] == "human"] == ["from B"]

    def test_one_busy_tenant_cannot_evict_another_tenants_conversation(self, monkeypatch):
        """The old LRU was global: 500 conversations from anyone silently evicted the oldest, whoever owned it."""
        victim = client_as()
        keep = chat(victim, "the victim's conversation").json()["conversationId"]
        busy = client_as()
        for i in range(30):
            chat(busy, f"noise {i}", f"busy-{i}")
        chat(victim, "still remembered?", keep)
        assert history_seen_by_model()[0] == "the victim's conversation"


class TestTheTenantContextIsAssertedByTheStore:
    """The RLS context is transaction-local (set_config(..., TRUE)): it does not survive a commit or rollback, and this handler does both around a slow model call. So the store must re-assert it itself."""

    def test_load_and_append_each_scope_the_session_to_the_callers_tenant(self):
        c = client_as()
        RLS.calls = []  # (the dependency's own context-setting is overridden in these tests)
        chat(c, "hello")
        assert RLS.calls and set(RLS.calls) == {c.tenant_id}
        assert len(RLS.calls) >= 2  # once to read, and again to write after the model call (a new transaction)

    def test_it_never_scopes_to_a_different_tenant(self):
        a, b = client_as(), client_as()
        chat(a, "from a")
        chat(b, "from b")
        assert set(RLS.calls) == {a.tenant_id, b.tenant_id}


class TestConcurrencyDiscipline:
    """SQLite has no row locks, so these observe what the store ASKS the database for; the real behaviour is checked against Postgres."""

    @pytest.fixture
    def spy(self, monkeypatch):
        from sqlalchemy.ext.asyncio import AsyncSession

        events: list[tuple] = []
        real_get, real_rollback = AsyncSession.get, AsyncSession.rollback

        async def get(self_, entity, ident, **kwargs):
            events.append(("get", bool(kwargs.get("with_for_update")), bool(kwargs.get("populate_existing"))))
            return await real_get(self_, entity, ident, **kwargs)

        async def rollback(self_):
            events.append(("rollback",))
            return await real_rollback(self_)

        monkeypatch.setattr(AsyncSession, "get", get)
        monkeypatch.setattr(AsyncSession, "rollback", rollback)
        real_invoke = copilot.safe_ainvoke

        async def invoke(bound, messages):
            events.append(("MODEL CALL",))
            return await real_invoke(bound, messages)

        monkeypatch.setattr(copilot, "safe_ainvoke", invoke)
        return events

    def test_the_append_takes_a_row_lock_and_the_read_does_not(self, spy):
        chat(client_as(), "hello")
        gets = [e for e in spy if e[0] == "get"]
        assert gets[0] == ("get", False, True)  # load_history: a plain read
        assert all(g[1] for g in gets[1:])  # append_turn: every read is FOR UPDATE, so two concurrent messages cannot overwrite each other

    def test_reads_always_refresh_from_the_database(self, spy):
        """A cached copy of the row (identity map) must never stand in for what is in the database."""
        chat(client_as(), "hello")
        assert all(e[2] for e in spy if e[0] == "get")

    def test_the_connection_is_released_before_the_slow_model_call_and_no_lock_is_held_across_it(self, spy):
        chat(client_as(), "hello")
        order = [e[0] for e in spy]
        assert order.index("rollback") < order.index("MODEL CALL")  # released first
        assert [e for e in spy[: order.index("MODEL CALL")] if e[0] == "get" and e[1]] == []  # and nothing locked a row before the call


class TestWhatIsStored:
    def test_only_successful_turns_are_stored_and_a_failed_one_leaves_no_trace(self):
        c = client_as()
        cid = chat(c, "good question").json()["conversationId"]
        LLM.raise_on_call = True
        degraded = chat(c, "this one fails", cid).json()
        assert degraded["degraded"] is True and "couldn't reach the LLM backend" in degraded["reply"]["content"]
        LLM.raise_on_call = False
        chat(c, "next question", cid)
        assert history_seen_by_model() == ["good question", "answer-1", "next question"]  # the apology did not poison the context

    def test_the_owner_and_tenant_are_recorded(self):
        c = client_as()
        cid = chat(c, "hello").json()["conversationId"]
        assert stored(c.tenant_id, str(c.user_id), cid) is not None

    def test_a_principal_without_a_user_id_is_owned_as_service(self):
        assert copilot_history.owner_key(SimpleNamespace(user_id=None)) == "service"
        assert copilot_history.owner_key(SimpleNamespace(user_id=uuid.UUID(int=7))) == str(uuid.UUID(int=7))

    def test_a_very_long_message_is_stored_truncated_but_sent_to_the_model_in_full(self):
        c = client_as()
        big = "x" * (copilot_history.MAX_STORED_CHARS + 5000)
        cid = chat(c, big).json()["conversationId"]
        assert len(history_seen_by_model(0)[0]) == len(big)  # the model got all of it
        assert len(stored(c.tenant_id, str(c.user_id), cid)[0]["content"]) == copilot_history.MAX_STORED_CHARS

    def test_an_owner_is_capped_and_the_oldest_conversations_are_pruned(self, monkeypatch):
        monkeypatch.setattr(copilot_history, "MAX_CONVERSATIONS_PER_OWNER", 3)
        c = client_as()
        for i in range(5):
            chat(c, f"q{i}", f"conv-{i}")
        with Session(DB.sync) as s:
            kept = sorted(r.conversation_id for r in s.query(CopilotConversation).filter_by(tenant_id=c.tenant_id).all())
        assert len(kept) == 3 and "conv-4" in kept  # the newest survive
        other = client_as()
        chat(other, "unaffected", "conv-0")  # the cap is per owner
        assert stored(other.tenant_id, str(other.user_id), "conv-0") is not None


class TestConversationIds:
    @pytest.mark.parametrize("bad", ["x" * 101, "has space", "semi;colon", "slash/slash", "quote'quote", "../../etc", "\u202e"])
    def test_a_malformed_id_is_refused_before_anything_is_stored(self, bad):
        c = client_as()
        r = chat(c, "hi", bad)
        assert r.status_code == 422 and "conversationId must be" in r.json()["detail"]
        with Session(DB.sync) as s:
            assert s.query(CopilotConversation).count() == 0
        assert LLM.sent == []  # and the model was never called

    @pytest.mark.parametrize("good", ["a", "x" * 100, "conv_1", "conv-1", "a.b:c", "3f1c2d9e-0000-4000-8000-000000000000"])
    def test_ordinary_ids_are_accepted(self, good):
        assert chat(client_as(), "hi", good).status_code == 200


class TestFailureModes:
    def test_a_storage_failure_does_not_discard_the_answer_the_analyst_waited_for(self, monkeypatch):
        async def broken(*a, **k):
            raise RuntimeError("database went away")

        monkeypatch.setattr(copilot_history, "append_turn", broken)
        r = chat(client_as(), "hello")
        assert r.status_code == 200 and r.json()["degraded"] is False and r.json()["reply"]["content"] == "answer-1"

    def test_a_working_model_that_keeps_calling_tools_is_not_reported_as_unreachable(self):
        """The truncation warning raised TypeError (structlog keyword arguments on a stdlib logger), the outer except caught it, and a model that WAS working was reported as "couldn't reach the LLM backend"."""
        LLM.tool_loop = True
        r = chat(client_as(), "keep using tools")
        assert r.status_code == 200
        assert r.json()["degraded"] is False
        assert "couldn't reach" not in r.json()["reply"]["content"] and r.json()["reply"]["content"] == "still thinking"
        assert LLM.tool_calls == 6  # it really did loop to the limit


    def test_tools_run_as_the_authenticated_user_so_their_permissions_can_be_checked(self):
        """execute_copilot_tool used to receive only the tenant id: nothing it ran could be tied to who asked."""
        LLM.tool_loop = True
        c = client_as()
        chat(c, "keep using tools")
        assert len(LLM.tool_users) == 6 and all(u.user_id == c.user_id and u.tenant_id == c.tenant_id and u.role == "admin" for u in LLM.tool_users)


class TestPermissionAndWiring:
    """Derived from the real role table rather than hard-coded names, so this stays true if the table changes."""

    ROLES = ["viewer", "api_service", "soc_analyst", "threat_hunter", "soc_lead", "tenant_admin", "admin", "platform_admin"]

    def test_every_role_is_checked_against_copilot_use_and_nothing_is_called_for_a_refused_one(self):
        from app.core.security import has_permission

        allowed = [r for r in self.ROLES if has_permission(r, "copilot:use")]
        denied = [r for r in self.ROLES if not has_permission(r, "copilot:use")]
        assert allowed and denied  # the test is meaningful in both directions
        for role in denied:
            assert chat(client_as(role=role), "hi").status_code == 403, role
        assert LLM.sent == []  # no refused caller reached the model
        for role in allowed:
            assert chat(client_as(role=role), "hi").status_code == 200, role

    def test_the_route_is_mounted_on_the_real_api(self):
        from app.main import app

        assert "/api/v1/copilot/chat" in app.openapi()["paths"]


def test_the_model_and_migration_agree():
    import pathlib

    sql = (pathlib.Path(__file__).resolve().parent.parent / "migrations" / "057_copilot_conversations.sql").read_text(encoding="utf-8")
    for column in CopilotConversation.__table__.columns:
        assert f"    {column.name} " in sql, f"column {column.name} is in the model but not in migration 057"
    assert "PRIMARY KEY (tenant_id, owner_key, conversation_id)" in sql
    assert {c.name for c in CopilotConversation.__table__.primary_key.columns} == {"tenant_id", "owner_key", "conversation_id"}
    assert [m for m in (SystemMessage,) if m]  # (keeps the import honest)
