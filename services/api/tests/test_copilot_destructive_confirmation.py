"""Deleting anything from the Copilot needs the ANALYST's confirmation, and the model cannot give it.

The Copilot's delete_alert used to delete on the model's say-so (after a permission check). Alert text is attacker-influenced and sits in the model's context, so injected text could get alerts deleted. Now the tool only REQUESTS: it describes what would be deleted, a signed, expiring confirmation (bound to tenant, user, action and
arguments) goes to the UI and is removed from what the model sees, and only the analyst's own call to POST /copilot/actions/confirm, which is not a model tool, performs it, re-checking alerts:delete at that moment.
"""
import base64
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app import copilot_tools as ct
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import copilot as cp

TENANT, OTHER_TENANT = uuid.uuid4(), uuid.uuid4()


def make_user(role="admin", tenant=None, uid=None):
    return CurrentUser(user_id=uid or uuid.uuid4(), tenant_id=tenant or TENANT, role=role, email="a@example.test")


def reader(tenant=None):
    """An API key that may use the Copilot and read alerts but may NOT delete them: exactly the principal the confirmation exists for."""
    u = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant or TENANT, role="analyst", email="key@example.test", scopes=["copilot:use", "alerts:read", "cases:read"])
    u.require_permission("copilot:use")
    with pytest.raises(HTTPException):
        u.require_permission("alerts:delete")
    return u


class FakeSession:
    """An async-context session recording statements; execute() answers one alert (or none)."""

    def __init__(self, alert=None, rowcount=1):
        self.alert, self.rowcount, self.statements = alert, rowcount, []
        self.commit = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt, *a, **k):
        self.statements.append(" ".join(str(stmt).split()).upper())
        res = MagicMock()
        res.scalar_one_or_none.return_value = self.alert
        res.rowcount = self.rowcount
        return res

    @property
    def deleted(self):
        return any(s.startswith("DELETE") for s in self.statements)


@pytest.fixture
def session(monkeypatch):
    holder = {}

    def install(alert=None, rowcount=1):
        holder["s"] = FakeSession(alert, rowcount)

        async def get(tid):
            return holder["s"]

        monkeypatch.setattr(ct, "_get_session", get)
        return holder["s"]

    return install


def an_alert(title="Suspicious login"):
    return SimpleNamespace(id=uuid.uuid4(), title=title)


# ---------------------------------------------------------------- tokens


class TestTheToken:
    def test_a_token_verifies_for_the_user_and_tenant_it_was_issued_to(self):
        token, exp = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"})
        data = ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="u1")
        assert data["a"] == "delete_alert" and data["args"] == {"alert_id": "a"} and data["exp"] == exp

    def test_two_tokens_for_the_same_action_differ(self):
        kw = dict(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"})
        assert ct.issue_confirmation(**kw)[0] != ct.issue_confirmation(**kw)[0]

    @pytest.mark.parametrize("bad", ["", "nodot", "a.b.c.d", "!!!.???", "x" * 50, "."])
    def test_garbage_is_malformed_or_a_bad_signature_never_a_pass(self, bad):
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(bad, tenant_id=str(TENANT), user_id="u1")
        assert exc.value.reason in {"malformed", "signature"}

    def test_a_tampered_payload_fails_the_signature(self):
        token, _ = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "mine"})
        body, sig = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["args"]["alert_id"] = "someone-elses"
        forged = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode() + "." + sig
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(forged, tenant_id=str(TENANT), user_id="u1")
        assert exc.value.reason == "signature"

    def test_a_tampered_signature_fails(self):
        token, _ = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"})
        body, sig = token.split(".")
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(body + "." + flipped, tenant_id=str(TENANT), user_id="u1")
        assert exc.value.reason == "signature"

    def test_a_token_signed_with_another_secret_fails(self, monkeypatch):
        token, _ = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"})
        monkeypatch.setattr(ct.settings, "SECRET_KEY", "a-completely-different-secret-key-value!!")
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="u1")
        assert exc.value.reason == "signature"

    def test_it_expires(self):
        now = 1_000_000.0
        token, exp = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"}, now=now)
        assert exp == int(now) + ct.CONFIRMATION_TTL_SECONDS
        ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="u1", now=now + ct.CONFIRMATION_TTL_SECONDS)
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="u1", now=now + ct.CONFIRMATION_TTL_SECONDS + 1)
        assert exc.value.reason == "expired"

    def test_it_is_not_usable_by_another_user_or_tenant(self):
        token, _ = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="delete_alert", args={"alert_id": "a"})
        with pytest.raises(ct.ConfirmationError) as e1:
            ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="someone-else-in-the-same-tenant")
        with pytest.raises(ct.ConfirmationError) as e2:
            ct.verify_confirmation(token, tenant_id=str(OTHER_TENANT), user_id="u1")
        assert (e1.value.reason, e2.value.reason) == ("wrong_user", "wrong_tenant")

    def test_the_signing_key_is_purpose_labelled_so_a_plain_secret_signature_is_not_accepted(self):
        """Anything else signed with HMAC(SECRET_KEY) (or with the bare hash of it) must never be mistakable for a confirmation."""
        import hashlib
        import hmac

        payload = json.dumps({"a": "delete_alert", "args": {"alert_id": "a"}, "t": str(TENANT), "u": "u1", "exp": int(time.time()) + 100, "n": "x"}, sort_keys=True, separators=(",", ":")).encode()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        for key in (ct.settings.SECRET_KEY.encode(), hashlib.sha256(ct.settings.SECRET_KEY.encode()).digest()):
            forged = b64(payload) + "." + b64(hmac.new(key, payload, hashlib.sha256).digest())
            with pytest.raises(ct.ConfirmationError) as exc:
                ct.verify_confirmation(forged, tenant_id=str(TENANT), user_id="u1")
            assert exc.value.reason == "signature"

    def test_an_action_that_is_not_confirmable_is_refused_even_with_a_valid_signature(self):
        token, _ = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u1", action="drop_everything", args={})
        with pytest.raises(ct.ConfirmationError) as exc:
            ct.verify_confirmation(token, tenant_id=str(TENANT), user_id="u1")
        assert exc.value.reason == "unknown_action"


# ---------------------------------------------------------------- the tool only requests


@pytest.mark.asyncio
class TestTheToolOnlyRequests:
    async def test_delete_alert_does_not_delete_anything(self, session):
        s = session(an_alert("Suspicious login"))
        out = await ct.delete_alert(tenant_id=str(TENANT), alert_id=str(uuid.uuid4()))
        assert not s.deleted and s.commit.await_count == 0
        assert out[ct._CONFIRM_KEY]["action"] == "delete_alert" and "Suspicious login" in out[ct._CONFIRM_KEY]["summary"] and "cannot be undone" in out[ct._CONFIRM_KEY]["summary"]

    async def test_an_alert_that_is_not_in_the_tenant_is_just_an_error(self, session):
        s = session(None)
        out = await ct.delete_alert(tenant_id=str(TENANT), alert_id=str(uuid.uuid4()))
        assert out == {"error": "alert not found"} and not s.deleted

    async def test_a_bad_uuid_is_an_error_and_touches_nothing(self, session):
        s = session(an_alert())
        assert await ct.delete_alert(tenant_id=str(TENANT), alert_id="not-a-uuid") == {"error": "invalid UUID format"}
        assert s.statements == []

    async def test_the_lookup_is_tenant_scoped(self, session):
        s = session(an_alert())
        await ct.delete_alert(tenant_id=str(TENANT), alert_id=str(uuid.uuid4()))
        assert "TENANT_ID" in s.statements[0]

    async def test_perform_deletes_with_a_tenant_scoped_statement_and_commits(self, session):
        s = session(rowcount=1)
        out = await ct.perform_delete_alert(tenant_id=str(TENANT), alert_id=str(uuid.uuid4()))
        assert out["deleted"] is True and s.deleted and "TENANT_ID" in s.statements[0] and s.commit.await_count == 1

    async def test_perform_reports_an_already_deleted_alert(self, session):
        session(rowcount=0)
        assert (await ct.perform_delete_alert(tenant_id=str(TENANT), alert_id=str(uuid.uuid4())))["error"] == "alert not found or already deleted"

    def test_the_model_cannot_reach_the_real_deletion(self):
        assert ct.perform_delete_alert not in ct._COPILOT_TOOL_DISPATCH.values()
        assert "perform_delete_alert" not in {t["function"]["name"] for t in ct.COPILOT_TOOL_SCHEMAS}
        assert not any("confirm" in t["function"]["name"] for t in ct.COPILOT_TOOL_SCHEMAS)

    def test_the_tool_description_tells_the_model_it_does_not_delete(self):
        d = next(t["function"]["description"] for t in ct.COPILOT_TOOL_SCHEMAS if t["function"]["name"] == "delete_alert")
        assert "does NOT delete" in d and "confirmation" in d


# ---------------------------------------------------------------- the executor


@pytest.mark.asyncio
class TestTheExecutor:
    async def test_a_delete_request_yields_a_pending_confirmation_and_deletes_nothing(self, session):
        s = session(an_alert())
        u = make_user()
        out = await ct.execute_copilot_tool("delete_alert", {"alert_id": str(uuid.uuid4())}, str(TENANT), user=u)
        assert out["status"] == "awaiting_user_confirmation" and "NOTHING HAS BEEN DONE" in out["message"] and not s.deleted
        pending = out[ct.PENDING_KEY]
        assert pending["action"] == "delete_alert" and pending["expiresAt"] > time.time()
        ct.verify_confirmation(pending["token"], tenant_id=str(TENANT), user_id=str(u.user_id))

    async def test_the_token_is_bound_to_the_requesting_user_and_the_exact_alert(self, session):
        session(an_alert())
        u, aid = make_user(), str(uuid.uuid4())
        out = await ct.execute_copilot_tool("delete_alert", {"alert_id": aid}, str(TENANT), user=u)
        data = ct.verify_confirmation(out[ct.PENDING_KEY]["token"], tenant_id=str(TENANT), user_id=str(u.user_id))
        assert data["args"] == {"alert_id": aid}
        with pytest.raises(ct.ConfirmationError):
            ct.verify_confirmation(out[ct.PENDING_KEY]["token"], tenant_id=str(TENANT), user_id=str(uuid.uuid4()))

    async def test_a_user_without_alerts_delete_gets_no_request_at_all(self, session):
        s = session(an_alert())
        out = await ct.execute_copilot_tool("delete_alert", {"alert_id": str(uuid.uuid4())}, str(TENANT), user=reader())
        assert "permission denied" in out["error"] and ct.PENDING_KEY not in out and s.statements == []

    async def test_a_tenant_mismatch_is_refused(self, session):
        s = session(an_alert())
        out = await ct.execute_copilot_tool("delete_alert", {"alert_id": str(uuid.uuid4())}, str(OTHER_TENANT), user=make_user())
        assert out == {"error": "tenant mismatch"} and s.statements == []

    async def test_read_only_tools_are_unchanged_and_carry_no_confirmation(self, session):
        session(an_alert())
        out = await ct.execute_copilot_tool("get_alert", {"alert_id": str(uuid.uuid4())}, str(TENANT), user=make_user())
        assert ct.PENDING_KEY not in out and "status" not in out or out.get("status") != "awaiting_user_confirmation"

    def test_split_pending_removes_the_token_from_what_the_model_sees(self):
        token, exp = ct.issue_confirmation(tenant_id=str(TENANT), user_id="u", action="delete_alert", args={"alert_id": "a"})
        result = {"alert_id": "a", "status": "awaiting_user_confirmation", ct.PENDING_KEY: {"action": "delete_alert", "summary": "s", "token": token, "expiresAt": exp}}
        visible, pending = ct.split_pending(result)
        assert pending["token"] == token and token not in json.dumps(visible) and ct.PENDING_KEY not in visible and visible["status"] == "awaiting_user_confirmation"

    @pytest.mark.parametrize("plain", [{"a": 1}, [1, 2], "text", None])
    def test_split_pending_passes_anything_else_through(self, plain):
        assert ct.split_pending(plain) == (plain, None)


# ---------------------------------------------------------------- the chat loop


@pytest.mark.asyncio
class TestTheChatLoop:
    async def test_the_model_is_told_nothing_was_deleted_and_never_sees_the_token(self, monkeypatch, session):
        s = session(an_alert("Beaconing host"))
        u = make_user()
        aid = str(uuid.uuid4())
        seen = []

        async def fake_invoke(bound, messages):
            seen.append(list(messages))
            if len(seen) == 1:
                return SimpleNamespace(content="", tool_calls=[{"name": "delete_alert", "args": {"alert_id": aid}, "id": "call-1"}])
            return SimpleNamespace(content="I have asked you to confirm the deletion.", tool_calls=[])

        llm = MagicMock()
        llm.bind_tools.return_value = object()
        monkeypatch.setattr(cp, "make_chat_model", lambda *a, **k: llm)
        monkeypatch.setattr(cp, "safe_ainvoke", fake_invoke)
        monkeypatch.setattr(cp.copilot_history, "load_history", AsyncMock(return_value=[]))
        monkeypatch.setattr(cp.copilot_history, "append_turn", AsyncMock())
        db = MagicMock()
        db.rollback = AsyncMock()
        out = await cp.copilot_chat(body=cp.CopilotChatRequest(message="delete that alert"), user=u, db=db)

        assert len(out.pendingActions) == 1 and not s.deleted
        pending = out.pendingActions[0]
        assert pending.action == "delete_alert" and "Beaconing host" in pending.summary
        tool_msgs = [m for m in seen[1] if m.__class__.__name__ == "ToolMessage"]
        assert len(tool_msgs) == 1
        fed_back = tool_msgs[0].content
        assert pending.token not in fed_back and "awaiting_user_confirmation" in fed_back and "NOTHING HAS BEEN DONE" in fed_back

    async def test_a_chat_that_requests_nothing_has_no_pending_actions(self, monkeypatch):
        async def fake_invoke(bound, messages):
            return SimpleNamespace(content="hello", tool_calls=[])

        llm = MagicMock()
        llm.bind_tools.return_value = object()
        monkeypatch.setattr(cp, "make_chat_model", lambda *a, **k: llm)
        monkeypatch.setattr(cp, "safe_ainvoke", fake_invoke)
        monkeypatch.setattr(cp.copilot_history, "load_history", AsyncMock(return_value=[]))
        monkeypatch.setattr(cp.copilot_history, "append_turn", AsyncMock())
        db = MagicMock()
        db.rollback = AsyncMock()
        out = await cp.copilot_chat(body=cp.CopilotChatRequest(message="hi"), user=make_user(), db=db)
        assert out.pendingActions == []


# ---------------------------------------------------------------- the confirm endpoint


@pytest.mark.asyncio
class TestTheConfirmEndpoint:
    @pytest.fixture
    def performer(self, monkeypatch):
        fn = AsyncMock(return_value={"deleted": True, "alert_id": "x"})
        monkeypatch.setitem(ct.CONFIRMED_ACTIONS, "delete_alert", fn)
        return fn

    def token_for(self, user, aid="alert-1", **kw):
        return ct.issue_confirmation(tenant_id=str(user.tenant_id), user_id=str(user.user_id), action="delete_alert", args={"alert_id": aid}, **kw)[0]

    async def test_a_valid_confirmation_performs_the_deletion_as_that_user_in_that_tenant(self, performer):
        u = make_user()
        out = await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(u, "alert-9")), user=u)
        assert out.status == "done" and out.action == "delete_alert" and out.result["deleted"] is True
        performer.assert_awaited_once_with(tenant_id=str(u.tenant_id), alert_id="alert-9")

    async def test_the_arguments_come_from_the_token_not_from_the_caller(self, performer):
        u = make_user()
        await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(u, "the-confirmed-alert")), user=u)
        assert performer.await_args.kwargs["alert_id"] == "the-confirmed-alert"

    async def test_the_permission_is_rechecked_at_confirmation_time(self, performer):
        low = reader()
        with pytest.raises(HTTPException) as exc:
            await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(low)), user=low)
        assert exc.value.status_code == 403
        performer.assert_not_awaited()

    @pytest.mark.parametrize("who", ["other_user", "other_tenant"])
    async def test_a_token_issued_to_someone_else_is_refused_and_nothing_is_deleted(self, performer, who):
        issuer = make_user()
        presenter = make_user() if who == "other_user" else make_user(tenant=OTHER_TENANT)
        with pytest.raises(HTTPException) as exc:
            await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(issuer)), user=presenter)
        assert exc.value.status_code == 403
        performer.assert_not_awaited()

    async def test_an_expired_confirmation_is_410_and_nothing_is_deleted(self, performer):
        u = make_user()
        with pytest.raises(HTTPException) as exc:
            await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(u, now=time.time() - 10_000)), user=u)
        assert exc.value.status_code == 410
        performer.assert_not_awaited()

    async def test_a_forged_confirmation_is_400_and_nothing_is_deleted(self, performer):
        u = make_user()
        token = self.token_for(u)
        with pytest.raises(HTTPException) as exc:
            await cp.confirm_action(body=cp.ConfirmActionRequest(token=token[:-4] + "AAAA"), user=u)
        assert exc.value.status_code == 400
        performer.assert_not_awaited()

    async def test_a_failed_deletion_is_reported_as_failed(self, monkeypatch):
        monkeypatch.setitem(ct.CONFIRMED_ACTIONS, "delete_alert", AsyncMock(return_value={"error": "alert not found or already deleted"}))
        u = make_user()
        out = await cp.confirm_action(body=cp.ConfirmActionRequest(token=self.token_for(u)), user=u)
        assert out.status == "failed"

    def test_the_endpoint_needs_copilot_use_and_is_not_a_model_tool(self):
        import ast
        from pathlib import Path

        tree = ast.parse(Path(cp.__file__).read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "confirm_action")
        assert "copilot:use" in ast.unparse(fn.args)
        assert "confirm_action" not in {t["function"]["name"] for t in ct.COPILOT_TOOL_SCHEMAS}


class TestAKeyWithTheDeleteScope:
    """The permission is a real gate in both directions: alerts:delete (or alerts:*) is what lets a request be made AND confirmed."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scope", ["alerts:delete", "alerts:*", "*"])
    async def test_a_key_with_the_delete_scope_gets_a_request(self, session, scope):
        session(an_alert())
        u = CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="analyst", email="k@example.test", scopes=["copilot:use", scope])
        out = await ct.execute_copilot_tool("delete_alert", {"alert_id": str(uuid.uuid4())}, str(TENANT), user=u)
        assert out["status"] == "awaiting_user_confirmation"
