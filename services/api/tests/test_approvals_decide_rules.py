"""Deciding an approval: expiry, the designated approver, and a failed notification.

decide_approval used to check none of these: an approval that expired days ago could still be approved (the agent then resumed a destructive action on stale context), a request
naming ``required_user_id`` could be approved by anyone with cases:write, and a realtime 401/500 was ignored so the run never resumed while the caller saw 200.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import approvals
from fastapi import HTTPException

TENANT = uuid.uuid4()


class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, row):
        self.row, self.committed, self.statement = row, 0, None

    async def execute(self, statement):
        self.statement = statement
        return _Result(self.row)

    async def commit(self):
        self.committed += 1

    async def refresh(self, row):
        return None


def _row(**kw):
    base = dict(
        id=uuid.uuid4(), tenant_id=TENANT, status="pending", expires_at=None, required_user_id=None, decided_by_id=None, decided_at=None,
        decision_comment=None, run_id=None, title="Isolate host", case_id=None, alert_id=None, risk_level="high", requested_by="agent",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _user(user_id=None):
    return SimpleNamespace(tenant_id=TENANT, user_id=user_id or uuid.uuid4())


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    sent: list[str] = []

    async def notify(row, *, event):
        sent.append(event)

    monkeypatch.setattr(approvals, "_notify_realtime", notify)
    monkeypatch.setattr(approvals.ApprovalResponse, "model_validate", classmethod(lambda cls, row: row))
    return sent


def _decide(row, decision="approve", user=None):
    body = approvals.ApprovalDecisionRequest(decision=decision, comment="ok")
    return approvals.decide_approval(approval_id=row.id, body=body, user=user or _user(), db=FakeDB(row))


@pytest.mark.asyncio
async def test_an_expired_approval_cannot_be_approved():
    row = _row(expires_at=datetime.now(UTC) - timedelta(days=3))
    with pytest.raises(HTTPException) as exc:
        await _decide(row)
    assert exc.value.status_code == 409 and "expired" in exc.value.detail
    assert row.status != "approved"


@pytest.mark.asyncio
async def test_an_expired_approval_can_still_be_denied():
    row = _row(expires_at=datetime.now(UTC) - timedelta(days=3))
    out = await _decide(row, decision="deny")
    assert out.status == "denied"


@pytest.mark.asyncio
async def test_an_unexpired_approval_is_approved():
    row = _row(expires_at=datetime.now(UTC) + timedelta(hours=1))
    assert (await _decide(row)).status == "approved"


@pytest.mark.asyncio
async def test_only_the_named_approver_can_approve():
    named = uuid.uuid4()
    row = _row(required_user_id=named)
    with pytest.raises(HTTPException) as exc:
        await _decide(row, user=_user())
    assert exc.value.status_code == 403 and row.status == "pending"
    assert (await _decide(row, user=_user(named))).status == "approved"


@pytest.mark.asyncio
async def test_the_row_is_locked_while_it_is_decided():
    """Read-then-write without a lock let a concurrent approve and deny both succeed, the last write winning."""
    row = _row()
    db = FakeDB(row)
    await approvals.decide_approval(approval_id=row.id, body=approvals.ApprovalDecisionRequest(decision="approve"), user=_user(), db=db)
    assert db.statement._for_update_arg is not None


@pytest.mark.asyncio
async def test_a_failed_realtime_notification_is_logged_not_swallowed(monkeypatch, caplog):
    import logging

    import httpx

    monkeypatch.undo()  # use the real _notify_realtime
    monkeypatch.setattr(approvals.settings, "REALTIME_BASE_URL", "http://realtime:4000", raising=False)

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            return httpx.Response(401, request=httpx.Request("POST", url))

    monkeypatch.setattr(approvals.httpx, "AsyncClient", _Client)
    with caplog.at_level(logging.WARNING):
        await approvals._notify_realtime(_row(), event="approval_decided")  # noqa: SLF001
    assert any("401" in r.getMessage() for r in caplog.records)
