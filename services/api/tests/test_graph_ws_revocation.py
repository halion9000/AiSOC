"""The graph WebSocket honours token revocation, like every HTTP route.

``_authenticate_ws`` decoded the JWT but never asked whether its jti had been revoked (logout, "sign out everywhere"), so a signed-out or stolen access token still opened /graph_ws/stream.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.api.v1.endpoints import graph_ws
from app.core.security import create_access_token


class FakeWS:
    def __init__(self):
        self.closed: tuple[int, str] | None = None

    async def close(self, code, reason=""):
        self.closed = (code, reason)


class FakeDB:
    def __init__(self, user):
        self.user = user

    async def execute(self, _stmt):
        return SimpleNamespace(scalar_one_or_none=lambda: self.user)


def _token(user_id):
    return create_access_token({"sub": str(user_id), "tenant_id": str(uuid.uuid4()), "role": "analyst"})


@pytest.mark.asyncio
async def test_a_revoked_token_is_refused(monkeypatch):
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, tenant_id=uuid.uuid4(), role="admin", email="a@example.test")
    monkeypatch.setattr(graph_ws, "is_revoked", AsyncMock(return_value=True))
    ws = FakeWS()
    assert await graph_ws._authenticate_ws(ws, _token(uid), FakeDB(user)) is None  # noqa: SLF001
    assert ws.closed is not None and "revoked" in ws.closed[1]


@pytest.mark.asyncio
async def test_a_live_token_still_works(monkeypatch):
    uid = uuid.uuid4()
    user = SimpleNamespace(id=uid, tenant_id=uuid.uuid4(), role="admin", email="a@example.test")
    monkeypatch.setattr(graph_ws, "is_revoked", AsyncMock(return_value=False))
    ws = FakeWS()
    got = await graph_ws._authenticate_ws(ws, _token(uid), FakeDB(user))  # noqa: SLF001
    assert got is not None and got.user_id == uid and ws.closed is None
