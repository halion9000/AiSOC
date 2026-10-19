"""An API key stops working when the person who minted it is deactivated.

``_resolve_api_key`` fell through to ``role='api_service'`` with the key's stored scopes when the owning user was inactive or gone, so offboarding someone (is_active=False) left every key they minted
(scopes up to ``*``) working until it expired.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from app.api.v1 import deps
from fastapi import HTTPException

TENANT = uuid.uuid4()


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeDB:
    """Answers the api_keys lookup, swallows the last_used update, then answers the owner lookup."""

    def __init__(self, key, owner):
        self.queue = [_Result(key), _Result(None), _Result(owner)]

    async def execute(self, _statement):
        return self.queue.pop(0)


@pytest.fixture(autouse=True)
def _no_cross_tenant_session(monkeypatch):
    @asynccontextmanager
    async def noop(_db):
        yield

    monkeypatch.setattr(deps, "cross_tenant_reads", noop)


def _key(user_id):
    return SimpleNamespace(
        id=uuid.uuid4(), tenant_id=TENANT, user_id=user_id, key_prefix="aisoc_x", expires_at=None, scopes=["*"], is_active=True
    )


@pytest.mark.asyncio
async def test_a_key_whose_owner_is_deactivated_is_refused():
    with pytest.raises(HTTPException) as exc:
        await deps._resolve_api_key("aisoc_secret", FakeDB(_key(uuid.uuid4()), owner=None))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_a_key_with_an_active_owner_works_and_takes_the_owners_role():
    owner = SimpleNamespace(id=uuid.uuid4(), role="analyst", email="a@example.test", account_name="a")
    user = await deps._resolve_api_key("aisoc_secret", FakeDB(_key(owner.id), owner=owner))
    assert user.role == "analyst" and user.tenant_id == TENANT


@pytest.mark.asyncio
async def test_a_service_key_with_no_owner_still_works():
    user = await deps._resolve_api_key("aisoc_secret", FakeDB(_key(None), owner=None))
    assert user.role == "api_service" and user.scopes == ["*"]
