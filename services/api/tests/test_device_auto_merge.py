"""The same-name merge runs behind the device report: at most every ten minutes per client, and a failure there never fails the report."""

import contextlib
import uuid

from app.api.v1.endpoints import devices as ep


class FakeDb:
    @contextlib.asynccontextmanager
    async def begin_nested(self):
        yield


def _patch(monkeypatch, behaviour):
    calls = []

    @contextlib.asynccontextmanager
    async def acting(_db, tid):
        yield

    async def fake(_db, tid, *_a, **_k):
        calls.append(tid)
        return behaviour(tid)

    monkeypatch.setattr(ep, "acting_as_tenant", acting)
    monkeypatch.setattr(ep, "auto_merge_same_name", fake)
    ep._auto_merge_last.clear()
    return calls


async def test_a_client_is_checked_at_most_every_ten_minutes(monkeypatch):
    calls = _patch(monkeypatch, lambda tid: 2)
    t = uuid.uuid4()
    assert await ep._auto_merge_touched(FakeDb(), [t], now=1000.0) == 2
    assert await ep._auto_merge_touched(FakeDb(), [t], now=1000.0 + 599) == 0
    assert await ep._auto_merge_touched(FakeDb(), [t], now=1000.0 + 601) == 2
    assert calls == [t, t]


async def test_each_client_has_its_own_clock_and_the_merges_add_up(monkeypatch):
    calls = _patch(monkeypatch, lambda tid: 1)
    a, b = uuid.uuid4(), uuid.uuid4()
    assert await ep._auto_merge_touched(FakeDb(), [a, b], now=5.0) == 2
    assert await ep._auto_merge_touched(FakeDb(), [a, b], now=6.0) == 0
    assert sorted(calls) == sorted([a, b])


async def test_a_failure_is_skipped_and_the_other_clients_are_still_checked(monkeypatch):
    bad, good = uuid.uuid4(), uuid.uuid4()

    def behaviour(tid):
        if tid == bad:
            raise RuntimeError("boom")
        return 3

    _patch(monkeypatch, behaviour)
    assert await ep._auto_merge_touched(FakeDb(), [bad, good], now=1.0) == 3
