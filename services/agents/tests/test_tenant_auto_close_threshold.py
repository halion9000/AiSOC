"""A tenant may set its own auto-close confidence; anything wrong with the setting falls back to the platform value."""

from __future__ import annotations

import sys
import types
import uuid
from contextlib import asynccontextmanager

import pytest
from app.agents import auto_triage_agent as ata


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ata.reset_tenant_threshold_cache()
    monkeypatch.setattr(ata, "AUTO_CLOSE_THRESHOLD", 0.85)
    yield
    ata.reset_tenant_threshold_cache()


class _Conn:
    def __init__(self, value, error=None):
        self.value, self.error, self.queries = value, error, []

    async def fetchval(self, sql, *args):
        self.queries.append((sql, args))
        if self.error:
            raise self.error
        return self.value


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


def with_pool(monkeypatch, pool):
    ledger = types.ModuleType("app.investigator.ledger")

    async def get_pool():
        return pool

    ledger.get_pool = get_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.investigator.ledger", ledger)
    monkeypatch.setattr("app.investigator.ledger", ledger, raising=False)


@pytest.mark.parametrize(
    "raw,expected",
    [("0.9", 0.9), (0.95, 0.95), ("1", 1.0), ("0.5", 0.5), (None, None), ("", None), ("abc", None), ("0.49", None), ("1.01", None), ("-1", None), ("nan", None), (True, None), ([], None)],
)
def test_a_stored_value_is_used_only_when_it_is_a_number_in_range(raw, expected):
    assert ata.parse_tenant_threshold(raw) == expected


@pytest.mark.asyncio
async def test_a_tenant_with_its_own_value_uses_it(monkeypatch):
    conn = _Conn("0.95")
    with_pool(monkeypatch, _Pool(conn))
    tenant = uuid.uuid4()
    assert await ata.effective_threshold(tenant) == 0.95
    assert conn.queries[0][1] == (str(tenant),)  # looked up by the alert's own tenant


@pytest.mark.asyncio
async def test_a_tenant_with_no_value_or_a_bad_one_gets_the_platform_value(monkeypatch):
    for stored in (None, "not a number", "0.1"):
        ata.reset_tenant_threshold_cache()
        with_pool(monkeypatch, _Pool(_Conn(stored)))
        assert await ata.effective_threshold(uuid.uuid4()) == 0.85


@pytest.mark.asyncio
async def test_a_database_error_never_stops_triage_it_uses_the_platform_value(monkeypatch):
    with_pool(monkeypatch, _Pool(_Conn(None, error=RuntimeError("db down"))))
    assert await ata.effective_threshold(uuid.uuid4()) == 0.85


@pytest.mark.asyncio
async def test_no_pool_means_the_platform_value(monkeypatch):
    with_pool(monkeypatch, None)
    assert await ata.effective_threshold(uuid.uuid4()) == 0.85


@pytest.mark.asyncio
async def test_the_value_is_cached_for_a_minute_then_read_again(monkeypatch):
    conn = _Conn("0.9")
    with_pool(monkeypatch, _Pool(conn))
    tenant = uuid.uuid4()
    assert await ata.effective_threshold(tenant, now=1000.0) == 0.9
    conn.value = "0.99"
    assert await ata.effective_threshold(tenant, now=1030.0) == 0.9  # inside the minute: no new query
    assert len(conn.queries) == 1
    assert await ata.effective_threshold(tenant, now=1061.0) == 0.99
    assert len(conn.queries) == 2


@pytest.mark.asyncio
async def test_the_platform_value_is_read_live_so_a_changed_global_applies_to_tenants_without_their_own(monkeypatch):
    with_pool(monkeypatch, _Pool(_Conn(None)))
    tenant = uuid.uuid4()
    assert await ata.effective_threshold(tenant) == 0.85
    ata.set_threshold(0.7)
    try:
        assert await ata.effective_threshold(tenant) == 0.7
    finally:
        ata.set_threshold(0.85)
