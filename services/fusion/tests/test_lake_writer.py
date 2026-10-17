"""Phase A1 — ClickHouse lake writer tests.

Proves the OCSF->column mapping, batching (size + age + stop flush), IP/UUID
coercion, and the fail-soft contract (a ClickHouse error never raises into the
consumer: the batch is kept and retried, up to a cap, instead of dropped). Uses a fake client so no live ClickHouse is
needed; the live-container assertion is the integration.yml gate.
"""

from __future__ import annotations

import pytest
from app.services.lake_writer import LakeWriter, event_to_row

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


def _message(**ocsf_overrides) -> dict:
    ocsf = {
        "class_uid": 2001,
        "category_uid": 2,
        "severity_id": 5,
        "severity": "Critical",
        "time": "2026-07-12T08:00:00Z",
        "metadata": {"product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
        "device": {"name": "WIN-DC01"},
        "actor": {"user": {"name": "svc-backup"}},
        "src_endpoint": {"ip": "10.20.30.40", "port": 51515},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
        "file": {"fingerprints": [{"value": "a" * 64}], "path": "/tmp/x"},
        "mitre_attck": [{"technique_id": "T1003", "tactic_names": ["Credential Access"]}],
        "raw_data": "raw log line",
    }
    ocsf.update(ocsf_overrides)
    return {"id": "22222222-2222-2222-2222-222222222222", "tenant_id": TENANT, "ocsf_event": ocsf}


class _FakeClient:
    def __init__(self) -> None:
        self.inserted: list[dict] = []
        self.fail = False

    def execute(self, sql, rows=None, **kwargs):  # noqa: ANN001
        if self.fail:
            raise RuntimeError("clickhouse down")
        if rows:
            self.inserted.extend(rows)
        return []

    def disconnect(self):  # noqa: D401
        pass


def _writer_with_fake(**kw) -> tuple[LakeWriter, _FakeClient]:
    w = LakeWriter(host="x", **kw)
    fake = _FakeClient()
    w._client = fake  # noqa: SLF001 — inject fake, skip start()
    return w, fake


# ── Mapping ──────────────────────────────────────────────────────────────────


async def test_event_to_row_maps_core_fields():
    row = event_to_row(_message())
    assert row is not None
    assert row["tenant_id"] == TENANT
    assert row["class_uid"] == 2001
    assert row["severity_id"] == 5
    assert row["source_ip"] == "10.20.30.40"
    assert row["dest_ip"] == "203.0.113.9"
    assert row["user_name"] == "svc-backup"
    assert row["src_hostname"] == "WIN-DC01"
    assert row["hash_sha256"] == "a" * 64
    assert row["connector_type"] == "Falcon"
    assert row["mitre_techniques"] == ["T1003"]
    assert row["mitre_tactics"] == ["Credential Access"]
    assert row["event_id"] == "22222222-2222-2222-2222-222222222222"
    assert "10.20.30.40" in row["iocs"]


async def test_missing_ip_coerced_to_null_ipv6():
    row = event_to_row(_message(src_endpoint={}, dst_endpoint={}))
    assert row["source_ip"] == "::"
    assert row["dest_ip"] == "::"


async def test_non_uuid_event_id_left_none_for_default():
    msg = _message()
    msg["id"] = "not-a-uuid"
    row = event_to_row(msg)
    assert row["event_id"] is None


async def test_no_ocsf_or_bad_tenant_returns_none():
    assert event_to_row({"tenant_id": TENANT}) is None
    assert event_to_row({"tenant_id": "nope", "ocsf_event": {"class_uid": 1}}) is None


# ── Batching + flush ─────────────────────────────────────────────────────────


async def test_flushes_when_batch_full():
    w, fake = _writer_with_fake(batch_size=3)
    for _ in range(3):
        await w.write_event(_message())
    assert len(fake.inserted) == 3
    assert w.rows_written == 3
    assert w.metrics()["buffered"] == 0


async def test_buffers_until_full():
    w, fake = _writer_with_fake(batch_size=5)
    await w.write_event(_message())
    await w.write_event(_message())
    assert fake.inserted == []  # not yet flushed
    assert w.metrics()["buffered"] == 2


async def test_stop_flushes_remaining():
    w, fake = _writer_with_fake(batch_size=100)
    await w.write_event(_message())
    await w.stop()
    assert len(fake.inserted) == 1


async def test_flush_if_stale_flushes_old_buffer():
    w, fake = _writer_with_fake(batch_size=100, batch_max_age_seconds=0.0)
    await w.write_event(_message())
    await w.flush_if_stale()
    assert len(fake.inserted) == 1


async def test_omits_none_event_id_from_insert_row():
    w, fake = _writer_with_fake(batch_size=1)
    msg = _message()
    msg["id"] = "not-a-uuid"
    await w.write_event(msg)
    assert "event_id" not in fake.inserted[0]


# ── Fail-soft ────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _no_retry_backoff(monkeypatch):
    from app.services import lake_writer

    monkeypatch.setattr(lake_writer, "_RETRY_BACKOFF_SECONDS", 0.0)


async def test_flush_failure_keeps_the_batch_and_does_not_raise():
    """A ClickHouse blip used to drop the batch for good (up to 100 events lost, one log line)."""
    w, fake = _writer_with_fake(batch_size=2)
    fake.fail = True
    await w.write_event(_message())
    await w.write_event(_message())  # triggers flush -> fails
    assert w.flush_failures == 1
    assert w.rows_written == 0
    assert w.metrics()["buffered"] == 2  # kept for the next attempt
    fake.fail = False  # ClickHouse recovers
    await w.flush()
    assert w.rows_written == 2 and len(fake.inserted) == 2 and w.metrics()["buffered"] == 0


async def test_retained_rows_are_capped_so_an_outage_cannot_grow_memory_forever(monkeypatch):
    from app.services import lake_writer

    monkeypatch.setattr(lake_writer, "_MAX_RETAINED_ROWS", 5)
    w, fake = _writer_with_fake(batch_size=1)
    fake.fail = True
    for _ in range(9):
        await w.write_event(_message())
    assert w.metrics()["buffered"] == 5
    assert w.rows_dropped == 4


async def test_a_connect_failure_at_start_is_retried_later_not_permanent(monkeypatch):
    """start() used to set _disabled for the life of the process on any connect error, so ClickHouse being down at boot meant no lake writes until the container was restarted."""
    import sys
    import types

    attempts = {"n": 0}
    fake = _FakeClient()

    class _Driver:
        def __init__(self, **kwargs):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise ConnectionError("clickhouse not up yet")
            self.__dict__.update(execute=fake.execute, disconnect=fake.disconnect)

    monkeypatch.setitem(sys.modules, "clickhouse_driver", types.SimpleNamespace(Client=_Driver))
    w = LakeWriter(host="x", batch_size=1)
    await w.start()
    assert w._client is None and w._disabled is False  # noqa: SLF001
    await w.write_event(_message())  # reconnects lazily and writes
    assert attempts["n"] == 2 and w.rows_written == 1


async def test_disabled_writer_is_noop():
    w = LakeWriter(host="x")
    w._disabled = True  # noqa: SLF001
    assert await w.write_event(_message()) is False
    await w.flush()  # no raise


async def test_stop_makes_a_last_attempt_even_during_the_backoff(monkeypatch):
    from app.services import lake_writer

    monkeypatch.setattr(lake_writer, "_RETRY_BACKOFF_SECONDS", 3600.0)
    w, fake = _writer_with_fake(batch_size=1)
    fake.fail = True
    await w.write_event(_message())  # fails, backoff starts
    fake.fail = False
    await w.stop()
    assert len(fake.inserted) == 1
