"""Unit tests for the Phase 3.1 fused-alert → Postgres sink.

Covers the skip/fail-soft decision logic with a stub pool. The real-container
insert path is gated by `.github/workflows/integration.yml`
(scripts/integration/spine_test.py) — asserting SQL against a live Postgres,
not a mock.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager

import pytest
from app.models.alert import (
    AlertSeverity,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from app.services.alert_sink import (
    AlertSink,
    PersistOutcome,
    _asyncpg_dsn,
    _entities,
    _iocs,
)

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
CONNECTOR = uuid.UUID("00000000-0000-0000-0000-0000000000c1")


def _fused(decision: FusionDecision = FusionDecision.NEW_ALERT) -> FusedAlert:
    raw = RawAlert(
        tenant_id=TENANT,
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
        username="svc-backup",
        mitre_techniques=["T1003"],
        connector_id=CONNECTOR,
        connector_type="crowdstrike_falcon",
        source_event_ids=["evt-1"],
        ocsf_class_uid=2004,
        rule_id="edr-cred-dump-1",
        rule_name="Credential dumping via LSASS access",
    )
    # Canonical, replay-stable id (issue #568) — the sink inserts it explicitly.
    raw.id = raw.deterministic_id()
    return FusedAlert(
        id=raw.id,
        tenant_id=TENANT,
        fusion_decision=decision,
        alert=raw,
    )


class _StubConn:
    def __init__(self, row):
        self._row = row
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self._row

    async def execute(self, sql, *args):
        self.executed = getattr(self, "executed", [])
        self.executed.append((sql, args))
        if getattr(self, "execute_error", None):
            raise self.execute_error
        return "UPDATE 1"


class _StubPool:
    def __init__(self, row):
        self.conn = _StubConn(row)

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def test_dsn_strips_sqlalchemy_driver():
    assert _asyncpg_dsn("postgresql+asyncpg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    assert _asyncpg_dsn("postgresql://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"


def test_iocs_and_entities_extraction():
    fused = _fused()
    iocs = _iocs(fused)
    assert {"type": "ip", "value": "10.20.30.40"} in iocs
    entities = _entities(fused)
    assert {"type": "host", "value": "WIN-DC01"} in entities
    assert {"type": "user", "value": "svc-backup"} in entities


@pytest.mark.asyncio
async def test_duplicate_decision_is_never_persisted():
    sink = AlertSink("postgresql://x")
    sink._pool = _StubPool(row={"id": uuid.uuid4()})  # would succeed if called
    result = await sink.persist(_fused(FusionDecision.DUPLICATE))
    assert result.outcome is PersistOutcome.DUPLICATE
    assert sink._pool.conn.calls == []


@pytest.mark.asyncio
async def test_new_alert_is_inserted_with_canonical_id_and_provenance():
    fused = _fused()
    # The sink inserts the canonical id explicitly; the DB echoes it back.
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.INSERTED
    assert result.alert_id == str(fused.id)
    assert result.persisted is True
    (sql, args) = pool.conn.calls[0]
    assert "INSERT INTO alerts" in sql
    assert "WHERE NOT EXISTS" in sql  # content dedup guard
    assert "ON CONFLICT (id) DO NOTHING" in sql  # exact-replay idempotency
    # Positional args follow the _INSERT_SQL column order.
    assert args[0] == fused.id  # explicit canonical id
    assert args[1] == TENANT
    assert args[10] == fused.alert.fingerprint()  # dedup_hash
    assert args[17] == CONNECTOR  # connector_id
    assert args[18] == "crowdstrike_falcon"  # connector_type
    assert json.loads(args[19]) == ["evt-1"]  # source_event_ids
    assert args[20] == 2004  # ocsf_class_uid
    assert args[21] == "edr-cred-dump-1"  # rule_id
    # The columns the alert rail, entity pages and device counts read (not only the generic `entities` blob).
    assert json.loads(args[23]) == ["10.20.30.40"]  # affected_ips
    assert json.loads(args[24]) == ["WIN-DC01"]  # affected_hosts
    assert json.loads(args[25]) == ["svc-backup"]  # affected_users


@pytest.mark.asyncio
async def test_dedup_hit_returns_duplicate():
    pool = _StubPool(row=None)  # WHERE NOT EXISTS / ON CONFLICT filtered it out
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    result = await sink.persist(_fused())
    assert result.outcome is PersistOutcome.DUPLICATE
    assert result.alert_id == str(_fused().id)  # canonical id still known
    assert result.durable is True


@pytest.mark.asyncio
async def test_a_dedup_hit_refreshes_the_existing_alerts_last_seen():
    """The row used to stay exactly as first written, so a recurrence a week later left no trace: last_seen never moved."""
    pool = _StubPool(row=None)
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    fused = _fused()
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.DUPLICATE
    (sql, args), = pool.conn.executed
    assert "last_seen" in sql and "updated_at" in sql
    assert args[0] == TENANT and args[1] == fused.alert.fingerprint()


@pytest.mark.asyncio
async def test_a_failed_last_seen_refresh_does_not_change_the_outcome():
    pool = _StubPool(row=None)
    pool.conn.execute_error = RuntimeError("db hiccup")
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    assert (await sink.persist(_fused())).outcome is PersistOutcome.DUPLICATE


@pytest.mark.asyncio
async def test_db_unavailable_is_distinct_from_duplicate(monkeypatch):
    sink = AlertSink("postgresql://nope:nope@127.0.0.1:1/none")

    async def _fail_start():
        sink._pool = None

    monkeypatch.setattr(sink, "start", _fail_start)
    result = await sink.persist(_fused())
    # Fail-soft (no raise) but observably UNAVAILABLE — retryable, NOT a dup.
    assert result.outcome is PersistOutcome.UNAVAILABLE
    assert result.durable is False


@pytest.mark.asyncio
async def test_persist_exception_is_failed_not_duplicate():
    class _BoomPool(_StubPool):
        def acquire(self):
            raise RuntimeError("connection reset")

    sink = AlertSink("postgresql://x")
    sink._pool = _BoomPool(row=None)
    result = await sink.persist(_fused())
    assert result.outcome is PersistOutcome.FAILED
    assert result.durable is False


def test_deterministic_id_is_replay_stable():
    # Same tenant + content ⇒ same canonical id across independent builds.
    a = _fused().alert
    b = _fused().alert
    assert a.id == b.id == a.deterministic_id()
    # And it is a proper uuid5 (not the random default_factory).
    assert a.id != uuid.uuid4()


@pytest.mark.asyncio
async def test_start_twice_opens_one_pool(monkeypatch):
    """The memory-prior refresh opens the pool through _ensure_pool and the worker then calls start(): the second call overwrote the first pool without closing it, leaking its connections."""
    import app.services.alert_sink as mod

    opened = []

    async def fake_create_pool(*_a, **_k):
        opened.append(object())
        return opened[-1]

    monkeypatch.setattr(mod.asyncpg, "create_pool", fake_create_pool)
    sink = AlertSink("postgresql://x")
    await sink.start()
    await sink.start()
    assert len(opened) == 1 and sink._pool is opened[0]


# ---- the vendor's incident id is the alert's identity (not only its fingerprint) --------------------------------------------------------------------------


def _fused_from_core(uid: str | None):
    """An alert CORE forwarded: its raw event carries the vendor incident id at finding.uid."""
    f = _fused()
    f.alert.raw_event = {"finding": {"uid": uid}} if uid else {}
    return f


def test_the_incident_id_helper_reads_finding_uid():
    from app.services.alert_sink import _finding_uid

    assert _finding_uid(_fused_from_core("petra:abc").alert) == "petra:abc"
    assert _finding_uid(_fused_from_core(None).alert) is None
    f = _fused()
    f.alert.raw_event = {"finding": "not-an-object"}
    assert _finding_uid(f.alert) is None
    f.alert.raw_event = {"finding": {"uid": ["x"]}}
    assert _finding_uid(f.alert) is None
    f.alert.raw_event = {"finding": {"uid": "x" * 500}}
    assert _finding_uid(f.alert) is None, "an absurd id is not an identity"


@pytest.mark.asyncio
async def test_the_insert_is_told_the_incident_id_so_a_changed_fingerprint_cannot_make_a_second_row():
    """Same tenant, same Petra incident, a different fingerprint (the promoter started extracting a user, then the fingerprint gained the client id): each change stored the incident
    AGAIN, 620 extra rows in one day. The insert now skips a (tenant, incident id) that already exists, whatever the fingerprint says."""
    pool = _StubPool(row={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    await sink.persist(_fused_from_core("petra:abc"))
    sql, args = pool.conn.calls[0]
    assert "finding" in sql and "NOT EXISTS" in sql
    assert args[-1] == "petra:abc"


@pytest.mark.asyncio
async def test_an_alert_without_an_incident_id_is_judged_by_its_fingerprint_alone():
    pool = _StubPool(row={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    await sink.persist(_fused_from_core(None))
    assert pool.conn.calls[0][1][-1] is None


@pytest.mark.asyncio
async def test_a_dedup_hit_by_incident_id_refreshes_the_stored_alert():
    pool = _StubPool(row=None)
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    fused = _fused_from_core("petra:abc")
    await sink.persist(fused)
    (sql, args), = pool.conn.executed
    assert "finding" in sql and args[-1] == "petra:abc"
