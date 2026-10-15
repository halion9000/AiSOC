"""ATT&CK techniques read off real alerts, for the coverage pages."""

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta

from app.api.v1.endpoints.detection_compat import CoverageCell, CoverageResponse, CoverageSummary, _add_observed_gaps
from app.db.database import Base
from app.models.alert import Alert
from app.models.tenant import Tenant
from app.services import mitre_from_alerts as m
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


@contextlib.asynccontextmanager
async def no_scope(_db, _tenant):
    yield


def run(fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, Alert.__table__]))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            try:
                return await fn(s)
            finally:
                await engine.dispose()

    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower().replace(" ", "-"), parent_tenant_id=parent)


def alert(t, title="x", description=None, techniques=(), tactics=(), created=NOW - timedelta(days=1)):
    return Alert(
        tenant_id=t.id, title=title, description=description, severity="medium", status="new", priority=3, created_at=created, updated_at=created,
        event_time=created, first_seen=created, last_seen=created, mitre_tactics=list(tactics), mitre_techniques=list(techniques),
        ai_recommendations=[], affected_ips=[], affected_hosts=[], affected_users=[], tags=[], raw_event={},
    )  # fmt: skip


def test_extracts_declared_and_quoted_ids_once_each():
    got = m.techniques_for_alert(
        "Possible t1059.001 use", "also T1059.001 and T1486", ["T1110", "bogus", 5], ["Credential Access", "Impact"]
    )
    assert set(got) == {"T1059.001", "T1486", "T1110"}
    assert got["T1486"] == "Impact"  # tactic from the static map; two declared tactics are not guessed between


def test_no_mitre_data_means_nothing_is_invented():
    assert m.techniques_for_alert("Huntress: suspicious login at 10:15", "T12345 is not one", [], []) == {}


def test_single_declared_tactic_is_used_for_an_unmapped_technique():
    assert m.techniques_for_alert("x", None, ["T1999"], ["Reconnaissance"]) == {"T1999": "Reconnaissance"}


def test_counts_alerts_across_parent_and_clients_and_ignores_old_ones():
    async def body(s):
        parent = tenant("Parent")
        s.add(parent)
        await s.flush()
        a, b = tenant("A", parent.id), tenant("B", parent.id)
        s.add_all([a, b])
        await s.flush()
        s.add_all(
            [
                alert(a, techniques=["T1110"]),
                alert(b, title="brute force T1110"),
                alert(b, techniques=["T1486"]),
                alert(a, techniques=["T1003"], created=NOW - timedelta(days=200)),  # outside the window
                alert(a, title="plain alert"),
            ]
        )
        await s.flush()
        return await m.observed_techniques(s, parent.id, now=NOW, scope=no_scope)

    got = run(body)
    assert got["T1110"] == {"alerts": 2, "tactic": "Credential Access"}
    assert got["T1486"]["alerts"] == 1
    assert "T1003" not in got


def test_gaps_added_only_for_techniques_no_rule_covers():
    base = CoverageResponse(
        tactics=["Execution"],
        cells=[CoverageCell(techniqueId="T1059", tactic="Execution", totalRules=2, activeRules=1, inactiveRules=1)],
        summary=CoverageSummary(totalRules=2, activeRules=1, inactiveRules=1, techniques=1, coveredTechniques=1),
        generatedAt="x",
    )
    out = _add_observed_gaps(base, {"T1059": {"alerts": 3, "tactic": "Execution"}, "T1486": {"alerts": 1, "tactic": "Impact"}})
    by = {c.techniqueId: c for c in out.cells}
    assert by["T1059"].totalRules == 2  # untouched
    assert by["T1486"].totalRules == 0 and by["T1486"].tactic == "Impact"
    assert out.tactics == ["Execution", "Impact"]
    assert out.summary.techniques == 2 and out.summary.coveredTechniques == 1
    assert _add_observed_gaps(base, {}) is base
