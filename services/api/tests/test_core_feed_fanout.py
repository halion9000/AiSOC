"""A report from CORE must not cost (items x client tenants) database statements.

CORE's reports about incident state, closed incidents and linked tickets were applied item by item in EVERY client tenant of the feed's owner: with 240 clients, one report of
a few hundred items was tens of thousands of sequential UPDATEs inside a row-level-security scope each, and CORE's 30 s limit expired ("127.0.0.1:8000 didn't answer within 30s"
on the Huntress and NinjaOne cards). Now one query finds the tenants that actually hold an alert for these incident ids, and only those are worked.
"""

import contextlib
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import inbox_core_feed as cf
from sqlalchemy.dialects import postgresql

OWNER = uuid.uuid4()
CLIENTS = [uuid.uuid4() for _ in range(240)]
HOLDER_A, HOLDER_B = CLIENTS[7], CLIENTS[200]


def _sql(stmt):
    c = stmt.compile(dialect=postgresql.dialect())
    return str(c).lower(), c.params


class Db:
    """Knows three kinds of statement: the scope query (children), the holder lookup (DISTINCT tenant ids), and updates (one row per holder tenant)."""

    def __init__(self, holders):
        self.holders = set(holders)
        self.updates = 0
        self.updated_in = []
        self.total = 0
        self.commit = AsyncMock()

    @contextlib.asynccontextmanager
    async def begin_nested(self):
        yield

    async def execute(self, stmt, *a, **k):
        self.total += 1
        sql, params = _sql(stmt)
        r = MagicMock()
        if "parent_tenant_id" in sql:
            r.scalars.return_value.all.return_value = list(CLIENTS)
        elif "distinct" in sql and "from alerts" in sql:
            # one (tenant, uid) row per holder tenant and requested uid (the requested ids are the string parameters that look like incident ids)
            flat = [x for v in params.values() for x in (v if isinstance(v, list | tuple | set) else [v])]
            requested = sorted({v for v in flat if isinstance(v, str) and ":" in v and v.split(":")[0].isalpha()})
            r.all.return_value = [(tid, uid) for tid in [OWNER, *CLIENTS] if tid in self.holders for uid in requested]
        elif sql.startswith("update alerts"):
            self.updates += 1
            tenant = next((v for v in params.values() if isinstance(v, uuid.UUID)), None)
            self.updated_in.append(tenant)
            r.rowcount = 1 if tenant in self.holders else 0
        else:
            r.rowcount = 0
            r.scalars.return_value.all.return_value = []
        return r


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(cf, "_verify_core_feed_token", AsyncMock(return_value=OWNER))
    monkeypatch.setattr(cf, "adopt_tenant", AsyncMock())
    sla = AsyncMock(return_value=0)
    monkeypatch.setattr(cf, "record_closure_events", sla)
    return sla


@pytest.mark.asyncio
async def test_a_state_report_only_touches_the_tenants_that_hold_the_alerts():
    db = Db(holders=[HOLDER_A, HOLDER_B])
    items = [cf.StateItem(uid=f"huntress:{i}", status="sent") for i in range(50)]
    out = await cf.report_core_feed_state("tok", cf.StateReport(vendor="huntress", items=items), db)
    assert out.updated == 100  # every item matched in each of the two holder tenants
    assert set(db.updated_in) == {HOLDER_A, HOLDER_B}
    assert db.updates == 100
    assert db.total < 120, f"{db.total} statements for 50 items across 241 tenants"


@pytest.mark.asyncio
async def test_a_tickets_report_is_bounded_the_same_way():
    db = Db(holders=[HOLDER_A])
    items = [cf.TicketsItem(uid=f"huntress:{i}", tickets=[cf.LinkedTicket(id="1")]) for i in range(80)]
    out = await cf.report_core_feed_tickets("tok", cf.TicketsReport(vendor="huntress", items=items), db)
    assert out.updated == 80
    assert set(db.updated_in) == {HOLDER_A}
    assert db.total < 120


@pytest.mark.asyncio
async def test_a_closed_report_is_bounded_and_only_resolving_tenants_get_sla_events(_env):
    db = Db(holders=[HOLDER_A, HOLDER_B])
    closed = [cf.ClosedItem(uid=f"ninjaone:{i}", state="cleared") for i in range(500)]
    out = await cf.report_core_feed_closed("tok", cf.ClosedReport(vendor="ninjaone", closed=closed), db)
    assert out.resolved == 10  # 5 chunks of 100 ids, one row each, in each of the two tenants
    assert set(db.updated_in) == {HOLDER_A, HOLDER_B}
    assert db.total < 150, f"{db.total} statements for 500 ids across 241 tenants"
    assert {c.args[1] for c in _env.await_args_list} == {HOLDER_A, HOLDER_B}, "SLA events only where something was resolved"


@pytest.mark.asyncio
async def test_nothing_is_touched_when_no_tenant_holds_the_alerts(_env):
    db = Db(holders=[])
    out = await cf.report_core_feed_state("tok", cf.StateReport(vendor="huntress", items=[cf.StateItem(uid="huntress:1", status="sent")]), db)
    assert out.updated == 0 and db.updates == 0
    closed = await cf.report_core_feed_closed("tok", cf.ClosedReport(vendor="huntress", closed=[cf.ClosedItem(uid="huntress:1")]), db)
    assert closed.resolved == 0 and db.updates == 0
    _env.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_owners_own_tenant_is_included_when_it_holds_alerts():
    db = Db(holders=[OWNER])
    out = await cf.report_core_feed_state("tok", cf.StateReport(vendor="huntress", items=[cf.StateItem(uid="huntress:1", status="sent")]), db)
    assert out.updated == 1 and db.updated_in == [OWNER]


@pytest.mark.asyncio
async def test_each_tenant_is_given_only_the_items_it_holds():
    """With holders A and B, an item held only by A must not be applied in B: the cost is the number of (item, tenant) pairs that exist, not items x holders."""

    class Split(Db):
        async def execute(self, stmt, *a, **k):
            sql, params = _sql(stmt)
            if "distinct" in sql and "from alerts" in sql:
                self.total += 1
                r = MagicMock()
                r.all.return_value = [(HOLDER_A, "huntress:1"), (HOLDER_A, "huntress:2"), (HOLDER_B, "huntress:2")]
                return r
            return await super().execute(stmt, *a, **k)

    db = Split(holders=[HOLDER_A, HOLDER_B])
    items = [cf.StateItem(uid=f"huntress:{i}", status="sent") for i in (1, 2)]
    out = await cf.report_core_feed_state("tok", cf.StateReport(vendor="huntress", items=items), db)
    assert out.updated == 3  # A: items 1 and 2; B: item 2 only
    assert db.updates == 3
