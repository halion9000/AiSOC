"""CORE's messages reach a feed's alerts wherever they were stored (the owner's tenant or a mapped client's), and PSA tickets reach the alert that has them."""

import uuid
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_vendor_actions as av
from app.api.v1.endpoints import inbox_core_feed as cf
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

OWNER = uuid.uuid4()
CLIENT_A, CLIENT_B = uuid.uuid4(), uuid.uuid4()


def _sql(stmt):
    c = stmt.compile(dialect=postgresql.dialect())
    return str(c), c.params


def _db(child_ids=(), returning=None, rowcounts=()):
    db = MagicMock()
    db.executed = []
    counts = list(rowcounts)

    async def execute(stmt, *a, **k):
        db.executed.append(stmt)
        r = MagicMock(rowcount=counts.pop(0) if counts else 0)
        r.scalars.return_value.all.return_value = list(child_ids)
        r.first.return_value = (returning.pop(0) if returning else None) if returning is not None else None
        return r

    db.execute = AsyncMock(side_effect=execute)
    db.commit = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setattr(cf, "_verify_core_feed_token", AsyncMock(return_value=OWNER))
    monkeypatch.setattr(cf, "adopt_tenant", AsyncMock())


# ---- scope -----------------------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_scope_is_the_owner_then_only_its_own_children():
    db = _db(child_ids=[CLIENT_A, CLIENT_B])
    assert await cf._scope_ids(db, OWNER) == [OWNER, CLIENT_A, CLIENT_B]  # noqa: SLF001
    sql, params = _sql(db.executed[0])
    assert "parent_tenant_id" in sql and OWNER in params.values()


@pytest.mark.asyncio
async def test_a_state_report_is_applied_in_every_tenant_in_scope():
    db = _db(child_ids=[CLIENT_A], rowcounts=[0, 1])  # the owner has no such alert; the client's tenant does
    out = await cf.report_core_feed_state(
        "tok", cf.StateReport(vendor="huntress", items=[cf.StateItem(uid="huntress:7", status="sent")]), db
    )
    assert out.updated == 1
    updates = [_sql(s) for s in db.executed[1:]]
    assert [OWNER in p.values() for _, p in updates] == [True, False]
    assert [CLIENT_A in p.values() for _, p in updates] == [False, True]


@pytest.mark.asyncio
async def test_a_result_for_an_action_queued_in_a_client_tenant_is_recorded_there(monkeypatch):
    db = _db(
        child_ids=[CLIENT_A], returning=[None, None, NS(alert_id=uuid.uuid4(), action="approve")]
    )  # statements: scope query, owner (no match), client (match)
    out = await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="done"), db)
    assert out.recorded is True
    owner_try, client_try = (_sql(s) for s in db.executed[1:3])
    assert OWNER in owner_try[1].values() and CLIENT_A in client_try[1].values()


@pytest.mark.asyncio
async def test_a_result_nobody_in_scope_claimed_is_still_404():
    db = _db(child_ids=[CLIENT_A], returning=[None, None, None])
    with pytest.raises(HTTPException) as e:
        await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="done"), db)
    assert e.value.status_code == 404


# ---- tickets ---------------------------------------------------------------------------------------------------------------------------------------------


def test_a_tickets_report_rejects_what_could_be_abused():
    ok = cf.LinkedTicket(id="123", summary="Malware on ACME-FS01", url="https://acme.halopsa.com/tickets?id=123")
    assert ok.system == "halopsa"
    with pytest.raises(ValidationError):
        cf.LinkedTicket(id="1", url="javascript:alert(1)")
    with pytest.raises(ValidationError):
        cf.LinkedTicket(id="1", system="evilpsa")
    with pytest.raises(ValidationError):
        cf.TicketsReport(vendor="Huntress!", items=[])
    with pytest.raises(ValidationError):
        cf.TicketsItem(uid="huntress:1", tickets=[cf.LinkedTicket(id=str(i)) for i in range(21)])


@pytest.mark.asyncio
async def test_tickets_are_stored_on_that_vendors_incident_only():
    db = _db(rowcounts=[1])
    rep = cf.TicketsReport(
        vendor="huntress",
        items=[
            cf.TicketsItem(uid="huntress:7", tickets=[cf.LinkedTicket(id="123", summary="S", status="Open")]),
            cf.TicketsItem(uid="petra:9", tickets=[cf.LinkedTicket(id="5")]),
        ],
    )
    assert await cf.apply_tickets(db, OWNER, rep) == 1
    assert len(db.executed) == 1  # the petra uid is not this vendor's
    sql, params = _sql(db.executed[0])
    assert sql.lower().startswith("update alerts") and OWNER in params.values() and "huntress:7" in params.values()
    stored = next(v for v in params.values() if isinstance(v, dict) and "tickets" in v)["tickets"]
    assert stored == [{"id": "123", "system": "halopsa", "summary": "S", "status": "Open"}]  # absent fields are left out, not null


def test_the_alert_shows_only_well_formed_tickets():
    assert av.linked_tickets({"tickets": [{"id": "1", "summary": "a"}, {"summary": "no id"}, "junk", None]}) == [
        {"id": "1", "summary": "a"}
    ]
    assert av.linked_tickets({}) == [] and av.linked_tickets(None) == [] and av.linked_tickets({"tickets": "x"}) == []


def test_the_tickets_route_needs_no_session_but_a_token_and_the_alert_route_still_needs_alerts_read():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    paths = {r.path for r in cf.router.routes if isinstance(r, APIRoute)}
    assert "/inbox/core-feed/{tenant_token}/tickets" in paths
    alert_routes = {(m, r.path): r for r in av.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(alert_routes[("GET", "/alerts/{alert_id}/vendor-actions")])) == {"alerts:read"}
