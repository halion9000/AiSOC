"""Other alerts about the same device or person."""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_related as ar
from fastapi import HTTPException

TENANT = uuid.uuid4()
ALERT_ID = uuid.uuid4()


def test_names_are_distinct_text_only_and_capped():
    assert ar.names_of(["PC-1", " PC-1 ", "", 5, None, "PC-2"]) == ["PC-1", "PC-2"]
    assert ar.names_of("PC-1") == [] and ar.names_of(None) == []
    assert len(ar.names_of([f"h{i}" for i in range(100)])) == ar.MAX_NAMES


def test_the_match_says_what_is_shared_and_nothing_when_nothing_is():
    assert ar.match_label(["PC-1"], ["a@x.com"], ["PC-1"], []) == "device"
    assert ar.match_label(["PC-1"], ["a@x.com"], [], ["a@x.com"]) == "user"
    assert ar.match_label(["PC-1"], ["a@x.com"], ["PC-1"], ["a@x.com"]) == "device and user"
    assert ar.match_label(["PC-1"], ["a@x.com"], ["pc-1"], ["A@x.com"]) is None, "names are matched exactly as stored"
    assert ar.match_label([], [], ["PC-1"], ["a@x.com"]) is None


def _row(title, hosts=(), users=(), source="petra"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        title=title,
        severity="high",
        status="new",
        created_at=datetime(2026, 10, 18, tzinfo=UTC),
        affected_hosts=list(hosts),
        affected_users=list(users),
        raw_event={"source": source},
        connector_type="generic",
    )


def _db(alert, related):
    db = MagicMock()
    results = [
        MagicMock(first=MagicMock(return_value=(1,))),  # the alert is in the caller's own tenant
        MagicMock(scalar_one_or_none=MagicMock(return_value=alert)),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=related)))),
    ]
    db.execute = AsyncMock(side_effect=lambda *a, **k: results.pop(0))
    return db


def _user():
    return SimpleNamespace(tenant_id=TENANT)


@pytest.mark.asyncio
async def test_lists_other_alerts_for_the_same_device_or_user_with_why_they_match():
    me = _row("Huntress incident", hosts=["PC-1"], users=["kevin@acme.com"], source="huntress")
    out = await ar.related_alerts(
        ALERT_ID,
        _user(),
        _db(
            me,
            [
                _row("Petra incident", users=["kevin@acme.com"]),
                _row("Earlier malware", hosts=["PC-1"], source="huntress"),
                _row("Unrelated", hosts=["PC-9"]),
            ],
        ),
    )
    assert [(i.title, i.matched) for i in out.items] == [("Petra incident", "user"), ("Earlier malware", "device")]
    assert out.more == 0


@pytest.mark.asyncio
async def test_an_alert_that_names_no_device_or_user_has_nothing_related_and_asks_no_query():
    db = _db(_row("Nothing named"), [])
    out = await ar.related_alerts(ALERT_ID, _user(), db)
    assert out.items == [] and db.execute.await_count == 2, "only the scope probe and the alert read"


@pytest.mark.asyncio
async def test_more_than_the_limit_is_reported_as_more():
    me = _row("me", hosts=["PC-1"])
    many = [_row(f"a{i}", hosts=["PC-1"]) for i in range(ar.MAX_RELATED + 1)]
    out = await ar.related_alerts(ALERT_ID, _user(), _db(me, many))
    assert len(out.items) == ar.MAX_RELATED and out.more == 1


@pytest.mark.asyncio
async def test_an_alert_the_caller_cannot_see_is_404():
    db = MagicMock()
    results = [MagicMock(first=MagicMock(return_value=None)), MagicMock(all=MagicMock(return_value=[]))]
    db.execute = AsyncMock(side_effect=lambda *a, **k: results.pop(0))
    with pytest.raises(HTTPException) as e:
        await ar.related_alerts(ALERT_ID, _user(), db)
    assert e.value.status_code == 404


def test_the_route_needs_alerts_read():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in ar.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("GET", "/alerts/{alert_id}/related")])) == {"alerts:read"}
