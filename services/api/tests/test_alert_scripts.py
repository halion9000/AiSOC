"""Run a CORE script from an alert: what CORE publishes, what may be queued, and that the request carries only what the alert and the owner's list allow."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_scripts as sc
from app.api.v1.endpoints import inbox_core_feed as cf
from fastapi import HTTPException
from pydantic import ValidationError

TENANT = uuid.uuid4()
ALERT_ID = uuid.uuid4()
SETTINGS = {"core_scripts": [{"id": 7, "name": "Disk Space Scan", "one_click": True}, {"id": 9, "name": "Restart Spooler", "one_click": False}]}


def test_only_well_formed_published_scripts_are_offered_sorted():
    out = sc.published_scripts({"core_scripts": [{"id": 9, "name": "b"}, {"id": "x", "name": "bad"}, {"id": 3, "name": " "}, {"id": 7, "name": "A", "one_click": True}, "junk"]})
    assert [(s.id, s.name, s.one_click) for s in out] == [(7, "A", True), (9, "b", False)]
    assert sc.published_scripts(None) == [] and sc.published_scripts({"core_scripts": "nope"}) == []


def test_the_device_is_the_first_host_the_alert_names():
    assert sc.device_of(SimpleNamespace(affected_hosts=["  ", "PC-01", "PC-02"])) == "PC-01"
    assert sc.device_of(SimpleNamespace(affected_hosts=[])) is None
    assert sc.device_of(SimpleNamespace(affected_hosts=None)) is None


def test_a_script_list_report_is_bounded():
    assert cf.ScriptsReport(scripts=[{"id": 1, "name": "x", "one_click": True}]).scripts[0].one_click is True
    with pytest.raises(ValidationError):
        cf.ScriptsReport(scripts=[{"id": 0, "name": "x"}])
    with pytest.raises(ValidationError):
        cf.ScriptsReport(scripts=[{"id": 1, "name": ""}])


def _alert(hosts=("PC-01",), uid="ninjaone:55"):
    return SimpleNamespace(
        id=ALERT_ID, tenant_id=TENANT, title="Disk space low", description="C: is at 4%", affected_hosts=list(hosts), enrichment_data={}, raw_event={"finding": {"uid": uid}}
    )


def _db(alert, settings=SETTINGS, extra=()):
    db = MagicMock()
    queue = [
        MagicMock(scalar_one_or_none=MagicMock(return_value=settings)),  # the owner's published scripts
        MagicMock(first=MagicMock(return_value=(1,))),  # the alert is in the caller's own tenant
        MagicMock(scalar_one_or_none=MagicMock(return_value=alert)),  # the alert
        *extra,
    ]
    seen: list = []

    async def execute(stmt, *a, **k):
        seen.append(stmt)
        return queue.pop(0)

    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.seen = seen
    return db


@pytest.fixture(autouse=True)
def _audit(monkeypatch):
    calls = []

    async def fake(**kw):
        calls.append(kw)

    monkeypatch.setattr(sc, "emit_audit", fake)
    return calls


async def _run(db, **body):
    user = SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())
    return await sc.run_alert_script(ALERT_ID, sc.RunScriptRequest(**body), MagicMock(), user, db)


NO_FLIGHT = MagicMock(first=MagicMock(return_value=None))


@pytest.mark.asyncio
async def test_a_linked_ticket_request_is_queued_for_core_with_the_device_script_and_ticket(_audit):
    db = _db(_alert(), extra=[NO_FLIGHT])
    out = await _run(db, script_id=7, ticket={"mode": "link", "number": "#0553688"})
    row = db.add.call_args.args[0]
    assert (row.vendor, row.action, row.status, row.incident_uid) == ("core", "run_script", "pending", "ninjaone:55")
    assert row.params["device"] == "PC-01" and row.params["script_id"] == 7 and row.params["ticket_id"] == "553688"
    assert out.runs_at_once is True and _audit[0]["action"] == "alerts:script_requested"
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_create_mode_carries_what_core_needs_to_open_the_ticket():
    db = _db(_alert(), extra=[MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value="1234")))), NO_FLIGHT])
    out = await _run(db, script_id=9, ticket={"mode": "create"})
    ticket = db.add.call_args.args[0].params["create_ticket"]
    assert ticket["halo_client_id"] == "1234" and ticket["summary"].startswith("Restart Spooler") and "C: is at 4%" in ticket["details"]
    assert out.runs_at_once is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alert, body, code",
    [
        (_alert(), {"script_id": 99}, 422),  # not a script CORE published
        (_alert(hosts=()), {"script_id": 7}, 422),  # no machine to run it on
        (_alert(), {"script_id": 7, "ticket": {"mode": "link", "number": "abc"}}, 422),
        (_alert(), {"script_id": 7, "ticket": {"mode": "link"}}, 422),
    ],
)
async def test_requests_that_make_no_sense_are_refused_and_queue_nothing(alert, body, code):
    db = _db(alert)
    with pytest.raises(HTTPException) as e:
        await _run(db, **body)
    assert e.value.status_code == code
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_a_case_that_does_not_hold_the_alert_is_refused():
    db = _db(_alert(), extra=[MagicMock(first=MagicMock(return_value=None))])
    with pytest.raises(HTTPException) as e:
        await _run(db, script_id=7, case_id=str(uuid.uuid4()))
    assert e.value.status_code == 422
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_a_second_request_while_one_is_waiting_is_refused():
    db = _db(_alert(), extra=[MagicMock(first=MagicMock(return_value=(uuid.uuid4(),)))])
    with pytest.raises(HTTPException) as e:
        await _run(db, script_id=7)
    assert e.value.status_code == 409
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_the_options_say_why_nothing_can_run():
    user = SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())
    none_case = MagicMock(first=MagicMock(return_value=None))
    out = await sc.alert_script_options(ALERT_ID, user, _db(_alert(), settings={}, extra=[none_case]))
    assert out.blocked and "CORE has not shared" in out.blocked
    out = await sc.alert_script_options(ALERT_ID, user, _db(_alert(hosts=()), extra=[none_case]))
    assert out.blocked and "does not name a machine" in out.blocked
    case = SimpleNamespace(id=uuid.uuid4(), case_number="C-9")
    out = await sc.alert_script_options(ALERT_ID, user, _db(_alert(), extra=[MagicMock(first=MagicMock(return_value=case))]))
    assert out.blocked is None and out.device == "PC-01" and out.case_number == "C-9" and [s.id for s in out.scripts] == [7, 9]
