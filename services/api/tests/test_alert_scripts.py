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
SETTINGS = {
    "core_scripts": [{"id": 7, "name": "Disk Space Scan", "one_click": True}, {"id": 9, "name": "Restart Spooler", "one_click": False}]
}


def test_only_well_formed_published_scripts_are_offered_sorted():
    out = sc.published_scripts(
        {
            "core_scripts": [
                {"id": 9, "name": "b"},
                {"id": "x", "name": "bad"},
                {"id": 3, "name": " "},
                {"id": 7, "name": "A", "one_click": True},
                "junk",
            ]
        }
    )
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
        id=ALERT_ID,
        tenant_id=TENANT,
        title="Disk space low",
        description="C: is at 4%",
        affected_hosts=list(hosts),
        enrichment_data={},
        raw_event={"finding": {"uid": uid}},
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
        (_alert(), {"script_id": 99, "ticket": {"mode": "link", "number": "5"}}, 422),  # not a script CORE published
        (_alert(hosts=()), {"script_id": 7, "ticket": {"mode": "link", "number": "5"}}, 422),  # no machine to run it on
        (_alert(), {"script_id": 7}, 422),  # no ticket chosen
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
        await _run(db, script_id=7, ticket={"mode": "link", "number": "5"}, case_id=str(uuid.uuid4()))
    assert e.value.status_code == 422
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_a_second_request_while_one_is_waiting_is_refused():
    db = _db(_alert(), extra=[MagicMock(first=MagicMock(return_value=(uuid.uuid4(),)))])
    with pytest.raises(HTTPException) as e:
        await _run(db, script_id=7, ticket={"mode": "link", "number": "5"})
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


@pytest.mark.asyncio
async def test_the_runs_list_shows_each_request_with_how_it_went():
    from datetime import UTC, datetime

    row = SimpleNamespace(
        id=uuid.uuid4(),
        params={"script_name": "Disk Space Scan", "device": "PC-01", "ticket_id": "553688"},
        status="done",
        created_at=datetime.now(UTC),
        claimed_at=datetime.now(UTC),
        result_message="Started.",
        finished_at=datetime.now(UTC),
    )
    created = SimpleNamespace(
        **{**row.__dict__, "id": uuid.uuid4(), "params": {"script_name": "Restart", "create_ticket": {"summary": "x"}}, "status": "failed"}
    )
    db = _db(_alert(), extra=[MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[row, created]))))])
    # The first queued result in _db is the owner's settings, which this route does not read; drop it.
    db.execute.side_effect = None
    queue = [
        MagicMock(first=MagicMock(return_value=(1,))),
        MagicMock(scalar_one_or_none=MagicMock(return_value=_alert())),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[row, created])))),
    ]

    async def execute(stmt, *a, **k):
        return queue.pop(0)

    db.execute = AsyncMock(side_effect=execute)
    out = await sc.alert_script_runs(ALERT_ID, SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4()), db)
    assert [(r.script_name, r.status, r.ticket_id, r.new_ticket) for r in out] == [
        ("Disk Space Scan", "done", "553688", False),
        ("Restart", "failed", None, True),
    ]


def test_a_low_disk_alert_suggests_the_one_disk_script_and_nothing_else_is_guessed():
    scripts = [sc.ScriptOption(id=7, name="Disk Space Scan"), sc.ScriptOption(id=9, name="Restart Spooler")]
    assert sc.suggested_script("Low disk space on C:", scripts) == 7
    assert sc.suggested_script("Printer offline", scripts) is None
    assert (
        sc.suggested_script("Low disk space", [sc.ScriptOption(id=1, name="Disk A"), sc.ScriptOption(id=2, name="Drive B")]) is None
    ), "two fit: no guess"
    assert sc.suggested_script(None, scripts) is None


@pytest.mark.asyncio
async def test_asking_from_a_case_leaves_a_system_comment_on_the_case_so_the_timeline_reads_in_order():
    case_id = uuid.uuid4()
    db = _db(_alert(), extra=[MagicMock(first=MagicMock(return_value=(1,))), NO_FLIGHT, MagicMock()])
    await _run(db, script_id=7, ticket={"mode": "link", "number": "553688"}, case_id=str(case_id))
    insert = db.seen[-1]
    sql = str(insert)
    assert "aisoc_case_comments" in sql and "is_system" in sql
    params = insert.compile().params
    assert params["c"] == case_id and "Disk Space Scan" in params["b"] and "553688" in params["b"]


# ---- bulk: one script, many alerts, one batch --------------------------------------------------------------------------------------------------------------


def _bulk_db(*alerts, flying=()):
    """Answers by what is asked (not by order): the owner's scripts, the tenant lookup, the alert, the in-flight check, the halopsa client."""
    by_id = {a.id: a for a in alerts}
    current: list = []
    db = MagicMock()

    async def execute(stmt, *a, **k):
        sql = str(stmt).lower()
        if "from tenants" in sql:
            return MagicMock(scalar_one_or_none=MagicMock(return_value=SETTINGS))
        if "from vendor_actions" in sql:
            return MagicMock(first=MagicMock(return_value=(uuid.uuid4(),) if current[-1] in flying else None))
        if "from client_aliases" in sql:
            return MagicMock(scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value="77"))))
        if "from alerts" in sql and "alerts.id =" in sql and "alerts.tenant_id =" in sql:
            params = stmt.compile().params
            alert_id = next(v for v in params.values() if v in by_id)
            current.append(alert_id)
            return MagicMock(first=MagicMock(return_value=(1,)), scalar_one_or_none=MagicMock(return_value=by_id[alert_id]))
        return MagicMock(first=MagicMock(return_value=(1,)), scalar_one_or_none=MagicMock(return_value=by_id[current[-1]]))

    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


def _a(host, uid):
    a = _alert(hosts=(host,) if host else (), uid=uid)
    a.id = uuid.uuid4()
    return a


async def _bulk(db, alerts, **body):
    user = SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())
    return await sc.run_script_bulk(
        sc.BulkRunRequest(script_id=body.pop("script_id", 7), alert_ids=[a.id for a in alerts], **body), MagicMock(), user, db
    )


@pytest.mark.asyncio
async def test_bulk_queues_one_request_per_machine_with_its_own_new_ticket_and_one_shared_batch_id():
    alerts = [_a("PC-01", "n:1"), _a("PC-02", "n:2")]
    db = _bulk_db(*alerts)
    out = await _bulk(db, alerts)
    rows = [c.args[0] for c in db.add.call_args_list]
    assert [r.params["device"] for r in rows] == ["PC-01", "PC-02"]
    assert len({r.params["batch_id"] for r in rows}) == 1 and rows[0].params["batch_id"] == out.batch_id
    assert all(
        "create_ticket" in r.params and "ticket_id" not in r.params and r.params["create_ticket"]["halo_client_id"] == "77" for r in rows
    )
    assert (out.queued, out.skipped) == (2, 0)
    assert db.commit.await_count == 1, "one commit for the whole batch, so CORE sees every request together"


@pytest.mark.asyncio
async def test_bulk_asks_for_a_machine_once_and_skips_what_cannot_go_with_the_reason():
    alerts = [_a("PC-01", "n:1"), _a("pc-01", "n:2"), _a(None, "n:3"), _a("PC-04", "n:4")]
    flying = {alerts[3].id}
    db = _bulk_db(*alerts, flying=flying)
    out = await _bulk(db, alerts)
    assert [i.outcome for i in out.items] == ["queued", "skipped", "skipped", "skipped"]
    assert "already covers" in (out.items[1].reason or "") and "does not name a machine" in (out.items[2].reason or "")
    assert "already waiting" in (out.items[3].reason or "")
    assert db.add.call_count == 1 and out.queued == 1 and out.skipped == 3


@pytest.mark.asyncio
async def test_bulk_preview_says_what_would_happen_and_queues_nothing():
    alerts = [_a("PC-01", "n:1"), _a("PC-02", "n:2")]
    db = _bulk_db(*alerts)
    out = await _bulk(db, alerts, preview=True)
    assert out.preview and out.queued == 2 and out.batch_id is None
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_refuses_a_script_core_has_not_switched_on_and_queues_nothing():
    alerts = [_a("PC-01", "n:1")]
    db = _bulk_db(*alerts)
    with pytest.raises(HTTPException) as e:
        await _bulk(db, alerts, script_id=99)
    assert e.value.status_code == 422
    db.add.assert_not_called()


def test_bulk_is_bounded_and_needs_alerts():
    with pytest.raises(ValidationError):
        sc.BulkRunRequest(script_id=7, alert_ids=[])
    with pytest.raises(ValidationError):
        sc.BulkRunRequest(script_id=7, alert_ids=[uuid.uuid4() for _ in range(sc.MAX_BULK + 1)])
