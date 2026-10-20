"""Approve / reject / resolve a Huntress incident from AiSOC: what may be queued, who may collect it, and that nothing runs twice or late."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_vendor_actions as av
from app.api.v1.endpoints import inbox_core_feed as cf
from app.services import vendor_actions as rules
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

TENANT = uuid.uuid4()
ALERT_ID = uuid.uuid4()
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)

OPEN_PLAN = {"status": "sent", "remediations": [{"id": 1, "status": "unapproved"}, {"id": 2, "status": "approved"}]}
APPROVED_PLAN = {"status": "sent", "remediations": [{"id": 1, "status": "approved"}]}


def _sql(stmt) -> tuple[str, dict]:
    c = stmt.compile(dialect=postgresql.dialect())
    return str(c), c.params


# ---- the rules -------------------------------------------------------------------------------------------------------------------------------------------


def test_only_a_huntress_alert_with_a_numeric_incident_id_qualifies():
    assert rules.alert_incident_uid({"source": "huntress", "finding": {"uid": "huntress:4821"}}) == "huntress:4821"
    assert rules.alert_incident_uid({"source": "petra", "finding": {"uid": "petra:4821"}}) is None
    assert rules.alert_incident_uid({"source": "huntress", "finding": {"uid": "huntress:48/../21"}}) is None
    assert rules.alert_incident_uid({"source": "huntress", "finding": {}}) is None
    assert rules.alert_incident_uid(None) is None
    assert rules.huntress_incident_id("huntress:4821") == 4821
    assert rules.huntress_incident_id("huntress:4821; DROP") is None


def test_approve_and_reject_need_an_unapproved_remediation_and_resolve_needs_none_left():
    assert rules.problem_with_request("approve", OPEN_PLAN) is None
    assert rules.problem_with_request("reject", OPEN_PLAN) is None
    assert rules.problem_with_request("approve", APPROVED_PLAN) is not None
    assert rules.problem_with_request("resolve", OPEN_PLAN) is not None
    assert rules.problem_with_request("resolve", APPROVED_PLAN) is None


def test_nothing_can_be_requested_without_a_reported_state_or_on_an_incident_that_is_not_open():
    assert rules.problem_with_request("resolve", None) is not None
    assert rules.problem_with_request("resolve", {}) is not None
    assert rules.problem_with_request("resolve", {"status": "closed", "remediations": []}) is not None
    assert rules.problem_with_request("delete", OPEN_PLAN) is not None


def test_a_pending_action_expires_and_an_unanswered_claim_fails():
    old = NOW - rules.PENDING_TTL - timedelta(seconds=1)
    assert rules.effective_status("pending", old, None, NOW) == "expired"
    assert rules.effective_status("pending", NOW - timedelta(minutes=1), None, NOW) == "pending"
    stale = NOW - rules.CLAIMED_TTL - timedelta(seconds=1)
    assert rules.effective_status("claimed", old, stale, NOW) == "failed"
    assert rules.effective_status("done", old, stale, NOW) == "done"


# ---- queueing (analyst side) -----------------------------------------------------------------------------------------------------------------------------


def _alert(source="huntress", state=OPEN_PLAN, uid="huntress:7", status="new", context=None):
    raw = {"source": source, "finding": {"uid": uid}}
    if context is not None:
        raw["unmapped"] = {"context": context}
    return SimpleNamespace(
        id=ALERT_ID,
        tenant_id=TENANT,
        status=status,
        raw_event=raw,
        enrichment_data={"vendor_state": state} if state is not None else {},
    )


def _db(alert, in_flight=()):
    db = MagicMock()
    # First the scope probe (is the alert in the caller's own tenant? when not: any client tenants?), then the alert read, then the in-flight check.
    probe = (
        [MagicMock(first=MagicMock(return_value=(1,)))]
        if alert is not None
        else [MagicMock(first=MagicMock(return_value=None)), MagicMock(all=MagicMock(return_value=[]))]
    )
    results = [
        *probe,
        MagicMock(scalar_one_or_none=MagicMock(return_value=alert)),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=list(in_flight))))),
    ]

    async def execute(stmt, *a, **k):
        return results.pop(0)

    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


async def _request(db, **body):
    user = SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())
    return await av.request_vendor_action(ALERT_ID, av.VendorActionRequest(**body), MagicMock(), user, db)


@pytest.fixture(autouse=True)
def _audit(monkeypatch):
    calls = []

    async def fake(**kw):
        calls.append(kw)

    monkeypatch.setattr(av, "emit_audit", fake)
    return calls


@pytest.mark.asyncio
async def test_a_valid_request_is_queued_pending_and_audited(_audit):
    db = _db(_alert())
    item = await _request(db, action="approve")
    row = db.add.call_args.args[0]
    assert (row.status, row.action, row.incident_uid, row.tenant_id) == ("pending", "approve", "huntress:7", TENANT)
    assert item.status == "pending"
    db.commit.assert_awaited()
    assert _audit and _audit[0]["action"] == "alerts:vendor_action_requested" and _audit[0]["changes"]["action"] == "approve"


@pytest.mark.asyncio
async def test_a_reject_carries_its_reason_and_comment_and_needs_the_comment():
    db = _db(_alert())
    await _request(db, action="reject", comment="  this is our own admin  ", reason="approved_application", useful=False)
    assert db.add.call_args.args[0].params == {"comment": "this is our own admin", "reason": "approved_application", "useful": False}
    with pytest.raises(HTTPException) as e:
        await _request(_db(_alert()), action="reject", comment="   ")
    assert e.value.status_code == 422
    with pytest.raises(ValidationError):
        av.VendorActionRequest(action="reject", comment="x", reason="not-a-reason")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alert, body, code",
    [
        (_alert(source="petra", uid="petra:7"), {"action": "approve"}, 422),
        (_alert(state=None), {"action": "approve"}, 409),
        (_alert(state=APPROVED_PLAN), {"action": "approve"}, 409),
        (_alert(state=OPEN_PLAN), {"action": "resolve"}, 409),
        (_alert(), {"action": "approve"}, 409),  # an action already in flight (below)
    ],
)
async def test_requests_that_make_no_sense_are_refused_and_queue_nothing(alert, body, code):
    in_flight = (
        [object()]
        if body is not None
        and alert.raw_event["source"] == "huntress"
        and alert.enrichment_data.get("vendor_state") == OPEN_PLAN
        and body["action"] == "approve"
        else []
    )
    db = _db(alert, in_flight)
    with pytest.raises(HTTPException) as e:
        await _request(db, **body)
    assert e.value.status_code == code
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_unknown_alert_is_404():
    db = _db(None)
    with pytest.raises(HTTPException) as e:
        await _request(db, action="approve")
    assert e.value.status_code == 404


def test_the_queue_routes_need_the_right_permissions():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in av.router.routes if isinstance(r, APIRoute) for m in r.methods}
    path = "/alerts/{alert_id}/vendor-actions"
    assert set(required_permissions(routes[("POST", path)])) == {"connectors:write"}
    assert set(required_permissions(routes[("GET", path)])) == {"alerts:read"}


# ---- CORE side -------------------------------------------------------------------------------------------------------------------------------------------


def _exec_db(rowcounts=(), returning=None):
    db = MagicMock()
    db.executed = []
    counts = list(rowcounts)

    async def execute(stmt, *a, **k):
        db.executed.append(stmt)
        r = MagicMock(rowcount=counts.pop(0) if counts else 0)
        r.scalars.return_value.all.return_value = returning or []
        r.first.return_value = returning[0] if returning else None
        return r

    db.execute = AsyncMock(side_effect=execute)
    db.commit = AsyncMock()
    return db


def test_a_state_report_rejects_what_could_be_abused():
    with pytest.raises(ValidationError):
        cf.StateReport(vendor="petra", items=[])
    with pytest.raises(ValidationError):
        cf.StateItem(uid='huntress:1"|.*', status="sent")
    with pytest.raises(ValidationError):
        cf.StateReport(vendor="huntress", items=[cf.StateItem(uid=f"huntress:{i}", status="sent") for i in range(501)])


@pytest.mark.asyncio
async def test_state_is_stored_on_this_tenants_alert_for_that_incident_only():
    db = _exec_db([1, 0])
    rep = cf.StateReport(
        vendor="huntress",
        items=[
            cf.StateItem(
                uid="huntress:7",
                status="sent",
                remediations=[cf._Remediation(id=1, status="unapproved", action="Delete File")],
                psa_ticket_eids=["T-1"],
            ),
            cf.StateItem(uid="petra:9", status="sent"),
        ],
    )
    assert await cf.apply_state(db, TENANT, rep, NOW) == 1
    assert len(db.executed) == 1  # the petra uid is not this vendor's, so no statement for it
    sql, params = _sql(db.executed[0])
    assert sql.lower().startswith("update alerts") and "tenant_id" in sql
    assert TENANT in params.values() and "huntress:7" in params.values()
    stored = next(v for v in params.values() if isinstance(v, dict) and "vendor_state" in v)["vendor_state"]
    assert stored["status"] == "sent" and stored["psa_ticket_eids"] == ["T-1"] and stored["remediations"][0]["action"] == "Delete File"


@pytest.mark.asyncio
async def test_claiming_expires_old_work_first_then_claims_pending_for_this_tenant_and_vendor_only():
    row = SimpleNamespace(id=uuid.uuid4(), created_at=NOW)
    db = _exec_db([0, 0, 1], returning=[row])
    got = await cf.claim_actions(db, TENANT, "huntress", NOW)
    assert got == [row]
    expire_pending, fail_claimed, claim = (_sql(s) for s in db.executed)
    assert "created_at <" in expire_pending[0] and "failed" in expire_pending[1].values() and "pending" in expire_pending[1].values()
    assert "claimed_at <" in fail_claimed[0] and "failed" in fail_claimed[1].values() and "claimed" in fail_claimed[1].values()
    sql, params = claim
    assert sql.lower().startswith("update vendor_actions") and "RETURNING" in sql
    assert TENANT in params.values() and "huntress" in params.values() and "pending" in params.values() and "claimed" in params.values()


@pytest.mark.asyncio
async def test_a_result_is_accepted_only_for_a_claimed_action_of_this_tenant(monkeypatch):
    monkeypatch.setattr(cf, "_verify_core_feed_token", AsyncMock(return_value=TENANT))
    monkeypatch.setattr(cf, "adopt_tenant", AsyncMock())
    monkeypatch.setattr(cf, "_scope_ids", AsyncMock(return_value=[TENANT]))
    db = _exec_db(returning=[])  # nothing matched
    with pytest.raises(HTTPException) as e:
        await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="done"), db)
    assert e.value.status_code == 404
    sql, params = _sql(db.executed[0])
    assert "status =" in sql and "claimed" in params.values() and TENANT in params.values()


@pytest.mark.asyncio
async def test_a_done_resolve_resolves_the_alert_but_only_while_it_is_still_new(monkeypatch):
    monkeypatch.setattr(cf, "_verify_core_feed_token", AsyncMock(return_value=TENANT))
    monkeypatch.setattr(cf, "adopt_tenant", AsyncMock())
    monkeypatch.setattr(cf, "_scope_ids", AsyncMock(return_value=[TENANT]))
    db = _exec_db(returning=[SimpleNamespace(alert_id=ALERT_ID, action="resolve")])
    out = await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="done", message="ok"), db)
    assert out.recorded is True
    sql, params = _sql(db.executed[1])
    assert sql.lower().startswith("update alerts") and "resolved" in params.values() and "new" in params.values()
    # an approve, or a failed resolve, leaves the alert alone
    db2 = _exec_db(returning=[SimpleNamespace(alert_id=ALERT_ID, action="approve")])
    await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="done"), db2)
    assert len(db2.executed) == 1
    db3 = _exec_db(returning=[SimpleNamespace(alert_id=ALERT_ID, action="resolve")])
    await cf.report_core_feed_action_result("tok", uuid.uuid4(), cf.ActionResult(status="failed", message="409"), db3)
    assert len(db3.executed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("call", ["state", "claim", "result"])
async def test_a_bad_core_feed_token_gets_401_on_every_new_route(monkeypatch, call):
    async def deny(db, token):
        raise HTTPException(status_code=401, detail="Invalid or revoked inbox token")

    monkeypatch.setattr(cf, "_verify_core_feed_token", deny)
    db = _exec_db()
    with pytest.raises(HTTPException) as e:
        if call == "state":
            await cf.report_core_feed_state("bad", cf.StateReport(vendor="huntress", items=[]), db)
        elif call == "claim":
            await cf.claim_core_feed_actions("bad", cf.ClaimRequest(vendor="huntress"), db)
        else:
            await cf.report_core_feed_action_result("bad", uuid.uuid4(), cf.ActionResult(status="done"), db)
    assert e.value.status_code == 401
    assert db.executed == []


# ---- Blumira and Field Effect: resolve only -------------------------------------------------------------------------------------------------------------


def test_blumira_and_field_effect_alerts_qualify_by_their_own_uid_and_nothing_else_does():
    assert rules.alert_vendor_and_uid({"source": "huntress", "finding": {"uid": "huntress:7"}}) == ("huntress", "huntress:7")
    assert rules.alert_vendor_and_uid({"source": "blumira", "finding": {"uid": "blumira:0f8e-12"}}) == ("blumira", "blumira:0f8e-12")
    assert rules.alert_vendor_and_uid({"source": "fieldeffect", "finding": {"uid": "fieldeffect:abc123"}}) == (
        "fieldeffect",
        "fieldeffect:abc123",
    )
    # a uid of one vendor on another vendor's record, a path trick, or no id at all
    assert rules.alert_vendor_and_uid({"source": "blumira", "finding": {"uid": "fieldeffect:abc"}}) is None
    assert rules.alert_vendor_and_uid({"source": "blumira", "finding": {"uid": "blumira:a/../b"}}) is None
    assert rules.alert_vendor_and_uid({"source": "ninjaone", "finding": {"uid": "ninjaone:5"}}) is None
    assert rules.alert_vendor_and_uid({"source": "blumira", "finding": {}}) is None
    assert rules.alert_vendor_and_uid(None) is None


def test_resolve_only_rules():
    assert rules.problem_with_resolve_only("blumira", "resolve", 30, "new") is None
    assert rules.problem_with_resolve_only("blumira", "resolve", None, "new") is not None
    assert rules.problem_with_resolve_only("blumira", "resolve", 99, "new") is not None
    assert rules.problem_with_resolve_only("fieldeffect", "resolve", None, "new") is None
    assert rules.problem_with_resolve_only("fieldeffect", "approve", None, "new") is not None
    assert rules.problem_with_resolve_only("blumira", "resolve", 10, "resolved") is not None


def test_the_blumira_account_id_comes_from_the_records_context():
    assert rules.vendor_account_id({"unmapped": {"context": {"blumira_account_id": " acc-1 "}}}) == "acc-1"
    assert rules.vendor_account_id({"unmapped": {"context": {}}}) is None
    assert rules.vendor_account_id({"unmapped": "x"}) is None
    assert rules.vendor_account_id(None) is None


@pytest.mark.asyncio
async def test_a_blumira_resolve_is_queued_with_its_resolution_note_and_account():
    alert = _alert(source="blumira", uid="blumira:f1", state=None, context={"blumira_account_id": "acc-9"})
    db = _db(alert)
    await _request(db, action="resolve", resolution=30, comment="  patched  ")
    row = db.add.call_args.args[0]
    assert (row.vendor, row.action, row.incident_uid, row.status) == ("blumira", "resolve", "blumira:f1", "pending")
    assert row.params == {"resolution": 30, "notes": "patched", "account_id": "acc-9"}


@pytest.mark.asyncio
async def test_a_field_effect_resolve_is_queued_with_its_comment():
    db = _db(_alert(source="fieldeffect", uid="fieldeffect:aro1", state=None))
    await _request(db, action="resolve", comment="done")
    row = db.add.call_args.args[0]
    assert (row.vendor, row.incident_uid, row.params) == ("fieldeffect", "fieldeffect:aro1", {"comment": "done"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alert, body",
    [
        (_alert(source="blumira", uid="blumira:f1", state=None), {"action": "resolve"}),  # no resolution picked
        (_alert(source="blumira", uid="blumira:f1", state=None), {"action": "resolve", "resolution": 5}),
        (_alert(source="blumira", uid="blumira:f1", state=None), {"action": "approve"}),
        (_alert(source="fieldeffect", uid="fieldeffect:a", state=None), {"action": "reject", "comment": "x"}),
        (_alert(source="fieldeffect", uid="fieldeffect:a", state=None, status="resolved"), {"action": "resolve"}),
    ],
)
async def test_resolve_only_requests_that_make_no_sense_queue_nothing(alert, body):
    db = _db(alert)
    with pytest.raises(HTTPException) as e:
        await _request(db, **body)
    assert e.value.status_code == 409
    db.add.assert_not_called()


def test_core_may_claim_for_blumira_and_field_effect_but_not_for_any_other_vendor():
    for vendor in ("huntress", "blumira", "fieldeffect"):
        assert cf.ClaimRequest(vendor=vendor).vendor == vendor
    with pytest.raises(ValidationError):
        cf.ClaimRequest(vendor="ninjaone")


# ---- re-check one alert's tool ---------------------------------------------------------------------------------------------------------------------------


def _refresh_db(alert, rowcount=1):
    db = _db(alert)
    probe = [MagicMock(first=MagicMock(return_value=(1,)))]
    queue = [*probe, MagicMock(scalar_one_or_none=MagicMock(return_value=alert)), MagicMock(rowcount=rowcount)]
    seen: list = []

    async def execute(stmt, *a, **k):
        seen.append(stmt)
        return queue.pop(0)

    db.execute = AsyncMock(side_effect=execute)
    db.seen = seen
    return db


async def _refresh(db):
    user = SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())
    return await av.refresh_alert_status(ALERT_ID, MagicMock(), user, db)


@pytest.mark.asyncio
async def test_refresh_asks_only_the_alerts_own_tool_and_is_audited(_audit):
    db = _refresh_db(_alert())
    out = await _refresh(db)
    assert out.vendor == "huntress"
    sql, params = _sql(db.seen[-1])
    assert sql.startswith("UPDATE connectors") and "sync_requested_at" in str(params.values()) and "huntress" in params.values()
    assert TENANT in params.values() and "core_feed" in params.values()
    assert _audit and _audit[0]["action"] == "alerts:refresh_requested"
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_refresh_says_so_when_nothing_feeds_that_tool_or_the_alert_has_no_incident():
    with pytest.raises(HTTPException) as e:
        await _refresh(_refresh_db(_alert(), rowcount=0))
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:
        await _refresh(_refresh_db(_alert(source="petra", uid="petra:7")))
    assert e.value.status_code == 422
