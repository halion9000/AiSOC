"""Hiding an alert type: what an alert type is, who a rule covers, how long it lasts, and what the endpoints refuse. The database parts run against a fake session (SQL is not executed here)."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import alert_suppressions as ep
from app.services import alert_scope as scope
from app.services import alert_suppression as sup
from fastapi import HTTPException

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
OWNER, CLIENT, OTHER = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def rule(**over):
    base = {
        "id": uuid.uuid4(),
        "tenant_id": OWNER,
        "scope": "client",
        "client_tenant_id": CLIENT,
        "device_key": None,
        "source": "ninjaone",
        "signature": "title:Process: 'x' does not exist",
        "revoked_at": None,
        "expires_at": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


def alert(**over):
    base = {"tenant_id": CLIENT, "rule_id": None, "title": "Process: 'x' does not exist", "source": "ninjaone", "hosts": ["PC-1.corp.local"]}
    base.update(over)
    return base


def m(r, **over):
    return sup.matches(r, **alert(**over))


# ---- what an alert type is ---------------------------------------------------------------------------------------------------------------------------------


def test_the_type_is_the_rule_id_when_there_is_one_else_the_title():
    assert sup.signature_of("R-42", "Whatever") == "rule:R-42"
    assert sup.signature_of(" R-42 ", None) == "rule:R-42"
    assert sup.signature_of(None, " A title ") == "title:A title"
    assert sup.signature_of("", "A title") == "title:A title"


def test_the_source_comes_from_the_alert_then_the_connector_and_may_be_unknown():
    assert sup.source_of({"source": "NinjaOne"}, "generic") == "ninjaone"
    assert sup.source_of({}, "Huntress") == "huntress"
    assert sup.source_of(None, None) is None
    assert sup.source_of({"source": ""}, None) is None


# ---- who a rule covers -------------------------------------------------------------------------------------------------------------------------------------


def test_a_client_rule_covers_that_clients_alerts_of_that_type_from_that_tool_only():
    r = rule()
    assert m(r)
    assert not m(r, tenant_id=OTHER), "another client"
    assert not m(r, title="Something else"), "another type"
    assert not m(r, source="huntress"), "another tool"
    assert not m(r, source=None)


def test_an_all_rule_covers_every_client():
    r = rule(scope="all", client_tenant_id=None)
    assert m(r, tenant_id=CLIENT) and m(r, tenant_id=OTHER)
    assert not m(r, title="Something else")


def test_a_device_rule_covers_only_that_machine_of_that_client_whatever_the_domain_or_case():
    r = rule(scope="device", device_key="pc-1")
    assert m(r)
    assert m(r, hosts=["pc-1"])
    assert m(r, hosts=["OTHER", "PC-1.other.local"])
    assert not m(r, hosts=["PC-2"])
    assert not m(r, hosts=[])
    assert not m(r, tenant_id=OTHER, hosts=["PC-1"]), "the same name in another client is another machine"


def test_a_device_rule_with_no_device_covers_nothing():
    assert not m(rule(scope="device", device_key=None))


def test_a_rule_id_type_matches_on_the_rule_not_the_title():
    r = rule(signature="rule:R-42")
    assert m(r, rule_id="R-42", title="Any wording")
    assert not m(r, rule_id="R-43")
    assert not m(r, rule_id=None)


# ---- how long ----------------------------------------------------------------------------------------------------------------------------------------------


def test_days_become_an_end_date_and_no_days_means_without_end():
    assert sup.expiry_from_days(None, NOW) is None
    assert sup.expiry_from_days(7, NOW) == NOW + timedelta(days=7)
    assert sup.expiry_from_days(1, NOW) == NOW + timedelta(days=1)
    assert sup.expiry_from_days(sup.MAX_DAYS, NOW) == NOW + timedelta(days=sup.MAX_DAYS)


@pytest.mark.parametrize("bad", [0, -3, sup.MAX_DAYS + 1, True, 2.5, "7"])
def test_other_day_counts_are_refused(bad):
    with pytest.raises(HTTPException) as e:
        sup.expiry_from_days(bad, NOW)
    assert e.value.status_code == 422


def test_a_rule_hides_until_it_is_lifted_or_runs_out():
    assert sup.is_active(rule(expires_at=None), NOW)
    assert sup.is_active(rule(expires_at=NOW + timedelta(seconds=1)), NOW)
    assert not sup.is_active(rule(expires_at=NOW), NOW)
    assert not sup.is_active(rule(expires_at=NOW - timedelta(days=1)), NOW)
    assert not sup.is_active(rule(revoked_at=NOW - timedelta(days=1)), NOW)


# ---- the endpoint ------------------------------------------------------------------------------------------------------------------------------------------


class FakeDB:
    def __init__(self, alert_row):
        self.alert_row = alert_row
        self.added = []
        self.commits = 0

    async def execute(self, statement):
        row = self.alert_row
        return SimpleNamespace(scalar_one_or_none=lambda: row, all=lambda: [])

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for o in self.added:
            o.id = o.id or uuid.uuid4()
            o.created_at = o.created_at or NOW

    async def commit(self):
        self.commits += 1


def an_alert(**over):
    base = {"title": "Process: 'x' does not exist", "rule_id": None, "raw_event": {"source": "ninjaone"}, "connector_type": None, "affected_hosts": ["PC-1.corp.local"]}
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def wired(monkeypatch):
    applied = []

    async def find(db, own, alert_id):
        return CLIENT

    async def fake_apply(db, r, owner):
        applied.append(r)
        return 3

    monkeypatch.setattr(scope, "find_alert_tenant", find)
    monkeypatch.setattr(scope, "acting_as_tenant", lambda db, tid: __import__("contextlib").nullcontext())
    monkeypatch.setattr(ep, "apply_rule", fake_apply)
    return applied


def user():
    return SimpleNamespace(tenant_id=OWNER, user_id=uuid.uuid4())


def hide(db, **over):
    body = ep.SuppressionIn(**{"alert_id": uuid.uuid4(), "scope": "client", **over})
    return asyncio.run(ep.hide_alert_type(body, user(), db))


def test_hiding_for_the_client_stores_the_type_the_tool_and_the_client_and_hides_open_alerts_now(wired):
    db = FakeDB(an_alert())
    out = hide(db, scope="client", days=30)
    rule_row = db.added[0]
    assert (rule_row.scope, rule_row.client_tenant_id, rule_row.tenant_id) == ("client", CLIENT, OWNER)
    assert rule_row.signature == "title:Process: 'x' does not exist" and rule_row.source == "ninjaone"
    assert rule_row.expires_at is not None and (rule_row.expires_at - datetime.now(UTC)) > timedelta(days=29)
    assert out.hidden_alerts == 3 and out.indefinite is False and out.active is True
    assert db.commits == 1 and wired == [rule_row]


def test_hiding_for_all_clients_is_not_tied_to_the_alerts_client_and_can_be_indefinite(wired):
    db = FakeDB(an_alert())
    out = hide(db, scope="all")
    assert db.added[0].client_tenant_id is None and db.added[0].expires_at is None
    assert out.indefinite is True and out.expires_at is None


def test_hiding_for_the_device_uses_the_only_machine_the_alert_names(wired):
    db = FakeDB(an_alert())
    hide(db, scope="device", days=1)
    assert db.added[0].device_key == "pc-1" and db.added[0].client_tenant_id == CLIENT


def test_a_device_rule_needs_a_machine_the_alert_names(wired):
    two = FakeDB(an_alert(affected_hosts=["A", "B"]))
    with pytest.raises(HTTPException) as e:
        hide(two, scope="device")
    assert e.value.status_code == 422 and "which one" in e.value.detail
    assert hide(FakeDB(an_alert(affected_hosts=["A", "B"])), scope="device", device="b.corp.local")
    with pytest.raises(HTTPException):
        hide(FakeDB(an_alert(affected_hosts=["A", "B"])), scope="device", device="elsewhere")
    with pytest.raises(HTTPException) as none:
        hide(FakeDB(an_alert(affected_hosts=[])), scope="device")
    assert none.value.status_code == 422
    assert not two.added and two.commits == 0


def test_bad_days_are_refused_before_anything_is_stored(wired):
    db = FakeDB(an_alert())
    with pytest.raises(HTTPException):
        hide(db, days=0)
    assert db.added == [] and db.commits == 0


def test_an_alert_the_caller_cannot_see_is_a_404_and_stores_nothing(monkeypatch):
    async def nowhere(db, own, alert_id):
        return None

    monkeypatch.setattr(scope, "find_alert_tenant", nowhere)
    db = FakeDB(None)
    with pytest.raises(HTTPException) as e:
        hide(db)
    assert e.value.status_code == 404 and db.added == []


def test_the_scopes_are_exactly_device_client_all():
    assert sup.SCOPES == ("device", "client", "all")
    with pytest.raises(ValueError):
        ep.SuppressionIn(alert_id=uuid.uuid4(), scope="everything")


# ---- hidden alerts stay out of the other views too -----------------------------------------------------------------------------------------------------


def test_vendor_detections_do_not_count_hidden_alerts():
    from app.services import vendor_detections as vd

    seen = []

    class DB:
        async def execute(self, statement):
            seen.append(str(statement.compile(compile_kwargs={"literal_binds": True})))
            return SimpleNamespace(all=lambda: [])

    asyncio.run(vd._scan(DB(), uuid.uuid4(), NOW, {}))
    assert "status != 'suppressed'" in seen[0]


def test_hidden_alerts_count_as_finished_everywhere_a_finished_status_list_is_used():
    from app.api.v1.endpoints.alerts import FINISHED_STATUSES
    from app.services.alert_queue import QUEUE_CLOSED_STATUSES
    from app.services.mssp_snapshots import FINISHED_ALERT

    for statuses in (FINISHED_STATUSES, QUEUE_CLOSED_STATUSES, FINISHED_ALERT):
        assert "suppressed" in statuses
