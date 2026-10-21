"""A person can link a ticket to an alert by hand; it is kept apart from CORE's matches, tidied, audited, and removable."""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import alert_vendor_actions as av
from fastapi import HTTPException

TENANT = uuid.uuid4()
ALERT_ID = uuid.uuid4()
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def test_the_number_is_tidied_the_link_must_be_https_and_who_added_it_is_recorded():
    t = av.clean_manual_ticket(
        av.ManualTicketRequest(id=" #4521 ", summary="  Ransomware canary ", url="https://halo.example.com/t?id=4521"), "u1", NOW
    )
    assert t == {
        "system": "halopsa",
        "id": "4521",
        "added_by": "u1",
        "added_at": NOW.isoformat(),
        "summary": "Ransomware canary",
        "url": "https://halo.example.com/t?id=4521",
    }
    plain = av.clean_manual_ticket(av.ManualTicketRequest(id="4522", url="javascript:alert(1)"), "u1", NOW)
    assert "url" not in plain and "summary" not in plain


@pytest.mark.parametrize("bad", ["", "#", "a b", "../x", "4521;DROP", "x" * 41])
def test_a_number_that_cannot_be_a_ticket_is_refused(bad):
    try:
        body = av.ManualTicketRequest(id=bad)
    except Exception:  # noqa: BLE001 - too long or empty is refused by the model itself
        return
    with pytest.raises(ValueError):
        av.clean_manual_ticket(body, "u1", NOW)


def test_manual_tickets_are_listed_after_core_s_and_flagged_and_a_duplicate_shows_once_as_core_reported_it():
    enrichment = {
        "tickets": [{"system": "halopsa", "id": "100", "summary": "From CORE", "status": "Open"}],
        "manual_tickets": [
            {"system": "halopsa", "id": "100", "summary": "typed"},
            {"system": "halopsa", "id": "200", "summary": "typed"},
            "junk",
            {"no": "id"},
        ],
    }
    tickets = av.linked_tickets(enrichment)
    assert [(t["id"], t.get("manual", False), t["summary"]) for t in tickets] == [("100", False, "From CORE"), ("200", True, "typed")]
    assert av.linked_tickets(None) == [] and av.linked_tickets({"manual_tickets": "x"}) == []


def _db(alert):
    db = MagicMock()
    results = [MagicMock(first=MagicMock(return_value=(1,))), MagicMock(scalar_one_or_none=MagicMock(return_value=alert)), MagicMock()]

    async def execute(stmt, *a, **k):
        db.statements.append(stmt)
        return results.pop(0) if results else MagicMock()

    db.statements = []
    db.execute = AsyncMock(side_effect=execute)
    db.commit = AsyncMock()
    return db


def _alert(enrichment=None):
    return SimpleNamespace(id=ALERT_ID, tenant_id=TENANT, enrichment_data=enrichment if enrichment is not None else {})


@pytest.fixture
def audit(monkeypatch):
    calls = []

    async def fake(**kw):
        calls.append(kw)

    monkeypatch.setattr(av, "emit_audit", fake)
    return calls


def _user():
    return SimpleNamespace(tenant_id=TENANT, user_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_adding_stores_the_ticket_beside_core_s_audits_it_and_returns_both(audit):
    alert = _alert({"tickets": [{"system": "halopsa", "id": "100"}]})
    db = _db(alert)
    out = await av.add_manual_ticket(ALERT_ID, av.ManualTicketRequest(id="#4521", summary="Manual"), MagicMock(), _user(), db)
    assert [(t["id"], t.get("manual", False)) for t in out.tickets] == [("100", False), ("4521", True)]
    values = db.statements[-1].compile().params
    assert any(
        isinstance(v, dict) and "manual_tickets" in v and v["tickets"] == [{"system": "halopsa", "id": "100"}] for v in values.values()
    ), "CORE's tickets are left exactly as they were"
    db.commit.assert_awaited()
    assert audit[0]["action"] == "alerts:ticket_linked" and audit[0]["changes"] == {"system": "halopsa", "ticket": "4521"}


@pytest.mark.asyncio
async def test_adding_the_same_number_again_updates_it_instead_of_listing_it_twice(audit):
    alert = _alert({"manual_tickets": [{"system": "halopsa", "id": "4521", "summary": "old"}]})
    out = await av.add_manual_ticket(ALERT_ID, av.ManualTicketRequest(id="4521", summary="new"), MagicMock(), _user(), _db(alert))
    assert [(t["id"], t["summary"]) for t in out.tickets] == [("4521", "new")]


@pytest.mark.asyncio
async def test_a_bad_number_is_a_422_and_a_full_list_is_a_409(audit):
    with pytest.raises(HTTPException) as e:
        await av.add_manual_ticket(ALERT_ID, av.ManualTicketRequest(id="a b"), MagicMock(), _user(), _db(_alert()))
    assert e.value.status_code == 422
    full = _alert({"manual_tickets": [{"system": "halopsa", "id": str(i)} for i in range(av.MAX_MANUAL_TICKETS)]})
    with pytest.raises(HTTPException) as e:
        await av.add_manual_ticket(ALERT_ID, av.ManualTicketRequest(id="new"), MagicMock(), _user(), _db(full))
    assert e.value.status_code == 409


@pytest.mark.asyncio
async def test_removing_deletes_a_hand_entered_ticket_or_one_halopsa_no_longer_has_and_a_core_ticket_halopsa_still_has_is_not_removable(audit):
    alert = _alert(
        {
            "tickets": [{"system": "halopsa", "id": "100", "summary": "Still in Halo"}, {"system": "halopsa", "id": "300"}],
            "manual_tickets": [{"system": "halopsa", "id": "200"}],
        }
    )
    out = await av.remove_manual_ticket(ALERT_ID, "200", MagicMock(), _user(), _db(alert))
    assert [t["id"] for t in out.tickets] == ["100", "300"]
    assert audit[0]["action"] == "alerts:ticket_unlinked"
    fresh = _alert({"tickets": [{"system": "halopsa", "id": "100", "summary": "Still in Halo"}, {"system": "halopsa", "id": "300"}]})
    gone = await av.remove_manual_ticket(ALERT_ID, "300", MagicMock(), _user(), _db(fresh))
    assert [t["id"] for t in gone.tickets] == ["100"], "a linked ticket with no summary (not found in HaloPSA) can be cleared"
    with pytest.raises(HTTPException) as e:
        await av.remove_manual_ticket(ALERT_ID, "100", MagicMock(), _user(), _db(alert))
    assert e.value.status_code == 404


def test_the_ticket_routes_need_alerts_write():
    from fastapi.routing import APIRoute
    from route_introspect import required_permissions

    routes = {(m, r.path): r for r in av.router.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(required_permissions(routes[("POST", "/alerts/{alert_id}/tickets")])) == {"alerts:write"}
    assert set(required_permissions(routes[("DELETE", "/alerts/{alert_id}/tickets/{ticket_id}")])) == {"alerts:write"}


# ---- every ticket gets a link to Halo, and an alert links back to the tool that raised it ----------------------------------------------------------------


def test_a_halo_ticket_without_a_link_gets_one_from_the_halo_address_and_one_with_a_link_keeps_it():
    base = "https://acme.halopsa.com"
    out = av.with_halo_urls(
        [{"system": "halopsa", "id": "4521"}, {"system": "halopsa", "id": "7", "url": "https://other.example/t/7"}, {"id": "a b/c"}], base
    )
    assert out[0]["url"] == "https://acme.halopsa.com/tickets?id=4521"
    assert out[1]["url"] == "https://other.example/t/7"
    assert out[2]["url"] == "https://acme.halopsa.com/tickets?id=a%20b%2Fc", "the number is encoded, never trusted into the address"
    assert av.with_halo_urls([{"system": "halopsa", "id": "1"}], None) == [
        {"system": "halopsa", "id": "1"}
    ], "no address known: nothing is invented"


@pytest.mark.asyncio
async def test_the_halo_address_is_read_from_the_organizations_settings_and_only_when_it_is_a_halo_address():
    async def get_with(settings):
        db = MagicMock()
        db.get = AsyncMock(return_value=SimpleNamespace(settings=settings))
        return await av.halo_base_of(db, TENANT)

    assert await get_with({"halopsa_base_url": "https://acme.halopsa.com"}) == "https://acme.halopsa.com"
    assert await get_with({"halopsa_base_url": "https://evil.example.com"}) is None
    assert await get_with({"halopsa_base_url": "http://acme.halopsa.com"}) is None
    assert await get_with({}) is None
    broken = MagicMock()
    broken.get = AsyncMock(side_effect=RuntimeError("db down"))
    assert await av.halo_base_of(broken, TENANT) is None, "a problem reading it never fails the page"


def test_the_halo_address_is_learned_from_the_urls_core_sends_and_nothing_else():
    from app.api.v1.endpoints.inbox_core_feed import LinkedTicket, TicketsItem, TicketsReport, halo_base_from

    def report(*urls):
        return TicketsReport(
            vendor="huntress", items=[TicketsItem(uid="huntress:1", tickets=[LinkedTicket(id=str(i), url=u) for i, u in enumerate(urls)])]
        )

    assert halo_base_from(report("https://Acme.HaloPSA.com/tickets?id=4521")) == "https://acme.halopsa.com"
    assert halo_base_from(report("https://evil.example.com/tickets?id=1", "https://acme.halopsa.com.evil.io/tickets?id=2")) is None
    assert halo_base_from(report()) is None


def test_an_alert_links_to_its_tool_only_with_a_plain_https_address():
    from app.api.v1.endpoints.alerts import _source_url_of

    assert (
        _source_url_of(SimpleNamespace(raw_event={"url": "https://app.petrasecurity.com/tenant/x/incidents/1"}))
        == "https://app.petrasecurity.com/tenant/x/incidents/1"
    )
    for bad in ("javascript:alert(1)", "http://insecure.example.com", "https://with space.example.com", 5, None):
        assert _source_url_of(SimpleNamespace(raw_event={"url": bad})) is None
    assert _source_url_of(SimpleNamespace(raw_event=None)) is None


def test_leading_zeros_are_dropped_from_a_numeric_ticket_number_everywhere():
    assert av.plain_ticket_number("0555871") == "555871"
    assert av.plain_ticket_number("000") == "0"
    assert av.plain_ticket_number("INC-007") == "INC-007", "only a plain number is changed"
    t = av.clean_manual_ticket(av.ManualTicketRequest(id="#0555871"), "u1", NOW)
    assert t["id"] == "555871"
    # a ticket already stored with the zero still links to the right place and does not appear twice beside CORE's own match
    shown = av.with_halo_urls([{"system": "halopsa", "id": "0555871"}], "https://acme.halopsa.com")
    assert shown[0]["url"] == "https://acme.halopsa.com/tickets?id=555871"
    both = av.linked_tickets(
        {"tickets": [{"system": "halopsa", "id": "555871", "summary": "S"}], "manual_tickets": [{"system": "halopsa", "id": "0555871"}]}
    )
    assert [t["id"] for t in both] == ["555871"]
