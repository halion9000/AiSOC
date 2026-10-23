"""The Identities page: one person per e-mail address per client, the tools that know them, their multi-factor state, and the alerts that name them."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import identities as ep
from app.services import identity_people as ip

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
A, B = uuid.uuid4(), uuid.uuid4()
NAMES = {A: "Acme", B: "Beta"}


def ms(tenant, upn, **over):
    base = {
        "tenant_id": tenant,
        "user_id": f"id-{upn}",
        "upn": upn,
        "display_name": None,
        "enabled": True,
        "user_type": "Member",
        "admin": False,
        "licensed": True,
        "registered": False,
        "capable": False,
        "per_user": None,
        "ca_enforced": False,
        "security_defaults": False,
        "methods": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


def src(tenant, vendor, email, **over):
    base = {"tenant_id": tenant, "vendor": vendor, "external_id": f"{vendor}-{email}", "email": email, "display_name": None, "enabled": None, "kind": "user", "details": {}, "refreshed_at": NOW}
    base.update(over)
    return SimpleNamespace(**base)


def alert(tenant, users, severity="high", days_ago=1, title="t"):
    return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant, affected_users=users, severity=severity, title=title, status="new", created_at=NOW - timedelta(days=days_ago), raw_event={})


# ---- e-mail addresses ---------------------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("good", ["a@b.co", " Amy.Smith@Acme.COM ", "x+tag@sub.example.org"])
def test_real_addresses_are_lower_cased(good):
    assert ip.normalize_email(good) == good.strip().lower()


@pytest.mark.parametrize("bad", ["", None, "amy", "amy@", "@acme.com", "a b@acme.com", "amy@acme", "DOMAIN\\amy", "a@b@c.com"])
def test_other_text_is_not_an_address(bad):
    assert ip.normalize_email(bad) is None


# ---- putting people together ------------------------------------------------------------------------------------------------------------------------


def test_one_person_in_several_tools_is_one_row_listing_the_tools():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com", display_name="Amy")], [src(A, "dropsuite", "AMY@acme.com"), src(A, "huntress-sat", "amy@acme.com", display_name="Amy S")], NOW)
    assert len(people) == 1
    p = people[0]
    assert (p.email, p.client_name, p.display_name) == ("amy@acme.com", "Acme", "Amy")
    assert p.vendors == ["cipp", "dropsuite", "huntress-sat"]
    assert [s.vendor for s in p.sources][0] == "cipp"


def test_the_same_address_in_two_clients_is_two_people():
    people = ip.build_people(NAMES, [ms(A, "sam@x.com"), ms(B, "sam@x.com")], [], NOW)
    assert len(people) == 2 and {p.client_name for p in people} == {"Acme", "Beta"}


def test_a_person_only_a_side_tool_knows_still_appears_and_non_addresses_are_left_out():
    people = ip.build_people(NAMES, [ms(A, "svc-account"), ms(A, "amy@acme.com")], [src(A, "datto-saas", "shared@acme.com", kind="shared"), src(A, "dropsuite", "not-an-address")], NOW)
    assert sorted(p.email for p in people) == ["amy@acme.com", "shared@acme.com"]
    assert next(p for p in people if p.email == "shared@acme.com").kind == "shared"


def test_a_tool_row_not_refreshed_for_days_is_no_longer_shown():
    old = src(A, "dropsuite", "gone@acme.com", refreshed_at=NOW - timedelta(days=ip.STALE_DAYS, minutes=1))
    fresh = src(A, "dropsuite", "here@acme.com", refreshed_at=NOW - timedelta(days=1))
    assert [p.email for p in ip.build_people(NAMES, [], [old, fresh], NOW)] == ["here@acme.com"]


def test_a_guest_is_a_guest_and_a_disabled_account_is_disabled():
    p = ip.build_people(NAMES, [ms(A, "g@ext.com", user_type="Guest", enabled=False, admin=True)], [], NOW)[0]
    assert (p.kind, p.enabled, p.admin) == ("guest", False, True)


# ---- multi-factor ------------------------------------------------------------------------------------------------------------------------------------


def test_multifactor_follows_the_same_rules_as_the_multifactor_page():
    people = ip.build_people(
        NAMES,
        [
            ms(A, "covered@a.com", registered=True, ca_enforced=True, methods="authenticator"),
            ms(A, "signedup@a.com", registered=True),
            ms(A, "none@a.com"),
        ],
        [],
        NOW,
    )
    by = {p.email: p.mfa for p in people}
    assert by == {"covered@a.com": "covered", "signedup@a.com": "registered_not_required", "none@a.com": "none"}


def test_when_microsoft_reports_no_registrations_being_required_counts_as_covered():
    people = ip.build_people(NAMES, [ms(A, "x@a.com", security_defaults=True), ms(A, "y@a.com")], [], NOW)
    by = {p.email: p.mfa for p in people}
    assert by == {"x@a.com": "covered", "y@a.com": "none"}


def test_a_person_only_a_side_tool_knows_has_unknown_multifactor():
    assert ip.build_people(NAMES, [], [src(A, "dropsuite", "a@a.com")], NOW)[0].mfa == "unknown"


# ---- alerts --------------------------------------------------------------------------------------------------------------------------------------------


def test_open_alerts_are_tied_to_the_people_they_name_in_the_same_client_only():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com"), ms(B, "amy@acme.com"), ms(A, "bob@acme.com")], [], NOW)
    by_key = ip.attach_alerts(people, [alert(A, ["Amy@Acme.com", "someone-else"], "low"), alert(A, ["amy@acme.com"], "critical", days_ago=0), alert(B, ["bob@acme.com"])])
    amy_a = next(p for p in people if p.email == "amy@acme.com" and p.tenant_id == A)
    amy_b = next(p for p in people if p.email == "amy@acme.com" and p.tenant_id == B)
    bob_a = next(p for p in people if p.email == "bob@acme.com")
    assert (amy_a.open_alerts, amy_a.top_severity) == (2, "critical")
    assert (amy_b.open_alerts, amy_b.top_severity) == (0, None)
    assert bob_a.open_alerts == 0, "bob's alert is in Beta, where Bob has no row"
    assert [a.severity for a in by_key[amy_a.key]] == ["critical", "low"], "newest first"


def test_an_alert_naming_a_person_twice_counts_once_and_unknown_people_are_ignored():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com")], [], NOW)
    ip.attach_alerts(people, [alert(A, ["amy@acme.com", "AMY@acme.com", "ghost@acme.com", None, 5])])
    assert people[0].open_alerts == 1


# ---- filtering and sorting ------------------------------------------------------------------------------------------------------------------------


def sample():
    people = ip.build_people(
        NAMES,
        [ms(A, "amy@acme.com", display_name="Amy", admin=True, registered=True, ca_enforced=True), ms(A, "bob@acme.com", display_name="Bob"), ms(B, "cy@beta.com", enabled=False)],
        [src(A, "dropsuite", "amy@acme.com"), src(A, "dropsuite", "dan@acme.com")],
        NOW,
    )
    ip.attach_alerts(people, [alert(A, ["bob@acme.com"], "high"), alert(A, ["bob@acme.com"], "low")])
    return people


def emails(rows):
    return [p.email for p in rows]


def test_filters_each_narrow_the_list_and_combine():
    people = sample()
    assert emails(ip.filter_people(people, search="AMY")) == ["amy@acme.com"]
    assert emails(ip.filter_people(people, search="beta")) == ["cy@beta.com"]
    assert sorted(emails(ip.filter_people(people, source="dropsuite"))) == ["amy@acme.com", "dan@acme.com"]
    assert emails(ip.filter_people(people, only_in="dropsuite")) == ["dan@acme.com"]
    assert emails(ip.filter_people(people, has_alerts=True)) == ["bob@acme.com"]
    assert emails(ip.filter_people(people, mfa="covered")) == ["amy@acme.com"]
    assert emails(ip.filter_people(people, admin=True)) == ["amy@acme.com"]
    assert emails(ip.filter_people(people, disabled=True)) == ["cy@beta.com"]
    assert emails(ip.filter_people(people, kind="guest")) == []
    assert emails(ip.filter_people(people, source="dropsuite", mfa="covered")) == ["amy@acme.com"]


def test_sorting_puts_the_most_alerts_first_by_default_and_supports_the_other_orders():
    people = sample()
    assert emails(ip.sort_people(people))[0] == "bob@acme.com"
    assert emails(ip.sort_people(people, "email")) == sorted(emails(people))
    assert emails(ip.sort_people(people, "client"))[-1] == "cy@beta.com"
    assert emails(ip.sort_people(people, "tools"))[0] == "amy@acme.com", "two tools beat one"
    assert emails(ip.sort_people(people, "name"))[0] == "amy@acme.com"


def test_the_summary_counts_everyone_whatever_the_filters():
    s = ep.summarize(sample())
    assert (s.total, s.with_alerts, s.admins, s.disabled) == (4, 1, 1, 1)
    assert s.without_mfa == 1, "Bob has none; Cy has none but is disabled; Dan is unknown"
    assert s.in_one_tool == 3
    assert s.tools == {"cipp": 3, "dropsuite": 2}


# ---- the report CORE sends -----------------------------------------------------------------------------------------------------------------------


def test_the_report_refuses_bad_vendors_kinds_and_oversized_lists():
    from pydantic import ValidationError

    ok = {"external_id": "1", "email": "a@b.co"}
    assert ep.IdentitiesReport(vendor="datto-saas", items=[ok]).items[0].kind == "user"
    for bad in ({"vendor": "Bad Vendor", "items": []}, {"vendor": "x", "items": [{**ok, "kind": "robot"}]}, {"vendor": "x", "items": [ok] * 1001}):
        with pytest.raises(ValidationError):
            ep.IdentitiesReport(**bad)


class FakeDB:
    def __init__(self):
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace()


def test_apply_stores_only_real_addresses_under_the_mapped_client_and_counts_the_rest(monkeypatch):
    import contextlib

    from app.api.v1.endpoints import signins

    seen = {}

    async def fake_targets(db, owner, view):
        seen["vendor"] = view.vendor
        return {A: view.items[:2]}, 1, 0, [SimpleNamespace(vendor_client_id="999", name="Gone Co", devices=1)]

    monkeypatch.setattr(signins, "targets_by_tenant", fake_targets)
    monkeypatch.setattr(ep, "acting_as_tenant", lambda db, tid: contextlib.nullcontext())
    db = FakeDB()
    report = ep.IdentitiesReport(
        vendor="dropsuite",
        items=[ep.IdentityIn(vendor_client_id="1", external_id="e1", email="Amy@Acme.com"), ep.IdentityIn(vendor_client_id="1", external_id="e2", email="not-an-address"), ep.IdentityIn(vendor_client_id="999", external_id="e3", email="z@z.com")],
    )
    out = asyncio.run(ep.apply_identities(db, uuid.uuid4(), report))
    assert seen["vendor"] == "dropsuite"
    assert (out.accepted, out.unmapped) == (1, 1)
    assert out.unmapped_clients[0].name == "Gone Co"
    assert len(db.statements) == 1
