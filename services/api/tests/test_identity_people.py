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


# ---- people the MDR tools raised alerts about -------------------------------------------------------------------------------------------------------


def tool_alert(tenant, users, source, **over):
    a = alert(tenant, users, **over)
    a.raw_event = {"source": source}
    a.connector_type = None
    return a


def src_of(raw, connector=None):
    from app.services.alert_suppression import source_of

    return source_of(raw, connector)


def test_a_person_an_mdr_tool_raised_an_alert_about_is_known_to_that_tool():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com")], [], NOW)
    out = ip.add_alert_sources(people, [tool_alert(A, ["Amy@Acme.com"], "petra"), tool_alert(A, ["amy@acme.com"], "fieldeffect")], NAMES, src_of)
    amy = out[0]
    assert amy.vendors == ["cipp", "fieldeffect", "petra"]
    assert [s.details.get("via") for s in amy.sources if s.vendor == "petra"] == ["an alert it raised"]


def test_a_person_only_an_alert_names_still_appears_under_that_client_with_that_tool():
    out = ip.add_alert_sources([], [tool_alert(A, ["new.person@acme.com", "not-an-address"], "blumira")], NAMES, src_of)
    assert [(p.email, p.client_name, p.vendors, p.mfa) for p in out] == [("new.person@acme.com", "Acme", ["blumira"], "unknown")]


def test_a_tool_is_listed_once_per_person_and_other_tools_alerts_do_not_make_people():
    people = ip.build_people(NAMES, [], [], NOW)
    out = ip.add_alert_sources(people, [tool_alert(A, ["x@acme.com"], "huntress"), tool_alert(A, ["x@acme.com"], "huntress"), tool_alert(A, ["pc-user@acme.com"], "ninjaone")], NAMES, src_of)
    assert [(p.email, p.vendors) for p in out] == [("x@acme.com", ["huntress"])]
    assert len(out[0].sources) == 1


def test_a_person_the_tool_lists_itself_is_not_given_a_second_row_for_the_same_tool():
    people = ip.build_people(NAMES, [], [src(A, "huntress", "amy@acme.com")], NOW)
    out = ip.add_alert_sources(people, [tool_alert(A, ["amy@acme.com"], "huntress")], NAMES, src_of)
    assert len(out) == 1 and [s.vendor for s in out[0].sources] == ["huntress"]
    assert out[0].sources[0].external_id != "alert"


# ---- alerts broken up by the tool that raised them ----------------------------------------------------------------------------------------------------


def test_each_persons_open_alerts_are_counted_by_the_tool_that_raised_them_most_first():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com"), ms(A, "bob@acme.com")], [], NOW)
    attach = ip.attach_alerts(
        people,
        [
            tool_alert(A, ["amy@acme.com"], "petra"),
            tool_alert(A, ["amy@acme.com"], "huntress"),
            tool_alert(A, ["amy@acme.com"], "huntress"),
            alert(A, ["amy@acme.com"]),
            tool_alert(A, ["bob@acme.com"], "blumira"),
        ],
        src_of,
    )
    amy = next(p for p in people if p.email == "amy@acme.com")
    bob = next(p for p in people if p.email == "bob@acme.com")
    assert list(amy.alerts_by_source.items()) == [("huntress", 2), ("other", 1), ("petra", 1)], "an alert naming no tool is 'other'; ties go by name"
    assert sum(amy.alerts_by_source.values()) == amy.open_alerts == 4
    assert bob.alerts_by_source == {"blumira": 1}
    assert len(attach) == 2


def test_an_alert_that_names_no_tool_counts_as_other_and_no_source_function_puts_everything_in_other():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com")], [], NOW)
    a = alert(A, ["amy@acme.com"])
    a.raw_event = {}
    ip.attach_alerts(people, [a], src_of)
    assert people[0].alerts_by_source == {"other": 1}
    again = ip.build_people(NAMES, [ms(A, "amy@acme.com")], [], NOW)
    ip.attach_alerts(again, [tool_alert(A, ["amy@acme.com"], "petra")])
    assert again[0].alerts_by_source == {"other": 1}


def test_people_can_be_filtered_to_those_with_an_open_alert_from_one_tool():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com"), ms(A, "bob@acme.com"), ms(A, "cy@acme.com")], [], NOW)
    ip.attach_alerts(people, [tool_alert(A, ["amy@acme.com"], "petra"), tool_alert(A, ["bob@acme.com"], "huntress")], src_of)
    assert [p.email for p in ip.filter_people(people, alert_source="petra")] == ["amy@acme.com"]
    assert [p.email for p in ip.filter_people(people, alert_source="blumira")] == []
    assert len(ip.filter_people(people)) == 3


def test_the_summary_says_how_many_people_have_an_alert_from_each_tool():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com"), ms(A, "bob@acme.com")], [], NOW)
    ip.attach_alerts(people, [tool_alert(A, ["amy@acme.com"], "petra"), tool_alert(A, ["amy@acme.com"], "petra"), tool_alert(A, ["bob@acme.com"], "petra"), tool_alert(A, ["bob@acme.com"], "huntress")], src_of)
    assert ep.summarize(people).alert_sources == {"huntress": 1, "petra": 2}


# ---- backup state from Dropsuite and Datto SaaS Protection -----------------------------------------------------------------------------------------


def backups_of(*sources):
    return ip.build_people(NAMES, [], list(sources), NOW)[0].backups


def drop(email, **details):
    return src(A, "dropsuite", email, enabled=details.pop("enabled", True), details=details)


def datto(email, state):
    return src(A, "datto-saas", email, details={"seat_state": state})


def test_dropsuite_says_ok_when_the_mailbox_backed_up_in_the_last_two_days():
    b = backups_of(drop("a@a.com", last_backup=(NOW - timedelta(hours=5)).isoformat(), errors=0))[0]
    assert (b.vendor, b.status) == ("dropsuite", "ok")


def test_dropsuite_says_stale_for_an_old_or_missing_backup_and_how_long_ago():
    old = backups_of(drop("a@a.com", last_backup=(NOW - timedelta(days=9)).isoformat(), errors=0))[0]
    assert old.status == "stale" and "9 days ago" in old.detail
    assert backups_of(drop("a@a.com", last_backup=None))[0].status == "stale"
    assert backups_of(drop("a@a.com", last_backup="not a date"))[0].status == "stale"
    just_over = backups_of(drop("a@a.com", last_backup=(NOW - timedelta(hours=49)).isoformat()))[0]
    assert just_over.status == "stale"


def test_dropsuite_errors_and_deactivation_beat_a_recent_backup():
    recent = (NOW - timedelta(hours=1)).isoformat()
    err = backups_of(drop("a@a.com", last_backup=recent, errors=2))[0]
    assert err.status == "issue" and "2 errors" in err.detail
    assert backups_of(drop("a@a.com", last_backup=recent, errors=1))[0].detail.endswith("1 error on this mailbox")
    assert backups_of(drop("a@a.com", last_backup=recent, enabled=False))[0].status == "paused"


def test_datto_saas_says_whether_the_seat_is_protected_not_when_it_ran():
    assert backups_of(datto("a@a.com", "Active"))[0].status == "ok"
    assert backups_of(datto("a@a.com", "Paused"))[0].status == "paused"
    assert backups_of(datto("a@a.com", "Archived"))[0].status == "unprotected"
    assert backups_of(datto("a@a.com", "Unprotected"))[0].status == "unprotected"
    assert backups_of(datto("a@a.com", ""))[0].status == "unprotected"


def test_a_person_in_both_backup_tools_shows_both_and_other_tools_add_nothing():
    people = ip.build_people(NAMES, [ms(A, "amy@acme.com")], [drop("amy@acme.com", last_backup=NOW.isoformat(), errors=0), datto("amy@acme.com", "Active"), src(A, "huntress-sat", "amy@acme.com")], NOW)
    assert [b.vendor for b in people[0].backups] == ["datto-saas", "dropsuite"]
    assert ip.build_people(NAMES, [ms(A, "x@a.com")], [], NOW)[0].backups == []


def test_people_can_be_filtered_by_how_their_backups_are():
    fresh = NOW.isoformat()
    people = ip.build_people(
        NAMES,
        [ms(A, "good@a.com"), ms(A, "bad@a.com"), ms(A, "mixed@a.com"), ms(A, "none@a.com")],
        [
            drop("good@a.com", last_backup=fresh, errors=0),
            drop("bad@a.com", last_backup=(NOW - timedelta(days=30)).isoformat()),
            drop("mixed@a.com", last_backup=fresh, errors=0),
            datto("mixed@a.com", "Paused"),
        ],
        NOW,
    )
    emails = lambda rows: sorted(p.email for p in rows)  # noqa: E731
    assert emails(ip.filter_people(people, backup="ok")) == ["good@a.com"]
    assert emails(ip.filter_people(people, backup="problem")) == ["bad@a.com", "mixed@a.com"]
    assert emails(ip.filter_people(people, backup="none")) == ["none@a.com"]
    assert ep.summarize(people).backup_problems == 2


# ---- breach exposure (ThreatMate) --------------------------------------------------------------------------------------------------------------------------


def tm(email, **details):
    return src(A, "threatmate", email, details=details)


def test_exposure_is_attached_to_a_known_person_and_is_not_a_tool_that_knows_them():
    people = ip.build_people(
        NAMES,
        [ms(A, "amy@a.com"), ms(A, "bo@a.com")],
        [tm("amy@a.com", exposed_in=2, latest_breach="2025-02-10", password_exposed=True, stealer_log=False, malware=False, breaches=[{"name": "Forum", "date": "2023-05-01", "data": ["Passwords"]}]), tm("bo@a.com", exposed_in=1)],
        NOW,
    )
    amy = next(p for p in people if p.email == "amy@a.com")
    assert (amy.exposure.count, amy.exposure.latest, amy.exposure.password) == (2, "2025-02-10", True)
    assert amy.exposure.breaches[0]["name"] == "Forum"
    assert amy.vendors == ["cipp"], "the exposure tool is not listed as a tool that knows the person"
    assert next(p for p in people if p.email == "bo@a.com").exposure.count == 1


def test_an_exposed_address_no_other_tool_knows_is_not_made_into_a_person():
    people = ip.build_people(NAMES, [ms(A, "amy@a.com")], [tm("gone@a.com", exposed_in=5)], NOW)
    assert [p.email for p in people] == ["amy@a.com"]


def test_a_person_with_no_exposure_report_has_none_and_a_zero_count_is_none():
    people = ip.build_people(NAMES, [ms(A, "amy@a.com"), ms(A, "bo@a.com")], [tm("bo@a.com", exposed_in=0)], NOW)
    assert [p.exposure for p in people] == [None, None]


def test_exposed_people_can_be_filtered_sorted_and_counted():
    people = ip.build_people(
        NAMES,
        [ms(A, "mild@a.com"), ms(A, "bad@a.com"), ms(A, "clean@a.com"), ms(A, "many@a.com")],
        [tm("mild@a.com", exposed_in=1), tm("bad@a.com", exposed_in=2, stealer_log=True), tm("many@a.com", exposed_in=9)],
        NOW,
    )
    emails = lambda rows: sorted(p.email for p in rows)  # noqa: E731
    assert emails(ip.filter_people(people, exposed="any")) == ["bad@a.com", "many@a.com", "mild@a.com"]
    assert emails(ip.filter_people(people, exposed="serious")) == ["bad@a.com"]
    assert [p.email for p in ip.sort_people(people, "exposure")][:3] == ["many@a.com", "bad@a.com", "mild@a.com"]
    s = ep.summarize(people)
    assert (s.exposed, s.exposed_serious) == (3, 1)
    assert ep._out(next(p for p in people if p.email == "bad@a.com")).exposure.stealer_log is True
    assert ep._out(next(p for p in people if p.email == "clean@a.com")).exposure is None


def test_a_stale_exposure_row_is_not_shown():
    old = src(A, "threatmate", "amy@a.com", details={"exposed_in": 3}, refreshed_at=NOW - timedelta(days=10))
    people = ip.build_people(NAMES, [ms(A, "amy@a.com")], [old], NOW)
    assert people[0].exposure is None
