"""When Microsoft does not report who has registered a second factor (it needs Entra ID P1), the count must not call everyone unprotected while security defaults require it."""

from types import SimpleNamespace

from app.api.v1.endpoints.identity import counts_for_mfa
from app.services.client_review import readiness
from app.services.m365_review import from_mfa


def person(**over):
    base = {
        "enabled": True,
        "licensed": True,
        "user_type": "Member",
        "admin": False,
        "registered": False,
        "capable": False,
        "per_user": None,
        "ca_enforced": False,
        "security_defaults": False,
        "methods": None,
        "upn": "p@x.example",
    }
    base.update(over)
    return SimpleNamespace(**base)


def tenant_without_registration_data(n=25, **over):
    return [person(security_defaults=True, **over) for _ in range(n)]


def test_security_defaults_with_no_registration_report_count_everyone_as_covered():
    users = tenant_without_registration_data(25)
    c = counts_for_mfa(users)
    assert (c["people"], c["with_mfa"], c["without_mfa"], c["not_required"]) == (25, 25, 0, 0)
    assert c["registration_unknown"] == 1


def test_an_admin_under_security_defaults_with_no_report_is_not_called_unprotected():
    users = tenant_without_registration_data(5, admin=True)
    assert counts_for_mfa(users)["admins_without_mfa"] == 0


def test_nothing_required_and_no_report_is_still_no_protection():
    users = [person() for _ in range(10)]
    c = counts_for_mfa(users)
    assert (c["with_mfa"], c["without_mfa"]) == (0, 10)
    assert c["admins_without_mfa"] == 0


def test_per_user_and_conditional_access_count_as_required_when_nothing_is_reported():
    users = [person(per_user="enforced"), person(per_user="enabled"), person(ca_enforced=True), person()]
    c = counts_for_mfa(users)
    assert (c["with_mfa"], c["without_mfa"]) == (3, 1)


def test_when_registration_is_reported_it_still_decides_who_has_a_second_factor():
    users = [person(security_defaults=True, registered=True, methods="microsoftAuthenticator"), person(security_defaults=True), person(registered=True)]
    c = counts_for_mfa(users)
    assert (c["with_mfa"], c["not_required"], c["without_mfa"]) == (1, 1, 1)
    assert c["registration_unknown"] == 0


def test_one_person_with_a_registered_method_proves_the_report_exists_for_the_whole_tenant():
    users = [person(security_defaults=True, capable=True), person(security_defaults=True), person(security_defaults=True)]
    c = counts_for_mfa(users)
    assert (c["with_mfa"], c["without_mfa"]) == (1, 2)
    assert c["registration_unknown"] == 0


def test_the_review_says_it_is_what_is_required_not_proof_of_sign_up():
    mfa = counts_for_mfa(tenant_without_registration_data(25))
    items = {i.key: i for i in readiness_items(mfa)}
    assert items["mfa_everyone"].status == "met"
    assert "25 of 25" in items["mfa_everyone"].evidence
    assert "doesn't report" in items["mfa_everyone"].evidence or "does not report" in items["mfa_everyone"].evidence
    assert items["mfa_admins"].status == "met"


def readiness_items(mfa):
    from app.services.client_review import device_facts

    return readiness(device_facts([], 0, 0), mfa, None).items


def test_the_microsoft_365_answer_agrees():
    status, evidence = from_mfa(tenant_without_registration_data(25))["everyone"]
    assert status == "met"
    assert "25 of 25" in evidence
    admins_status, _ = from_mfa(tenant_without_registration_data(3, admin=True))["admins"]
    assert admins_status == "met"
