from types import SimpleNamespace as NS

import pytest
from app.services import m365_review as m


def _user(**over):
    base = {
        "admin": False,
        "registered": True,
        "ca_enforced": True,
        "security_defaults": False,
        "per_user": "disabled",
        "user_type": "Member",
        "enabled": True,
        "capable": True,
    }
    base.update(over)
    return NS(**base)


def test_every_mapped_question_exists_exactly_once_in_the_template():
    for prefix in [*m.CHECK_QUESTIONS.values(), *m.MFA_QUESTIONS.values()]:
        assert m.question_for(prefix)
    assert len(m.QUESTIONS) == 99 and len({q for _, q in m.QUESTIONS}) == 99


def test_question_for_refuses_something_that_matches_none_or_several():
    with pytest.raises(ValueError):
        m.question_for("Ensure nothing like this")
    with pytest.raises(ValueError):
        m.question_for("Ensure Safe")  # several questions start this way


def test_a_reported_check_answers_its_template_question_and_everything_else_needs_a_person():
    out = m.m365_answers([{"key": "safe_attachments", "status": "met", "evidence": "2 policies"}], [])
    got = {a.question: a for a in out}
    a = got["Ensure Safe Attachments policy is enabled"]
    assert (a.status, a.evidence, a.group) == ("met", "2 policies", "M365 Defender")
    assert sum(1 for x in out if x.status == "needs_person") == 98
    assert [x.question for x in out] == [q for _, q in m.QUESTIONS], "template order"


def test_an_unknown_key_or_a_status_that_is_not_one_of_the_three_is_ignored():
    out = m.m365_answers([{"key": "made_up", "status": "met"}, {"key": "spf", "status": "great"}, {"key": "spf"}], [])
    assert all(a.status == "needs_person" for a in out)


def test_the_multifactor_list_answers_admin_everyone_per_user_and_capable_questions():
    users = [
        _user(admin=True),
        _user(admin=True, registered=False, ca_enforced=False),
        _user(),
        _user(per_user="enforced", ca_enforced=False),
        _user(capable=False),
    ]
    a = {x.question: x for x in m.m365_answers([], users)}
    assert a["Ensure multifactor authentication is enabled for all users in administrative roles"].status == "not_met"
    assert "1 of 2 administrators" in a["Ensure multifactor authentication is enabled for all users in administrative roles"].evidence
    assert a["Ensure 'Per-user MFA' is disabled"].status == "not_met"
    assert a["Ensure all member users are 'MFA capable'"].status == "not_met"
    assert a["Ensure multifactor authentication is enabled for all users"].status in {"partly", "not_met"}
    clean = {x.question: x for x in m.m365_answers([], [_user(admin=True), _user()])}
    assert [
        clean[q].status
        for q in (
            "Ensure multifactor authentication is enabled for all users in administrative roles",
            "Ensure 'Per-user MFA' is disabled",
            "Ensure all member users are 'MFA capable'",
        )
    ] == ["met", "met", "met"]


# Every check key CORE can emit (hud/src/aisoc-m365-reads.test.ts pins the same list: change both together).
CORE_CHECK_KEYS = [
    "ga_count",
    "safe_attachments",
    "anti_phishing",
    "safe_links",
    "common_attachments",
    "conn_ip_allow",
    "conn_safe_list",
    "spf",
    "dkim",
    "dmarc",
    "user_risk_ca",
    "signin_risk_ca",
    "managed_device_ca",
    "admin_signin_frequency",
    "legacy_auth_ca",
    "device_code_ca",
    "user_consent",
    "create_tenants",
    "create_security_groups",
    "guest_access",
    "admin_consent_workflow",
    "password_expiry",
    "sharepoint_modern_auth",
    "sharepoint_external_sharing",
    "shared_mailbox_signin",
    "audit_disabled",
    "customer_lockbox",
    "mailtips",
    "exo_modern_auth",
    "smtp_auth_disabled",
    "owa_storage_providers",
    "external_sender_tag",
    "malware_admin_notify",
    "authenticator_fatigue",
    "weak_auth_methods",
    "system_preferred_mfa",
    "banned_passwords",
    "onprem_password_protection",
    "password_hash_sync",
    "device_quota",
    "laps",
    "ga_local_admin",
    "local_admin_join",
    "guest_dynamic_group",
    "cloud_only_admins",
    "inbound_allowed_domains",
    "outbound_spam_notify",
    "mail_forwarding_blocked",
    "audit_bypass",
    "safe_attachments_collab",
    "outlook_addins",
    "transport_whitelist",
    "unified_audit_log",
    "zap_teams",
    "calendar_external_sharing",
    "bookings_restricted",
    "admin_license_footprint",
]


def test_every_check_key_core_can_emit_has_a_template_question_and_nothing_else_is_mapped():
    assert sorted(m.CHECK_QUESTIONS) == sorted(CORE_CHECK_KEYS)
    assert len(set(CORE_CHECK_KEYS)) == len(CORE_CHECK_KEYS) == 57
    # each key answers a different question
    questions = [m.question_for(q) for q in m.CHECK_QUESTIONS.values()]
    assert len(set(questions)) == len(questions)
    # and the multi-factor answers do not collide with a check's question
    assert not set(questions) & {m.question_for(q) for q in m.MFA_QUESTIONS.values()}


def test_the_ingest_refuses_bad_keys_bad_statuses_and_oversized_reports():
    from app.api.v1.endpoints.client_review import M365CheckIn, M365ChecksReport
    from pydantic import ValidationError

    ok = {"key": "spf", "status": "met", "evidence": "x"}
    assert M365CheckIn(**ok).key == "spf"
    for bad in (
        {**ok, "key": "Has Space"},
        {**ok, "key": ""},
        {**ok, "key": "x" * 61},
        {**ok, "status": "great"},
        {**ok, "status": "needs_person"},  # that one is A.C.O.R.N's own word, never CORE's
        {**ok, "evidence": "e" * 301},
    ):
        with pytest.raises(ValidationError):
            M365CheckIn(**bad)
    with pytest.raises(ValidationError):
        M365ChecksReport(vendor="Bad Vendor", vendor_client_id="c", checks=[])
    with pytest.raises(ValidationError):
        M365ChecksReport(vendor="cipp", vendor_client_id="", checks=[])
    with pytest.raises(ValidationError):
        M365ChecksReport(vendor="cipp", vendor_client_id="c", checks=[ok] * 81)


def test_evidence_is_cut_at_300_characters_and_multifactor_answers_stand_alone():
    long = "e" * 500
    out = {a.question: a for a in m.m365_answers([{"key": "spf", "status": "met", "evidence": long}], [])}
    assert len(out[m.question_for(m.CHECK_QUESTIONS["spf"])].evidence) == 300
    only_mfa = m.m365_answers([], [_user(admin=True), _user()])
    answered = [a.question for a in only_mfa if a.status != "needs_person"]
    assert sorted(answered) == sorted(m.question_for(q) for q in m.MFA_QUESTIONS.values())
    assert [a.question for a in only_mfa] == [q for _, q in m.QUESTIONS]


def test_every_check_key_is_listed_in_the_reference_document():
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[3] / "docs" / "M365_CHECKS.md").read_text(encoding="utf-8")
    missing = [k for k in m.CHECK_QUESTIONS if f"`{k}`" not in doc]
    assert not missing, f"docs/M365_CHECKS.md does not mention: {missing}"
