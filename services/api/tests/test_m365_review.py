from types import SimpleNamespace as NS

import pytest
from app.services import m365_review as m


def _user(**over):
    base = dict(
        admin=False,
        registered=True,
        ca_enforced=True,
        security_defaults=False,
        per_user="disabled",
        user_type="Member",
        enabled=True,
        capable=True,
    )
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
