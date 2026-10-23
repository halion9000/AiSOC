"""What AiSOC suggests adding to vCIO Toolbox: which checks become suggestions, and how the words and priority come out."""

from datetime import UTC, datetime

from app.services.client_review import Readiness, ReadinessItem
from app.services.vcio_proposals import TITLES, drafts_from_readiness

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def readiness(*items: tuple[str, str, str]) -> Readiness:
    built = [ReadinessItem(key=k, question=f"Question for {k}?", status=s, evidence=e) for k, s, e in items]
    return Readiness(
        met=sum(i.status == "met" for i in built),
        partly=sum(i.status == "partly" for i in built),
        not_met=sum(i.status == "not_met" for i in built),
        unknown=sum(i.status == "unknown" for i in built),
        items=built,
    )


def test_only_checks_that_are_failing_or_partly_met_become_suggestions():
    got = drafts_from_readiness(
        readiness(
            ("mfa_admins", "not_met", "2 administrator(s) have no Multi-Factor."),
            ("edr", "partly", "85 of 100 machines report Huntress."),
            ("dns", "met", "All good."),
            ("patching", "unknown", "ThreatMate does not scan this client's machines."),
        ),
        NOW,
    )
    assert [d.key for d in got] == ["mfa_admins", "edr"]


def test_a_failing_check_is_high_priority_and_a_partly_met_one_medium():
    got = {d.key: d for d in drafts_from_readiness(readiness(("mfa_admins", "not_met", "x"), ("edr", "partly", "y")), NOW)}
    assert (got["mfa_admins"].priority, got["edr"].priority) == ("High", "Medium")


def test_the_description_says_the_question_the_evidence_and_where_it_came_from():
    (d,) = drafts_from_readiness(readiness(("mfa_admins", "not_met", "2 administrator(s) have no Multi-Factor.")), NOW)
    assert d.name == TITLES["mfa_admins"]
    assert d.evidence == "2 administrator(s) have no Multi-Factor."
    assert (
        d.description
        == "Question for mfa_admins? 2 administrator(s) have no Multi-Factor. Suggested by AiSOC from the connected tools on 2026-10-22."
    )


def test_a_check_with_no_recommendation_to_make_is_never_suggested_even_when_it_fails():
    """E-mail filtering and the like are always 'unknown', and an unknown key has no title: nothing is invented."""
    assert drafts_from_readiness(readiness(("email_filtering", "not_met", "z"), ("something_new", "not_met", "z")), NOW) == []


def test_every_title_is_plain_and_short_enough_for_vcio_toolbox():
    for key, title in TITLES.items():
        assert 10 < len(title) <= 120, key
        assert title == title.strip() and not title.endswith("."), key
