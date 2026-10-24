"""Typing answers and notes into the client review: what is accepted, how a typed answer lies over the worked-out one, and that clearing it goes back."""

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import client_review as cr
from app.services import review_overrides as ro
from app.services.client_review import ReadinessItem
from app.services.m365_review import M365Answer
from app.services.tech_stack import TechAnswer
from fastapi import HTTPException

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def row(section, key, status=None, answer=None, note=None):
    return SimpleNamespace(section=section, key=key, status=status, answer=answer, note=note, updated_at=NOW)


# ---- what is accepted ---------------------------------------------------------------------------------------------------------------------------------


def test_valid_statuses_answers_and_notes_are_trimmed_and_kept():
    assert ro.clean_answer("readiness", "backups", " met ", None, "  checked the console  ") == ("met", None, "checked the console")
    assert ro.clean_answer("tech", "firewall", "seen", " Fortinet ", None) == ("seen", "Fortinet", None)
    assert ro.clean_answer("m365", "Ensure X", "needs_person", None, None) == ("needs_person", None, None)


def test_nothing_in_any_field_means_clear():
    assert ro.clean_answer("readiness", "backups", None, None, None) == (None, None, None)
    assert ro.clean_answer("readiness", "backups", "  ", "", "   ") == (None, None, None)


@pytest.mark.parametrize(
    "args",
    [
        ("nonsense", "k", None, None, None),
        ("readiness", "k", "seen", None, None),
        ("tech", "k", "met", None, None),
        ("m365", "k", "unknown", None, None),
        ("readiness", "k", "met", "typed answer", None),
        ("m365", "k", None, "typed answer", None),
        ("tech", "", "seen", None, None),
        ("tech", "k" * 401, "seen", None, None),
        ("tech", "k", "seen", "a" * 301, None),
        ("readiness", "k", None, None, "n" * (ro.MAX_NOTE + 1)),
    ],
)
def test_anything_else_is_refused(args):
    with pytest.raises(HTTPException) as e:
        ro.clean_answer(*args)
    assert e.value.status_code == 422


# ---- the readiness checklist --------------------------------------------------------------------------------------------------------------------------


def item(key, status="unknown", evidence="AiSOC does not collect this yet"):
    return ReadinessItem(key=key, question=f"Q {key}", status=status, evidence=evidence)


def test_a_typed_status_replaces_the_worked_out_one_and_remembers_it():
    items = ro.merge_readiness([item("backups"), item("edr", "not_met", "4 of 6")], [row("readiness", "backups", "met", note="Veeam to the cloud, tested in September")])
    backups = items[0]
    assert (backups.status, backups.manual, backups.auto_status) == ("met", True, "unknown")
    assert backups.note == "Veeam to the cloud, tested in September"
    assert backups.evidence == "AiSOC does not collect this yet", "what A.C.O.R.N worked out is kept"
    assert (items[1].status, items[1].manual, items[1].note) == ("not_met", False, None)


def test_a_note_alone_changes_no_status():
    items = ro.merge_readiness([item("edr", "partly")], [row("readiness", "edr", None, note="two machines are being replaced")])
    assert (items[0].status, items[0].manual, items[0].auto_status) == ("partly", False, None)
    assert items[0].note == "two machines are being replaced"


def test_typing_the_same_status_marks_it_confirmed_without_a_difference():
    items = ro.merge_readiness([item("edr", "met")], [row("readiness", "edr", "met")])
    assert (items[0].status, items[0].manual, items[0].auto_status) == ("met", True, None)


def test_the_counts_follow_the_typed_statuses():
    items = ro.merge_readiness([item("a", "unknown"), item("b", "met"), item("c", "not_met")], [row("readiness", "a", "met"), row("readiness", "c", "partly")])
    assert ro.readiness_counts(items) == {"met": 2, "partly": 1, "not_met": 0, "unknown": 0}


# ---- the technology questions ------------------------------------------------------------------------------------------------------------------------


def tech(key, status="unknown", suggested=None):
    return TechAnswer(key=key, group="G", question=f"Q {key}", status=status, suggested=suggested, evidence="e")


def test_a_typed_answer_fills_a_question_a_person_had_to_answer():
    a = ro.merge_tech([tech("firewall")], [row("tech", "firewall", None, "Fortinet 60F")])[0]
    assert (a.status, a.suggested, a.manual, a.auto_status, a.auto_suggested) == ("seen", "Fortinet 60F", True, "unknown", None)


def test_a_typed_status_alone_sets_a_sensible_answer():
    assert ro.merge_tech([tech("x", "seen", "Huntress")], [row("tech", "x", "not_seen")])[0].suggested == "None seen"
    assert ro.merge_tech([tech("x", "seen", "Huntress")], [row("tech", "x", "unknown")])[0].suggested is None
    kept = ro.merge_tech([tech("x", "seen", "Huntress")], [row("tech", "x", "seen")])[0]
    assert (kept.suggested, kept.manual) == ("Huntress", True)
    assert ro.merge_tech([tech("x")], [row("tech", "x", "seen")])[0].suggested == "Yes"


def test_a_typed_answer_and_status_together_and_the_worked_out_answer_is_kept():
    a = ro.merge_tech([tech("x", "seen", "Huntress (2)")], [row("tech", "x", "seen", "Huntress and Field Effect")])[0]
    assert (a.suggested, a.auto_suggested) == ("Huntress and Field Effect", "Huntress (2)")


def test_a_note_alone_leaves_the_technology_answer_alone():
    a = ro.merge_tech([tech("x", "seen", "Huntress")], [row("tech", "x", None, None, "per the IT contact")])[0]
    assert (a.status, a.suggested, a.manual, a.note) == ("seen", "Huntress", False, "per the IT contact")


# ---- the Microsoft 365 questions ---------------------------------------------------------------------------------------------------------------------


def test_a_question_that_needed_a_person_gets_the_typed_status_and_a_checked_one_remembers_the_check():
    items = [M365Answer(group="g", question="Ensure A", status="needs_person"), M365Answer(group="g", question="Ensure B", status="not_met", evidence="read through CIPP")]
    out = ro.merge_m365(items, [row("m365", "Ensure A", "met", note="checked in the portal"), row("m365", "Ensure B", "partly")])
    assert (out[0].status, out[0].manual, out[0].auto_status, out[0].note) == ("met", True, "needs_person", "checked in the portal")
    assert (out[1].status, out[1].auto_status, out[1].evidence) == ("partly", "not_met", "read through CIPP")


def test_rows_of_another_section_or_question_do_nothing():
    items = ro.merge_readiness([item("backups")], [row("tech", "backups", "seen"), row("readiness", "other", "met")])
    assert (items[0].status, items[0].manual) == ("unknown", False)


# ---- the endpoint ------------------------------------------------------------------------------------------------------------------------------------


class FakeDB:
    def __init__(self, existing=None, count=0, tenant_found=True):
        self.existing, self.count, self.tenant_found = existing, count, tenant_found
        self.deleted, self.commits, self.statements = [], 0, []

    async def execute(self, statement):
        self.statements.append(statement)
        text = str(statement)
        if "FROM tenants" in text:
            return SimpleNamespace(scalar_one_or_none=lambda: uuid.uuid4() if self.tenant_found else None)
        if "count(" in text:
            return SimpleNamespace(scalar_one=lambda: self.count)
        if "client_review_answers" in text and text.lstrip().upper().startswith("SELECT"):
            return SimpleNamespace(scalar_one_or_none=lambda: self.existing)
        return SimpleNamespace()

    async def delete(self, obj):
        self.deleted.append(obj)

    async def commit(self):
        self.commits += 1


OWNER, CLIENT = uuid.uuid4(), uuid.uuid4()


@pytest.fixture(autouse=True)
def no_scoping(monkeypatch):
    """The tenant-scoping block is not under test here."""
    import contextlib

    monkeypatch.setattr(cr, "acting_as_tenant", lambda d, t: contextlib.nullcontext())


def put(db, **over):
    body = cr.AnswerIn(**{"section": "readiness", "key": "backups", "status": "met", "note": "n", **over})
    return asyncio.run(cr.save_review_answer(CLIENT, body, SimpleNamespace(tenant_id=OWNER, user_id=uuid.uuid4()), db))


def test_saving_stores_the_typed_values_and_says_when():
    db = FakeDB()
    out = put(db)
    assert (out.status, out.note, out.cleared) == ("met", "n", False)
    assert out.updated_at is not None and db.commits == 1


def test_saving_nothing_removes_an_existing_answer_and_goes_back_to_the_automatic_one():
    existing = row("readiness", "backups", "met")
    db = FakeDB(existing=existing)
    out = put(db, status=None, note=None)
    assert out.cleared is True and db.deleted == [existing] and db.commits == 1


def test_clearing_something_that_was_never_typed_is_harmless():
    db = FakeDB(existing=None)
    assert put(db, status="", note="").cleared is True
    assert db.deleted == [] and db.commits == 0


def test_a_client_that_is_not_the_callers_is_a_404_and_a_bad_status_a_422():
    with pytest.raises(HTTPException) as e:
        put(FakeDB(tenant_found=False))
    assert e.value.status_code == 404
    with pytest.raises(HTTPException) as bad:
        put(FakeDB(), status="seen")
    assert bad.value.status_code == 422


def test_a_client_cannot_hold_more_than_the_limit_of_typed_answers():
    with pytest.raises(HTTPException) as e:
        put(FakeDB(count=ro.MAX_PER_CLIENT))
    assert e.value.status_code == 422
    assert put(FakeDB(existing=row("readiness", "backups", "met"), count=ro.MAX_PER_CLIENT)).status == "met", "changing one that exists is always allowed"
