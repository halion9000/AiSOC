"""Answers typed into the client review, laid over what A.C.O.R.N worked out.

A person can set a question's status (and, for the technology questions, the answer) and add a note. A status or answer replaces the automatic one on the page, which keeps showing what A.C.O.R.N worked
out ("Suggested"), so nothing is lost and the automatic answer can be returned to by clearing it. A note alone changes no answer. Pure functions over simple values, testable without a database.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

SECTIONS: dict[str, frozenset[str]] = {
    "readiness": frozenset({"met", "partly", "not_met", "unknown"}),
    "tech": frozenset({"seen", "not_seen", "unknown"}),
    "m365": frozenset({"met", "partly", "not_met", "needs_person"}),
}
MAX_NOTE = 4000
MAX_ANSWER = 300
MAX_PER_CLIENT = 400


def clean_answer(
    section: str, key: str, state: str | None, answer: str | None, note: str | None
) -> tuple[str | None, str | None, str | None]:
    """The status, answer and note to store, trimmed and checked. ``(None, None, None)`` means there is nothing to keep, so the row is removed. Raises a 422 for a status the section does not have."""
    if section not in SECTIONS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="section must be readiness, tech or m365")
    if not key.strip() or len(key) > 400:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="That question key is not valid")
    st = (state or "").strip() or None
    if st is not None and st not in SECTIONS[section]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"status for {section} must be one of: {', '.join(sorted(SECTIONS[section]))}",
        )
    ans = (answer or "").strip() or None
    if ans is not None and section != "tech":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="only the technology questions take a typed answer")
    if ans is not None and len(ans) > MAX_ANSWER:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"the answer can be at most {MAX_ANSWER} characters")
    nt = (note or "").strip() or None
    if nt is not None and len(nt) > MAX_NOTE:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"the note can be at most {MAX_NOTE} characters")
    return st, ans, nt


def _index(rows: list[Any], section: str) -> dict[str, Any]:
    return {r.key: r for r in rows if r.section == section}


def merge_readiness(items: list[Any], rows: list[Any]) -> list[Any]:
    """The checklist with typed statuses laid over the worked-out ones. Each item says whether it was replaced, what A.C.O.R.N had worked out, and carries the note."""
    by_key = _index(rows, "readiness")
    for i in items:
        r = by_key.get(i.key)
        if r is None:
            continue
        i.note = r.note
        i.updated_at = r.updated_at
        if r.status and r.status != i.status:
            i.auto_status = i.status
            i.status = r.status
            i.manual = True
        elif r.status:
            i.manual = True
    return items


def merge_tech(items: list[Any], rows: list[Any]) -> list[Any]:
    """The technology answers with a typed status and answer laid over the worked-out ones."""
    by_key = _index(rows, "tech")
    for a in items:
        r = by_key.get(a.key)
        if r is None:
            continue
        a.note = r.note
        a.updated_at = r.updated_at
        if not (r.status or r.answer):
            continue
        a.manual = True
        a.auto_status = a.status
        a.auto_suggested = a.suggested
        if r.status:
            a.status = r.status
        if r.answer:
            a.suggested = r.answer
            if not r.status and a.status == "unknown":
                a.status = "seen"
        elif r.status == "not_seen":
            a.suggested = "None seen"
        elif r.status == "unknown":
            a.suggested = None
        elif r.status == "seen" and not a.suggested:
            a.suggested = "Yes"
    return items


def merge_m365(items: list[Any], rows: list[Any]) -> list[Any]:
    """The Microsoft 365 answers with a typed status laid over the worked-out ones (a question that needed a person has an answer once someone gives it)."""
    by_key = _index(rows, "m365")
    for a in items:
        r = by_key.get(a.question)
        if r is None:
            continue
        a.note = r.note
        a.updated_at = r.updated_at
        if r.status:
            a.manual = True
            if r.status != a.status:
                a.auto_status = a.status
                a.status = r.status
    return items


def readiness_counts(items: list[Any]) -> dict[str, int]:
    return {k: sum(1 for i in items if i.status == k) for k in ("met", "partly", "not_met", "unknown")}
