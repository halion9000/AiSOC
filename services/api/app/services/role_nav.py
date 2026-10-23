"""Which parts of the console a role hides.

A role can hide a whole section of the sidebar (``section:Automation``) or a single page (its address, ``/settings/mfa``). This is what the person SEES: it does not replace permissions, which are what the server enforces.
A person with several roles sees a page when any of their roles shows it, so a page is hidden for them only when every one of their roles hides it. Pure functions, so the rules are testable without a database.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from fastapi import HTTPException, status

MAX_ENTRIES = 200
_SECTION = re.compile(r"^section:[A-Za-z0-9][A-Za-z0-9 &/_-]{0,59}$")
_PAGE = re.compile(r"^/[A-Za-z0-9/_-]{0,119}$")


def valid_entry(entry: str) -> bool:
    return bool(_SECTION.match(entry) or _PAGE.match(entry))


def clean_hidden_nav(entries: Iterable[str] | None) -> list[str]:
    """The entries, trimmed and without repeats, in the order given. Anything that is not a section or a page address is refused, so a role cannot carry junk the sidebar then has to guess about."""
    out: list[str] = []
    for raw in entries or []:
        entry = str(raw).strip()
        if not valid_entry(entry):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Not a section or page the console can hide: {entry[:80]!r}")
        if entry not in out:
            out.append(entry)
    if len(out) > MAX_ENTRIES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"A role can hide at most {MAX_ENTRIES} entries")
    return out


def hidden_for_roles(per_role: list[list[str]]) -> list[str]:
    """What a person with these roles does not see: the entries every one of their roles hides. No roles at all (nothing assigned) hides nothing."""
    if not per_role:
        return []
    shared = set(per_role[0])
    for hidden in per_role[1:]:
        shared &= set(hidden)
    return sorted(shared)
