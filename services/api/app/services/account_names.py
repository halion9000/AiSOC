"""Account names that are free to use (see app/core/account_names.py for what a valid name is)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from app.core.account_names import normalize_account_name, suggest_account_name, with_suffix
from app.models.tenant import User

_MAX_ATTEMPTS = 10_000


async def account_name_taken(db: Any, name: str) -> bool:
    """Is this name used by any account on the platform? (Case-insensitive; account names are unique across all tenants.)"""
    found = (await db.execute(select(User.id).where(func.lower(User.account_name) == normalize_account_name(name)).limit(1))).first()
    return found is not None


async def unique_account_name(db: Any, source: str) -> str:
    """A free valid name made from `source` (free text or an email): the suggestion itself, else `-2`, `-3`, ... added. For accounts created on someone's behalf who did not choose a name."""
    base = suggest_account_name(source)
    candidate = base
    for n in range(2, _MAX_ATTEMPTS):
        if not await account_name_taken(db, candidate):
            return candidate
        candidate = with_suffix(base, n)
    raise RuntimeError(f"no free account name found for {source!r}")
