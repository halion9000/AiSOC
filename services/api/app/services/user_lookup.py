"""Find a user by email address, the one way: case-insensitively (see app/core/emails.py).

A bare `User.email == address` is exact-case, so it misses a legacy account stored as `Alice@x` when asked for `alice@x`, and cannot see that `alice@x` is already taken by `Alice@x`. Every lookup goes through here (a test fails the
build if code compares `User.email ==` directly).

If a deployment already holds two accounts that differ only in letter case (the very thing this prevents from now on), the answer is deterministic and never an error: an exact-case match wins, otherwise the oldest account.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select

from app.core.emails import normalize_email
from app.models.tenant import User


async def find_user_by_email(db: Any, email: str, *, active_only: bool = False, tenant_id: uuid.UUID | None = None) -> User | None:
    stmt = select(User).where(func.lower(User.email) == normalize_email(email))
    if active_only:
        stmt = stmt.where(User.is_active.is_(True))
    if tenant_id is not None:
        stmt = stmt.where(User.tenant_id == tenant_id)
    stmt = stmt.order_by((User.email == email).desc(), User.created_at.asc()).limit(1)
    return (await db.execute(stmt)).scalars().first()
