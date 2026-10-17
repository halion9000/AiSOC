"""/auth/refresh with a refresh token whose subject is not a UUID answers 401, not a 500."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from app.api.v1.endpoints import auth
from app.core.security import create_refresh_token
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_a_refresh_token_with_a_malformed_subject_is_a_401(monkeypatch):
    monkeypatch.setattr(auth, "is_revoked", AsyncMock(return_value=False))
    token = create_refresh_token({"sub": "not-a-uuid", "tenant_id": "x", "role": "analyst"})
    with pytest.raises(HTTPException) as exc:
        await auth.refresh_token(auth.RefreshRequest(refresh_token=token), db=None)  # the database is never reached
    assert exc.value.status_code == 401
