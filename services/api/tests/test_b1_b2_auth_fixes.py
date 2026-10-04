"""Tests for B1 (SSO fail-closed) and B2 (get_current_user ValueError → 401).

B1: oidc.py and saml.py must return 501 when unconfigured, never mint stub tokens.
B2: get_current_user must return 401 on malformed UUID sub claims, not 500.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials


# ─── B1: OIDC fail-closed ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_login_returns_501_when_unconfigured():
    """OIDC login must raise 501 when OIDC_ISSUER/OIDC_CLIENT_ID are missing."""
    from app.auth.oidc import router

    login_route = None
    for route in router.routes:
        if hasattr(route, "name") and route.name == "oidc_login":
            login_route = route
            break
    assert login_route is not None, "oidc_login route must exist"

    # oidc.py reads config via os.environ at call time.
    with patch.dict("os.environ", {}, clear=True):
        import os as _os

        _os.environ.pop("OIDC_ISSUER", None)
        _os.environ.pop("OIDC_CLIENT_ID", None)

        request = MagicMock()
        request.query_params = {}

        with pytest.raises(HTTPException) as exc_info:
            await login_route.endpoint(request)

        assert exc_info.value.status_code == 501
        assert "not configured" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_oidc_login_does_not_set_cookie_when_unconfigured():
    """OIDC login must NOT set aisoc_token cookie when unconfigured."""
    from app.auth.oidc import router

    login_route = None
    for route in router.routes:
        if hasattr(route, "name") and route.name == "oidc_login":
            login_route = route
            break

    with patch.dict("os.environ", {}, clear=True):
        import os as _os

        _os.environ.pop("OIDC_ISSUER", None)
        _os.environ.pop("OIDC_CLIENT_ID", None)

        request = MagicMock()
        request.query_params = {}

        try:
            response = await login_route.endpoint(request)
            cookies = getattr(response, "headers", {})
            assert "set-cookie" not in {k.lower() for k in cookies}
        except HTTPException as e:
            assert e.status_code == 501


# ─── B1: SAML fail-closed ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_saml_login_returns_501_when_python3_saml_missing():
    """SAML login must raise 501 when python3-saml is not installed."""
    from app.auth.saml import router

    login_route = None
    for route in router.routes:
        if hasattr(route, "name") and route.name == "saml_login":
            login_route = route
            break
    if login_route is None:
        pytest.skip("saml_login route not found")

    with patch.dict(
        "sys.modules",
        {"onelogin": None, "onelogin.saml2": None, "onelogin.saml2.auth": None},
    ):
        request = MagicMock()
        request.query_params = {}

        with pytest.raises(HTTPException) as exc_info:
            await login_route.endpoint(request)

        assert exc_info.value.status_code == 501


@pytest.mark.asyncio
async def test_saml_acs_returns_501_when_python3_saml_missing():
    """SAML ACS must raise 501 when python3-saml is not installed (no stub token)."""
    from app.auth.saml import router

    acs_route = None
    for route in router.routes:
        if hasattr(route, "name") and route.name == "saml_acs":
            acs_route = route
            break
    if acs_route is None:
        pytest.skip("saml_acs route not found")

    with patch.dict(
        "sys.modules",
        {"onelogin": None, "onelogin.saml2": None, "onelogin.saml2.auth": None},
    ):
        request = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await acs_route.endpoint(request)

        assert exc_info.value.status_code == 501


# ─── B2: get_current_user malformed UUID → 401 ────────────────────────────────


@pytest.mark.asyncio
async def test_get_current_user_returns_401_on_malformed_uuid():
    """get_current_user must return 401 (not 500) when sub claim is not a valid UUID."""
    from app.api.v1.deps import get_current_user

    # Pass a real HTTPAuthorizationCredentials so credentials.credentials
    # returns a string (not a MagicMock), avoiding the hash_api_key crash.
    creds = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="fake.jwt.token"
    )
    mock_db = AsyncMock()

    with patch("app.api.v1.deps.decode_token") as mock_decode:
        mock_decode.return_value = {
            "sub": "not-a-valid-uuid-at-all",
            "type": "access",
            "tenant_id": str(uuid.uuid4()),
        }

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(creds, mock_db)

        assert exc_info.value.status_code == 401
        assert (
            "malformed" in exc_info.value.detail.lower()
            or "invalid" in exc_info.value.detail.lower()
        )


@pytest.mark.asyncio
async def test_get_current_user_returns_401_on_empty_sub():
    """get_current_user must return 401 when sub claim is empty string."""
    from app.api.v1.deps import get_current_user

    creds = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="fake.jwt.token"
    )
    mock_db = AsyncMock()

    with patch("app.api.v1.deps.decode_token") as mock_decode:
        mock_decode.return_value = {
            "sub": "",
            "type": "access",
            "tenant_id": str(uuid.uuid4()),
        }

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(creds, mock_db)

        assert exc_info.value.status_code == 401