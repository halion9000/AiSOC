"""Authentication endpoints: login, refresh, logout, user preferences."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, bearer_scheme, get_current_user

__all__ = ["router", "get_current_user"]
from app.core.config import settings
from app.core.security import known_permissions
from app.core.token_revocation import RevocationUnavailable, is_revoked, revoke
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.models.tenant import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    """Optionally also revoke the refresh token that goes with this session."""

    refresh_token: str | None = None


class LogoutResponse(BaseModel):
    revoked: bool
    detail: str


class UserMeResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class PreferencesPatch(BaseModel):
    """Partial update payload for user preferences (merged server-side)."""

    preferences: dict[str, Any]


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: DBSession) -> TokenResponse:
    """Authenticate with email/password, return JWT tokens."""
    result = await db.execute(select(User).where(User.email == request.email, User.is_active.is_(True)))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last login
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.now(UTC)))

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    current_user: AuthUser,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    body: LogoutRequest | None = None,
) -> LogoutResponse:
    """End this session on the server: revoke the access token (and the refresh token, if given) so neither works again, even if copied.

    Honest about what it did: ``revoked`` is false, with the reason, when there was nothing it could revoke (an API key, or a token issued before revocation existed);
    and if the revocation store is down it answers 503 rather than claiming the session ended.
    """
    token = credentials.credentials if credentials else None
    if token is None:
        return LogoutResponse(revoked=False, detail="There is no session token to revoke.")
    if token.startswith("aisoc_"):
        return LogoutResponse(revoked=False, detail="API keys are not sessions; revoke the key from the API keys page.")
    try:
        access = decode_token(token)
    except Exception as e:  # get_current_user already accepted it, so this is only a race with expiry
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e

    to_revoke: list[tuple[str, Any]] = []
    if access.get("jti"):
        to_revoke.append((access["jti"], access["exp"]))
    if body and body.refresh_token:
        try:
            refresh = decode_token(body.refresh_token)
        except Exception:
            refresh = {}
        # Only this user's own refresh token: a body must not be a way to sign someone else out.
        if refresh.get("type") == "refresh" and refresh.get("sub") == str(current_user.user_id) and refresh.get("jti"):
            to_revoke.append((refresh["jti"], refresh["exp"]))

    if not to_revoke:
        return LogoutResponse(
            revoked=False,
            detail="This session was issued before server-side revocation existed, so it cannot be revoked and will end when it expires.",
        )
    try:
        for jti, exp in to_revoke:
            await revoke(jti, exp)
    except RevocationUnavailable as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not end the session: the revocation store is unavailable. Try again.",
        ) from e
    return LogoutResponse(revoked=True, detail="Session ended.")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: DBSession) -> TokenResponse:
    """Refresh access token using a valid refresh token."""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = payload.get("sub")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from e

    if await is_revoked(payload.get("jti")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


class AuthorizeRequest(BaseModel):
    permission: str


class AuthorizeResponse(BaseModel):
    allowed: bool
    permission: str


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(body: AuthorizeRequest, current_user: AuthUser) -> AuthorizeResponse:
    """May the caller (user login or API key) do `permission`?

    Other services (the agents service, which the web console talks to directly)
    ask the API instead of keeping their own copy of the role table, so there is
    one source of truth. 401 for bad credentials, 403 when the caller lacks the
    permission, 422 for a name the API does not recognise (a typo must not
    silently pass for an admin, who holds every permission).
    """
    if body.permission not in known_permissions():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown permission: {body.permission}")
    current_user.require_permission(body.permission)
    return AuthorizeResponse(allowed=True, permission=body.permission)


@router.get("/me", response_model=UserMeResponse)
async def get_me(current_user: AuthUser, db: DBSession) -> UserMeResponse:
    """Get current authenticated user info."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserMeResponse.model_validate(user)


@router.patch("/me/preferences", response_model=UserMeResponse)
async def patch_me_preferences(
    body: PreferencesPatch,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Merge user preferences (e.g. theme) into the stored JSONB column.

    Only the keys supplied in the request body are updated; all other
    existing keys are preserved.  This lets the frontend evolve independent
    preference namespaces without overwriting each other.
    """
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    merged = {**(user.preferences or {}), **body.preferences}
    await db.execute(update(User).where(User.id == current_user.user_id).values(preferences=merged))
    await db.commit()

    # Re-fetch to return fresh state
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    return UserMeResponse.model_validate(user)
