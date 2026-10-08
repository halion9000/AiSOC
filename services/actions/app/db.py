"""Database access for the actions service: the engine, a session factory, and the FastAPI dependency the action routes use.

If DATABASE_URL is not configured the action routes answer HTTP 503 with a clear message. They do NOT fall back to process memory: that would silently reintroduce the defect this layer exists to remove
(pending approvals, ChatOps links and the record of what ran, all lost on restart) with nobody able to see it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_factory: async_sessionmaker[AsyncSession] | None = None


def get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    """The session factory, or None when DATABASE_URL is not configured."""
    global _engine, _factory
    if _factory is None:
        url = get_settings().DATABASE_URL.strip()
        if not url:
            return None
        _engine = create_async_engine(url, pool_pre_ping=True)
        _factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _factory


async def dispose_engine() -> None:
    global _engine, _factory
    if _engine is not None:
        await _engine.dispose()
    _engine, _factory = None, None


SessionProvider = Callable[[], AbstractAsyncContextManager[AsyncSession]]


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """A session, or HTTP 503 when the store is not configured. The 503 is raised when this is ENTERED, not when the route is matched."""
    factory = get_session_factory()
    if factory is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The action store is not configured: set DATABASE_URL. Response actions are not accepted without a durable store.",
        )
    async with factory() as session:
        yield session


def get_session_provider() -> SessionProvider:
    """For PUBLIC routes (the ChatOps callback): hands back a way to open a session LATER, so nothing touches the database until the caller has been authenticated.
    A plain `Depends(get_db)` resolves before the route runs, i.e. before a signed link is verified, letting an unauthenticated request reach the database layer."""
    return session_scope


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session
