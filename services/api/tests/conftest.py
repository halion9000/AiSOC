"""Shared test fixtures for the API service."""
import os

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core import token_revocation


class FakeRedis:
    """An in-memory stand-in for the slice of Redis the token denylist uses, with a switch to simulate an outage."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}
        self.down = False

    def _check(self) -> None:
        if self.down:
            raise RedisConnectionError("simulated outage")

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self._check()
        self.data[key] = value
        self.ttls[key] = ex
        return True

    async def exists(self, key: str) -> int:
        self._check()
        return int(key in self.data)


@pytest.fixture(autouse=True)
def revocation_store(monkeypatch):
    """Every test gets a private, empty denylist instead of reaching for a real Redis: access tokens now carry a jti that get_current_user looks up on each request."""
    store = FakeRedis()
    monkeypatch.setattr(token_revocation, "_get_client", lambda: store)
    return store


@pytest.fixture(autouse=True)
def _a_test_cannot_change_the_environment_every_later_test_sees():
    """Snapshot the process environment before each test and restore it after.

    Some tests set variables directly (os.environ.setdefault("ENVIRONMENT", "development") in the GraphQL and route-coverage tests) and never undid it, so every test that ran AFTER them silently ran in development mode, where a request with no credentials
    is the demo user: whether a test saw development mode depended on which other tests had run first, and a single file behaved differently from the full run. A test that needs a particular environment must now say so (monkeypatch.setenv, or patching the mode as the authentication tests do).
    """
    before = dict(os.environ)
    yield
    if dict(os.environ) != before:
        os.environ.clear()
        os.environ.update(before)
