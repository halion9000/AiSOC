"""Shared test fixtures for the API service."""
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
