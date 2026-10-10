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


_PYTEST_OWN_VARIABLE = "PYTEST_CURRENT_TEST"  # pytest rewrites this itself at every phase of every test: it is not the tests' business and is never compared or restored


def _environment() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != _PYTEST_OWN_VARIABLE}


def _restore_the_environment_afterwards():
    before = _environment()
    yield
    if _environment() != before:
        for name in [k for k in os.environ if k != _PYTEST_OWN_VARIABLE and k not in before]:
            del os.environ[name]
        os.environ.update(before)


# Snapshot the process environment before each test, each class and each module, and restore it afterwards.
#
# Some tests set variables directly (os.environ.setdefault("ENVIRONMENT", "development") in the GraphQL and route-coverage tests) and never undid it, so every test that ran AFTER them silently ran in development mode, where a request with no credentials is the demo
# user: whether a test saw development mode depended on which other tests had run first, and a single file behaved differently from the full run. The offenders do it from different places (inside a test; from a CLASS-scoped fixture, as the route-coverage test does), and a
# restore at one scope cannot undo a change made at a wider one, hence all three. A test that needs a particular environment must say so (monkeypatch.setenv, or patching the mode as the authentication tests do). Autouse fixtures are set up first within their scope, so the snapshot
# is taken before any other fixture of that scope changes anything.
@pytest.fixture(autouse=True)
def _a_test_cannot_change_the_environment_the_next_test_sees():
    yield from _restore_the_environment_afterwards()


@pytest.fixture(autouse=True, scope="class")
def _a_class_cannot_change_the_environment_the_next_class_sees():
    yield from _restore_the_environment_afterwards()


@pytest.fixture(autouse=True, scope="module")
def _a_module_cannot_change_the_environment_the_next_module_sees():
    yield from _restore_the_environment_afterwards()
