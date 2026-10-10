"""A test cannot change the environment that every later test sees.

Some tests set variables directly (os.environ.setdefault("ENVIRONMENT", "development") in the GraphQL and route-coverage tests) and never undid it, so every test that ran after them silently ran in development mode (where a request with no credentials is the demo user). The autouse
fixtures in conftest.py restore the process environment after each test, each class and each module. These tests run in definition order (in one process) and prove it for the mechanisms the real offenders use: a change made INSIDE a test, and a change made by a CLASS-scoped fixture (what
test_b10_backend_route_coverage does). The module-scoped case needs two files and lives in test_environment_isolation_module_a.py / _b.py.
"""
import os

import pytest

PROBE = "AISOC_ENVIRONMENT_LEAK_PROBE"
_SEEN: dict = {}


def env() -> dict:
    """The environment without the variable pytest rewrites itself at every phase of every test."""
    return {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}


class TestAChangeInsideATestDoesNotLeak:
    def test_one_a_test_changes_the_environment_the_way_the_offenders_did(self):
        _SEEN["before_one"] = env()
        os.environ.setdefault("ENVIRONMENT", "development")
        os.environ["ENVIRONMENT"] = "development"
        os.environ[PROBE] = "leaked"
        assert os.environ[PROBE] == "leaked"

    def test_two_the_next_test_sees_exactly_what_the_first_one_started_with(self):
        assert PROBE not in os.environ, "an environment variable set by an earlier test leaked into this one"
        assert env() == _SEEN["before_one"], "the environment was changed by an earlier test and not restored"

    def test_three_removing_and_adding_during_a_test(self):
        _SEEN["before_three"] = env()
        os.environ["AISOC_ENV_PROBE_ADDED"] = "present"
        os.environ.pop("PATH", None)

    def test_four_what_was_removed_is_back_and_what_was_added_is_gone(self):
        assert env() == _SEEN["before_three"] and "PATH" in os.environ and "AISOC_ENV_PROBE_ADDED" not in os.environ


class TestAClassScopedFixtureDoesNotLeak:
    """What test_b10_backend_route_coverage does: a class-scoped fixture calls os.environ.setdefault(...). It runs before any per-test snapshot, so only a class-level restore can undo it."""

    @pytest.fixture(scope="class")
    def sets_the_environment_like_the_route_coverage_test(self):
        _SEEN["before_class"] = env()
        os.environ.setdefault("ENVIRONMENT", "development")
        os.environ["ENVIRONMENT"] = "development"
        os.environ[PROBE + "_CLASS"] = "leaked"
        return True

    def test_one_the_fixture_changes_the_environment_for_this_class(self, sets_the_environment_like_the_route_coverage_test):
        assert os.environ["ENVIRONMENT"] == "development" and os.environ[PROBE + "_CLASS"] == "leaked", "the class's own tests do see the change they asked for"


class TestTheNextClassSeesNoneOfIt:
    def test_the_environment_is_what_it_was_before_the_class_scoped_fixture_ran(self):
        assert PROBE + "_CLASS" not in os.environ, "a class-scoped fixture's environment change leaked into the next class"
        assert env() == _SEEN["before_class"], "the environment was changed by an earlier class and not restored"
