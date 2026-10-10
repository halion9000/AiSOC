"""A test cannot change the environment that every later test sees.

Some tests set variables directly (os.environ.setdefault("ENVIRONMENT", "development") in the GraphQL and route-coverage tests) and never undid it, so every test that ran after them silently ran in development mode (where a request with no credentials is
the demo user). The autouse fixture in conftest.py restores the process environment after each test; these two tests run in order (definition order, in one process) and prove it: the first changes the environment the way the offenders did, the second must not see it.
"""
import os

PROBE = "AISOC_ENVIRONMENT_LEAK_PROBE"
_BEFORE = {"ENVIRONMENT": os.environ.get("ENVIRONMENT")}


class TestEnvironmentChangesDoNotLeak:
    def test_one_a_test_changes_the_environment_the_way_the_offenders_did(self):
        os.environ.setdefault("ENVIRONMENT", "development")
        os.environ["ENVIRONMENT"] = "development"
        os.environ[PROBE] = "leaked"
        assert os.environ[PROBE] == "leaked" and os.environ["ENVIRONMENT"] == "development"

    def test_two_the_next_test_sees_none_of_it(self):
        assert PROBE not in os.environ, "an environment variable set by an earlier test leaked into this one"
        assert os.environ.get("ENVIRONMENT") == _BEFORE["ENVIRONMENT"], "ENVIRONMENT was changed by an earlier test and not restored"

    def test_three_a_variable_a_test_removes_comes_back_for_the_next(self):
        os.environ["AISOC_ENV_PROBE_REMOVED"] = "present"  # set by this test; the fixture must also undo additions made DURING the test
        os.environ.pop("PATH", None)

    def test_four_what_the_previous_test_removed_is_back_and_what_it_added_is_gone(self):
        assert "PATH" in os.environ and "AISOC_ENV_PROBE_REMOVED" not in os.environ
