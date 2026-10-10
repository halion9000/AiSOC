"""First half of the module-scope check (see test_environment_isolation.py): a MODULE-scoped fixture changes the environment. test_environment_isolation_module_b.py runs after this file (alphabetical order) and must see none of it."""
import os

import pytest


@pytest.fixture(scope="module")
def sets_the_environment_for_the_whole_module():
    with open(os.path.join(os.path.dirname(__file__), ".env_isolation_before_module_a.tmp"), "w", encoding="utf-8") as f:
        f.write(repr(sorted((k, v) for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST")))
    os.environ["AISOC_ENVIRONMENT_LEAK_PROBE_MODULE"] = "leaked"
    os.environ["ENVIRONMENT"] = "development"
    return True


def test_the_module_scoped_fixture_changes_the_environment_for_this_module(sets_the_environment_for_the_whole_module):
    assert os.environ["AISOC_ENVIRONMENT_LEAK_PROBE_MODULE"] == "leaked"
