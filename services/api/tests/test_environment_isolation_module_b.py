"""Second half of the module-scope check: runs after test_environment_isolation_module_a.py and must see none of what its module-scoped fixture changed."""
import os


def test_a_module_scoped_fixtures_environment_change_did_not_leak_into_the_next_module():
    path = os.path.join(os.path.dirname(__file__), ".env_isolation_before_module_a.tmp")
    if not os.path.exists(path):  # module_a did not run first (a single-file or reordered run): nothing to compare
        assert "AISOC_ENVIRONMENT_LEAK_PROBE_MODULE" not in os.environ
        return
    before = dict(eval(open(path, encoding="utf-8").read()))  # noqa: S307 (a file this test suite wrote a moment ago)
    os.remove(path)
    assert "AISOC_ENVIRONMENT_LEAK_PROBE_MODULE" not in os.environ, "a module-scoped fixture's environment change leaked into the next module"
    assert {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"} == before
