"""Helpers for tests that need to change a setting the code under test reads from ITS OWN import of the settings object.

Another test (test_graphql) reloads modules, after which `from app.core.config import settings` in a test file and the same import inside an application module are DIFFERENT objects: patching the test's copy then changes nothing the code reads, and the test passes alone but fails in the
full run. Patch the setting through the module that reads it.
"""


def patch_login_allow_email(monkeypatch, on: bool) -> None:
    """Switch email sign-in on or off where the sign-in lookup reads it (app.services.user_lookup)."""
    from app.services import user_lookup

    monkeypatch.setattr(user_lookup.settings, "LOGIN_ALLOW_EMAIL", on)
