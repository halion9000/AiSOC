"""The Slack bot refuses to start without SLACK_SIGNING_SECRET. There is no mode in which it runs unverified.

Without the secret Bolt cannot verify that a request really came from Slack, so /slack/events would accept forged slash commands and
interactive payloads from anyone who can reach it. The old code disabled verification whenever the secret was missing, and later only
refused outside a "development" environment. Now no environment value, set or unset, changes the answer.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from app.core import config as config_module


def _clear_settings_caches():
    """test_config.py reloads app.core.config, which leaves app.main holding the PREVIOUS module's cached get_settings; clear both."""
    import app.main as main_module

    config_module.get_settings.cache_clear()
    main_module.get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _fresh_settings():
    _clear_settings_caches()
    yield
    _clear_settings_caches()


def _build(monkeypatch, *, secret, environment=None):
    for key in ("SLACK_SIGNING_SECRET", "AISOC_SLACK_BOT_ENVIRONMENT", "ENVIRONMENT"):
        monkeypatch.delenv(key, raising=False)
    if secret is not None:
        monkeypatch.setenv("SLACK_SIGNING_SECRET", secret)
    if environment is not None:
        monkeypatch.setenv("AISOC_SLACK_BOT_ENVIRONMENT", environment)
        monkeypatch.setenv("ENVIRONMENT", environment)
    _clear_settings_caches()
    from app.main import _build_bolt_app

    return _build_bolt_app(MagicMock(), MagicMock())


@pytest.mark.parametrize("environment", [None, "production", "staging", "", "development", "dev", "local", "test", "Development"])
@pytest.mark.parametrize("secret", [None, "", "   "])
def test_without_a_signing_secret_it_refuses_to_start_whatever_the_environment_says(monkeypatch, secret, environment):
    with pytest.raises(RuntimeError, match="SLACK_SIGNING_SECRET is required"):
        _build(monkeypatch, secret=secret, environment=environment)


@pytest.mark.parametrize("environment", [None, "production", "development", ""])
def test_with_a_signing_secret_it_starts_normally(monkeypatch, environment):
    assert _build(monkeypatch, secret="a-real-signing-secret", environment=environment) is not None


def test_the_helper_that_used_to_excuse_a_local_run_is_gone():
    assert not hasattr(config_module, "is_development")


def test_bolt_is_always_told_to_verify_and_given_the_secret(monkeypatch):
    """The guard is only half of it: the app it builds must actually verify Slack's signature with that secret."""
    import app.main as main_module

    seen: dict = {}
    real = main_module.AsyncApp

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(main_module, "AsyncApp", spy)
    _build(monkeypatch, secret="  a-real-signing-secret  ")
    assert seen["request_verification_enabled"] is True
    assert seen["signing_secret"] == "a-real-signing-secret"

