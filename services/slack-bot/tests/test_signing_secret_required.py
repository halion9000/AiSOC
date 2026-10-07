"""Outside development the Slack bot refuses to start without SLACK_SIGNING_SECRET.

Without the secret Bolt cannot verify that a request really came from Slack, so /slack/events would accept forged slash commands
and interactive payloads from anyone who can reach it. The old code disabled verification whenever the secret was missing (its own
docstring said verification was "mandatory in production"). Unset AISOC_SLACK_BOT_ENVIRONMENT means a local run; set-but-empty or
unrecognised is NOT development, because a mistake must fail closed.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from app.core import config as config_module
from app.core.config import is_development


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


def _build(monkeypatch, *, secret, environment):
    for key in ("SLACK_SIGNING_SECRET", "AISOC_SLACK_BOT_ENVIRONMENT"):
        monkeypatch.delenv(key, raising=False)
    if secret:
        monkeypatch.setenv("SLACK_SIGNING_SECRET", secret)
    if environment is not None:
        monkeypatch.setenv("AISOC_SLACK_BOT_ENVIRONMENT", environment)
    _clear_settings_caches()
    from app.main import _build_bolt_app

    return _build_bolt_app(MagicMock(), MagicMock())


@pytest.mark.parametrize("environment", ["production", "staging", "prod", "prodution", "", " "])
def test_outside_development_a_missing_secret_is_a_refusal_to_start(monkeypatch, environment):
    with pytest.raises(RuntimeError, match="SLACK_SIGNING_SECRET is required"):
        _build(monkeypatch, secret=None, environment=environment)


@pytest.mark.parametrize("environment", ["production", "staging", "prod", ""])
def test_outside_development_a_configured_secret_starts_normally(monkeypatch, environment):
    assert _build(monkeypatch, secret="a-real-signing-secret", environment=environment) is not None


@pytest.mark.parametrize("environment", ["development", "dev", "local", "test", "Development", None])
def test_a_local_run_without_a_secret_still_starts(monkeypatch, environment):
    assert _build(monkeypatch, secret=None, environment=environment) is not None


@pytest.mark.parametrize("value,expected", [(None, True), ("development", True), ("DEV", True), ("local", True), ("test", True),
                                            ("production", False), ("", False), ("  ", False), ("prodution", False)])
def test_is_development(monkeypatch, value, expected):
    monkeypatch.delenv("AISOC_SLACK_BOT_ENVIRONMENT", raising=False)
    if value is not None:
        monkeypatch.setenv("AISOC_SLACK_BOT_ENVIRONMENT", value)
    assert is_development() is expected
