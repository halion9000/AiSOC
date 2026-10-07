"""Slack bot test setup.

The bot refuses to start without SLACK_SIGNING_SECRET (there is no mode in which it runs unverified), so tests that build the app
supply one, exactly as a real deployment does. A test that needs the secret ABSENT removes it explicitly (monkeypatch.delenv).
"""
from __future__ import annotations

import sys

import pytest


def _clear_settings_caches() -> None:
    """test_config.py reloads app.core.config, which can leave app.main holding the previous module's cached get_settings."""
    from app.core import config

    config.get_settings.cache_clear()
    main = sys.modules.get("app.main")
    if main is not None:
        main.get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _a_signing_secret_like_a_real_deployment(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "test-signing-secret")
    _clear_settings_caches()
    yield
    _clear_settings_caches()
