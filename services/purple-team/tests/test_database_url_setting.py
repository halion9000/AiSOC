"""purple-team: the database variable compose sets is the one the service reads.

Compose gives every service a plain DATABASE_URL, but this service's settings class has the PURPLE_TEAM_ prefix, so DATABASE_URL was IGNORED and the
service fell back to postgresql://...@localhost, which does not exist inside its container. Both names are accepted now, the prefixed one first
(the same order as its Alembic environment, so the app and its migrations always agree).
"""
from __future__ import annotations

from pathlib import Path

import yaml
from app.core.config import Settings

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text(encoding="utf-8"))["services"]["purple-team"]
DEFAULT = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"


def _clear(monkeypatch):
    for key in ("PURPLE_TEAM_DATABASE_URL", "DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)


def test_the_variable_compose_sets_is_read(monkeypatch):
    _clear(monkeypatch)
    env = COMPOSE["environment"]
    env = env if isinstance(env, dict) else dict(x.split("=", 1) for x in env if "=" in x)
    assert "DATABASE_URL" in env, "compose gives this service no database URL"
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@postgres:5432/aisoc")
    assert Settings().database_url == "postgresql+asyncpg://u:p@postgres:5432/aisoc"


def test_the_prefixed_name_wins_and_the_default_is_the_fallback(monkeypatch):
    _clear(monkeypatch)
    assert Settings().database_url == DEFAULT
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://a@h1/db")
    monkeypatch.setenv("PURPLE_TEAM_DATABASE_URL", "postgresql+asyncpg://b@h2/db")
    assert Settings().database_url == "postgresql+asyncpg://b@h2/db"


def test_constructing_by_field_name_still_works():
    assert Settings(database_url="postgresql+asyncpg://c@h3/db").database_url == "postgresql+asyncpg://c@h3/db"
