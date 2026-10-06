"""Production bootstrap: input validation, strict migrations, scopes, schema guard.

The end-to-end run (fresh Postgres -> bootstrap -> login/key checks) needs a
real database and is exercised manually; these tests cover the logic and the
invariants that keep production safe, and they run anywhere.
"""
import re
from pathlib import Path

import pytest

from app.scripts import bootstrap_production as bp

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


@pytest.mark.parametrize("email", ["hal@example.com", "Someone.Else+soc@corp.co.uk"])
def test_accepts_real_emails(email):
    bp.validate_inputs(email, "a-long-enough-password")


@pytest.mark.parametrize("email", ["", "not-an-email", "a@b", "admin@aisoc.local", "ADMIN@aisoc.local"])
def test_rejects_bad_or_seeded_emails(email):
    with pytest.raises(bp.BootstrapError):
        bp.validate_inputs(email, "a-long-enough-password")


def test_rejects_short_password_but_allows_none_for_reruns():
    with pytest.raises(bp.BootstrapError, match="at least"):
        bp.validate_inputs("hal@example.com", "short")
    bp.validate_inputs("hal@example.com", None)  # rerun: admin already exists


def test_missing_migrations_is_strict():
    files = ["001_init.sql", "002_rls.sql", "052_case_tasks_and_timeline.sql"]
    assert bp.missing_migrations(files, set(files)) == []
    assert bp.missing_migrations(files, {"001_init.sql"}) == ["002_rls.sql", "052_case_tasks_and_timeline.sql"]


def test_core_key_scopes_are_minimal_and_valid():
    from app.api.v1.endpoints import api_keys

    allowed = next(v for k, v in vars(api_keys).items() if k.isupper() and "SCOPE" in k and isinstance(v, (set, frozenset, list, tuple)))
    assert set(bp.CORE_KEY_SCOPES) <= set(allowed), "CORE's key must only use scopes AiSOC recognises"
    assert "*" not in bp.CORE_KEY_SCOPES
    assert not any(s.endswith(":delete") for s in bp.CORE_KEY_SCOPES), "CORE never deletes"


def test_every_orm_table_is_created_by_a_sql_migration():
    """Production builds the schema from SQL migrations only (create_all is
    development-only). An ORM table with no CREATE TABLE in any migration
    silently does not exist in production. case_tasks/case_timeline were."""
    import app.models  # noqa: F401
    from app.db.database import Base

    created = set()
    for f in MIGRATIONS.glob("*.sql"):
        created |= {m.lower() for m in re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)\"?", f.read_text(encoding="utf-8"), re.I)}
    missing = sorted(t for t in Base.metadata.tables if t.lower() not in created)
    assert not missing, f"ORM tables with no SQL migration (would not exist in production): {missing}"


def test_agents_service_key_is_read_only_and_distinct():
    assert bp.AGENTS_KEY_NAME != bp.CORE_KEY_NAME
    assert set(bp.AGENTS_KEY_SCOPES) == {"alerts:read", "cases:read"}
    assert not any(s.endswith((":write", ":delete", ":execute")) for s in bp.AGENTS_KEY_SCOPES)
