"""The weekly digest must write a status the database accepts.

report_artefacts.status is CHECK-constrained (migration 019) to pending | generating | completed | failed. The digest worker wrote status="ready", which the database refused with a CheckViolationError, so EVERY tenant's digest failed ({'tenants': 3, 'generated': 0, 'failed': 3}), under the superuser exactly as under the restricted role: no weekly digest could ever be saved.
Nothing caught it: the existing worker tests mock every database call, and the html-fallback test PATCHES `_generate_for_tenant` WITH ITS OWN RE-IMPLEMENTATION and asserts on the copy's output, so it can never see what the real function writes. These tests run the real function (mocking only its collaborators) and read the allowed values from the migration, not from a copy in the test.
"""
import ast
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.report import ReportArtefact
from app.workers import weekly_digest_task as wdt

SERVICE = Path(wdt.__file__).resolve().parents[2]
MIGRATION = (SERVICE / "migrations" / "019_board_reports.sql").read_text(encoding="utf-8")
ALLOWED = set(re.search(r"status\s+TEXT NOT NULL DEFAULT 'pending'\s*CHECK \(status IN \(([^)]*)\)\)", MIGRATION).group(1).replace("'", "").replace(" ", "").split(","))


class _Session:
    def __init__(self):
        self.added, self.commits = [], 0

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


class _Factory:
    def __init__(self, session):
        self.session = session

    def __call__(self):
        return self

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


def test_the_allowed_values_are_read_from_the_migration_and_are_what_we_think():
    assert ALLOWED == {"pending", "generating", "completed", "failed"}, "migration 019's constraint changed: re-read these tests"


@pytest.mark.asyncio
async def test_the_real_per_tenant_function_saves_an_artefact_with_an_allowed_status(monkeypatch):
    session = _Session()
    monkeypatch.setattr(wdt, "AsyncSessionLocal", _Factory(session))
    monkeypatch.setattr(wdt, "_artefact_exists", AsyncMock(return_value=False))
    monkeypatch.setattr(wdt, "build_weekly_digest", AsyncMock(return_value=SimpleNamespace(model_dump=lambda mode="python": {"ok": True})))
    monkeypatch.setattr(wdt, "render_digest_pdf", lambda digest: b"%PDF-1.4 test")
    tenant = uuid.uuid4()
    await wdt._generate_for_tenant(tenant, datetime(2026, 10, 5, tzinfo=UTC), datetime(2026, 10, 11, 23, 59, 59, tzinfo=UTC))
    assert len(session.added) == 1 and session.commits == 1
    artefact = session.added[0]
    assert isinstance(artefact, ReportArtefact) and artefact.tenant_id == tenant and artefact.report_type == "weekly_digest"
    assert artefact.status in ALLOWED, f"the digest wrote status={artefact.status!r}; the database accepts only {sorted(ALLOWED)}"
    assert artefact.status == "completed"


@pytest.mark.asyncio
async def test_an_existing_artefact_for_the_window_writes_nothing(monkeypatch):
    session = _Session()
    monkeypatch.setattr(wdt, "AsyncSessionLocal", _Factory(session))
    monkeypatch.setattr(wdt, "_artefact_exists", AsyncMock(return_value=True))
    await wdt._generate_for_tenant(uuid.uuid4(), datetime(2026, 10, 5, tzinfo=UTC), datetime(2026, 10, 11, tzinfo=UTC))
    assert session.added == [] and session.commits == 0


def test_the_model_default_is_an_allowed_status():
    assert ReportArtefact.__table__.c.status.default.arg in ALLOWED


def _status_literals():
    """Every string constant the application assigns as a ReportArtefact status: `ReportArtefact(status="x")` and `<something>.status = "x"` in a module that uses ReportArtefact."""
    found = []
    for path in (SERVICE / "app").rglob("*.py"):
        source = path.read_text(encoding="utf-8", errors="replace")
        if "ReportArtefact" not in source:
            continue
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "ReportArtefact":
                for kw in node.keywords:
                    if kw.arg == "status" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        found.append((str(path.relative_to(SERVICE)), kw.value.lineno, kw.value.value))
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "status" for t in node.targets) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                found.append((str(path.relative_to(SERVICE)), node.lineno, node.value.value))
    return found


def test_every_status_the_application_assigns_to_a_report_artefact_is_one_the_database_accepts():
    found = _status_literals()
    assert any(f[0].endswith("weekly_digest_task.py") for f in found), "the scan no longer sees the digest worker: it would pass vacuously"
    bad = [f for f in found if f[2] not in ALLOWED]
    assert not bad, f"statuses the database would refuse: {bad}"
