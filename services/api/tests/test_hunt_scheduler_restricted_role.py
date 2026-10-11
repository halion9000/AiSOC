"""The hunt scheduler must not depend on bypassing row-level security.

`run_once` used to begin with `SET LOCAL row_security = off`. That only bypasses RLS for a superuser, the table owner or a BYPASSRLS role.
For the ordinary restricted role (`aisoc_app`: not a superuser, no BYPASSRLS; docker-compose.rls.yml runs `actions` and `agents` as it, and
the API can be pointed at it by hand) the very next SELECT FAILED with
"query would be affected by row-level security policy", so scheduled hunts silently never ran whenever the API connected that way (latent in
the shipped config: the overlay does not switch the API yet). Verified on a real Postgres (Docker is not available where the suite runs, so
the behaviour is pinned here through what the sweep ASKS the database to do):
  as aisoc_app    the real run_once() raised ProgrammingError: query would be affected by row-level security policy for table
  "aisoc_saved_hunts"
  as the superuser the same call returned 0.
"""

import inspect
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.workers import hunt_scheduler

APP = Path(hunt_scheduler.__file__).resolve().parents[1]


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: self._rows)


class _RecordingDB:
    """Records every statement the sweep issues, as text; answers the one SELECT with the hunts it was given."""

    def __init__(self, hunts):
        self.hunts, self.statements, self.committed = hunts, [], 0

    async def execute(self, statement, params=None):
        self.statements.append((str(statement), dict(params or {})))
        return _Result(self.hunts)

    async def commit(self):
        self.committed += 1

    async def close(self):
        return None


def _hunt(tenant):
    return SimpleNamespace(id=uuid.uuid4(), tenant_id=tenant, schedule="* * * * *", last_run_at=None)


async def _sweep(hunts, monkeypatch):
    monkeypatch.setattr(hunt_scheduler, "_is_due", lambda hunt, now: True)
    calls = []

    async def runner(db, hunt):
        calls.append(("run", hunt.tenant_id, [p.get("t") for s, p in db.statements if "set_config" in s][-1:]))
        return 1

    async def callback(db, hunt, hits):
        return None

    db = _RecordingDB(hunts)
    fired = await hunt_scheduler.run_once(db=db, now=datetime(2026, 10, 11, tzinfo=UTC), executor=runner, hit_callback=callback)
    return fired, db, calls


@pytest.mark.asyncio
async def test_the_sweep_never_asks_the_database_to_switch_row_security_off(monkeypatch):
    a, b = uuid.uuid4(), uuid.uuid4()
    fired, db, _ = await _sweep([_hunt(a), _hunt(b)], monkeypatch)
    assert fired == 2
    assert not [s for s, _ in db.statements if "row_security" in s.lower()], db.statements


@pytest.mark.asyncio
async def test_each_hunt_is_run_under_its_own_tenant_not_the_previous_ones(monkeypatch):
    a, b = uuid.uuid4(), uuid.uuid4()
    fired, db, calls = await _sweep([_hunt(a), _hunt(b)], monkeypatch)
    assert [c[1] for c in calls] == [a, b]
    assert [c[2] for c in calls] == [[str(a)], [str(b)]], "the tenant must be bound to the hunt being run, before it runs"
    kinds = [
        "select" if s.lstrip().upper().startswith("SELECT") and "set_config" not in s else "set_config" if "set_config" in s else "update"
        for s, _ in db.statements
    ]
    assert kinds[0] == "select" and kinds.count("set_config") == 2 and kinds.count("update") == 2


@pytest.mark.asyncio
async def test_the_sweep_still_reads_every_tenants_hunts_in_one_query_and_commits_once(monkeypatch):
    fired, db, _ = await _sweep([_hunt(uuid.uuid4()), _hunt(uuid.uuid4()), _hunt(uuid.uuid4())], monkeypatch)
    selects = [s for s, _ in db.statements if s.lstrip().upper().startswith("SELECT") and "set_config" not in s]
    assert len(selects) == 1 and fired == 3 and db.committed == 1
    assert (
        "tenant_id" not in selects[0].lower().split("where", 1)[1]
    ), "the sweep must not filter by one tenant: it is cross-tenant by design"


@pytest.mark.asyncio
async def test_with_no_hunts_nothing_is_written_and_nothing_is_committed(monkeypatch):
    fired, db, _ = await _sweep([], monkeypatch)
    assert fired == 0 and db.committed == 0 and len(db.statements) == 1


def test_no_module_in_the_api_switches_row_security_off():
    """A guard across the whole API package: `row_security = off` works for a superuser and breaks the restricted role the hardened
    deployment uses. (Comments that explain why are allowed; statements are not.)"""
    offenders = []
    for path in APP.rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r"row_security\s*(=|TO)\s*(off|false|0)", code, re.I) or re.search(r"SET\s+(LOCAL\s+)?row_security", code, re.I):
                offenders.append(f"{path.relative_to(APP)}:{number}: {line.strip()[:90]}")
    assert not offenders, offenders


def test_the_scheduler_source_explains_why_it_does_not_bypass_rls():
    source = inspect.getsource(hunt_scheduler)
    assert "BYPASSRLS" in source and "aisoc_app" in source and "row_security" in source.split("This used to start with")[1][:40]
