"""Step 3 of docs/security/rls-fail-closed-plan.md, at the unit level: the tag, the listener, and where get_current_user tags.

The property that matters (the tenant is still in force after a commit) needs a real PostgreSQL and is in test_rls_session_tag_postgres.py.
"""

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1 import deps
from app.core.config import settings
from app.db import rls_hook

TENANT = uuid.uuid4()
HOME = uuid.uuid4()
TARGET = uuid.uuid4()


class FakeConnection:
    def __init__(self, dialect: str):
        self.dialect = SimpleNamespace(name=dialect)
        self.calls: list[tuple[str, dict]] = []

    def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setattr(settings, "AISOC_RLS_TAG_SESSIONS", True)


@pytest.fixture
def off(monkeypatch):
    monkeypatch.setattr(settings, "AISOC_RLS_TAG_SESSIONS", False)


def test_the_flag_defaults_to_off():
    assert type(settings).model_fields["AISOC_RLS_TAG_SESSIONS"].default is False


@pytest.mark.asyncio
async def test_with_the_flag_off_nothing_is_ever_tagged(off):
    session = SimpleNamespace(info={})
    await rls_hook.tag_session(session, TENANT)
    assert session.info == {}


@pytest.mark.asyncio
async def test_with_the_flag_on_the_session_carries_the_tenant_as_text(on):
    session = SimpleNamespace(info={})
    await rls_hook.tag_session(session, TENANT)
    assert session.info == {rls_hook.TAG: str(TENANT)}


@pytest.mark.asyncio
async def test_no_tenant_means_no_tag_even_with_the_flag_on(on):
    session = SimpleNamespace(info={})
    await rls_hook.tag_session(session, None)
    assert session.info == {}


def test_the_listener_reapplies_the_tenant_on_a_postgresql_connection():
    connection = FakeConnection("postgresql")
    rls_hook._after_begin(SimpleNamespace(info={rls_hook.TAG: str(TENANT)}), None, connection)
    assert len(connection.calls) == 1
    sql, params = connection.calls[0]
    assert "set_config('app.current_tenant_id'" in sql and "TRUE" in sql and params == {"t": str(TENANT)}


@pytest.mark.parametrize(
    ("dialect", "info"),
    [("sqlite", {rls_hook.TAG: str(TENANT)}), ("postgresql", {}), ("postgresql", {rls_hook.TAG: ""})],
    ids=["not postgresql", "no tag", "empty tag"],
)
def test_the_listener_sends_nothing_when_it_should_not(dialect, info):
    connection = FakeConnection(dialect)
    rls_hook._after_begin(SimpleNamespace(info=info), None, connection)
    assert connection.calls == []


def test_the_listener_is_installed_once_and_only_once():
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    rls_hook.install()
    rls_hook.install()
    assert event.contains(Session, "after_begin", rls_hook._after_begin)


# ── where get_current_user tags ──────────────────────────────────────────────────────────────────────────────────────────────────────


def _user():
    return deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=HOME, role="admin", email="x@example.com")


async def _authenticated(monkeypatch):
    async def fake(credentials, db):
        return _user()

    monkeypatch.setattr(deps, "_authenticate", fake)


def _request(method="GET", path="/api/v1/alerts", view_as=None):
    headers = {deps.VIEW_AS_HEADER: view_as} if view_as else {}
    return SimpleNamespace(headers=headers, method=method, url=SimpleNamespace(path=path), state=SimpleNamespace())


@pytest.mark.asyncio
async def test_a_plain_request_tags_the_session_with_the_callers_own_tenant(on, monkeypatch):
    await _authenticated(monkeypatch)
    db = SimpleNamespace(info={})
    user = await deps.get_current_user(object(), db, _request(), SimpleNamespace(headers={}))
    assert user.tenant_id == HOME and db.info[rls_hook.TAG] == str(HOME)


@pytest.mark.asyncio
async def test_a_view_as_request_that_is_not_granted_is_tagged_with_the_home_tenant(on, monkeypatch):
    await _authenticated(monkeypatch)

    async def not_granted(*args, **kwargs):
        return None

    monkeypatch.setattr(deps, "resolve_view_as", not_granted)
    db = SimpleNamespace(info={})
    user = await deps.get_current_user(object(), db, _request(view_as=str(TARGET)), SimpleNamespace(headers={}))
    assert user.tenant_id == HOME and db.info[rls_hook.TAG] == str(HOME)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_a_granted_view_as_request_is_tagged_with_the_VIEWED_tenant_and_only_after_the_audit_writes(on, monkeypatch, method):
    await _authenticated(monkeypatch)
    seen_tags = {}
    db = SimpleNamespace(info={})

    async def granted(*args, **kwargs):
        return SimpleNamespace(tenant_id=TARGET, access="full")

    async def record(session, *args, **kwargs):
        seen_tags["at_audit_write"] = session.info.get(rls_hook.TAG)

    monkeypatch.setattr(deps, "resolve_view_as", granted)
    monkeypatch.setattr(deps, "record_view", record)
    monkeypatch.setattr(deps, "record_act_as", record)
    user = await deps.get_current_user(object(), db, _request(method=method, view_as=str(TARGET)), SimpleNamespace(headers={}))
    assert user.tenant_id == TARGET and user.home_tenant_id == HOME
    assert db.info[rls_hook.TAG] == str(TARGET)
    assert (
        seen_tags["at_audit_write"] is None
    ), "the audit write must run BEFORE the tag exists, in its own explicit scope (acting_as_tenant)"


@pytest.mark.asyncio
async def test_with_the_flag_off_get_current_user_tags_nothing(off, monkeypatch):
    await _authenticated(monkeypatch)
    db = SimpleNamespace(info={})
    await deps.get_current_user(object(), db, _request(), SimpleNamespace(headers={}))
    assert db.info == {}


class _FakePostgresSession:
    def __init__(self, in_transaction: bool):
        self.info: dict = {}
        self._in = in_transaction
        self.executed: list[tuple[str, dict]] = []

    def in_transaction(self):
        return self._in

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    async def execute(self, statement, params=None):
        self.executed.append((str(statement), params or {}))


@pytest.mark.asyncio
async def test_a_session_already_inside_a_transaction_gets_the_tenant_applied_to_it_NOW(on):
    """`get_current_user` authenticates on the session first, so it is already in a transaction when it is tagged; the listener only runs at the
    next BEGIN, so without this the handler's first writes would have no tenant (measured against fail-closed policies)."""
    session = _FakePostgresSession(in_transaction=True)
    await rls_hook.tag_session(session, TENANT)
    assert session.info == {rls_hook.TAG: str(TENANT)}
    assert len(session.executed) == 1 and session.executed[0][1] == {"t": str(TENANT)} and "TRUE" in session.executed[0][0]


@pytest.mark.asyncio
async def test_a_session_not_yet_in_a_transaction_is_only_tagged_and_the_listener_does_the_rest(on):
    session = _FakePostgresSession(in_transaction=False)
    await rls_hook.tag_session(session, TENANT)
    assert session.info == {rls_hook.TAG: str(TENANT)} and session.executed == []


@pytest.mark.asyncio
async def test_with_the_flag_off_not_even_a_session_in_a_transaction_is_touched(off):
    session = _FakePostgresSession(in_transaction=True)
    await rls_hook.tag_session(session, TENANT)
    assert session.info == {} and session.executed == []
