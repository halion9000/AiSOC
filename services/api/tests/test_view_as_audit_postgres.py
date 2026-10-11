"""'View another tenant' against a REAL Postgres, as the restricted role: the `tenant:viewed` event must reach the VIEWED tenant's audit
chain in every session state the RLS plan will put it in.

Measured with the real emit_audit as `aisoc_app` (docs/security/rls-fail-closed-plan.md): with no tenant set the event is written and
chained; with the session tagged with the viewer's HOME tenant the insert is
rejected ("new row violates row-level security policy": neither the audit_log nor the grants policy has a WITH CHECK, so the USING
expression applies to writes), and the read of the chain head returns None, which reads
as "genesis" and would silently FORK the target's hash chain if only the insert were let through. `acting_as_tenant` gives the read and
the insert one scope; these tests keep it that way, and check the CHAIN, not just that a row exists.
Opt in as for test_mssp_resolver_cross_tenant_postgres.py: AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), a DISPOSABLE,
fully migrated API database.
UNLIKE that test, this one CANNOT CLEAN UP: audit_log is immutable (a trigger blocks DELETE and UPDATE, which also blocks the cascade from
deleting a tenant), so each run leaves its own uniquely named tenants, user and audit rows
behind. That is why the database must be disposable. Without the variables it is skipped; CI does not set them yet.
"""

import os
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def _required(table, **given):
    values = {}
    for col in table.columns:
        if col.nullable or col.default is not None or col.server_default is not None or col.primary_key:
            continue
        kind = col.type
        values[col.name] = (
            "x"
            if isinstance(kind, sa.String | sa.Text)
            else False
            if isinstance(kind, sa.Boolean)
            else 0
            if isinstance(kind, sa.Integer)
            else uuid.uuid4()
        )
    values.update(given)
    return values


@pytest.fixture
async def world():
    from app.models.tenant import User

    owner, app = create_async_engine(PG_URL), create_async_engine(APP_URL)
    tag = uuid.uuid4().hex[:8]
    home, target, viewer = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with owner.begin() as conn:
        for tid, name in ((home, "home"), (target, "target")):
            await conn.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                {"i": tid, "n": f"va-{name}-{tag}", "s": f"va-{name}-{tag}"},
            )
        values = _required(
            User.__table__,
            id=viewer,
            tenant_id=home,
            email=f"viewer-{tag}@example.com",
            username=f"viewer-{tag}",
            account_name=f"viewer-{tag}",
        )
        await conn.execute(text(f"insert into users ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)
    from types import SimpleNamespace

    user = SimpleNamespace(
        user_id=viewer, email=f"viewer-{tag}@example.com", role="admin", tenant_id=home, home_tenant_id=home, holds=lambda permission: False
    )
    try:
        yield {"home": home, "target": target, "user": user, "sessions": async_sessionmaker(app, expire_on_commit=False), "owner": owner}
    finally:
        await owner.dispose()
        await app.dispose()


async def _chain(world):
    async with world["owner"].connect() as conn:
        rows = (
            await conn.execute(
                text("select action, prev_hash, entry_hash from audit_log where tenant_id = :t order by created_at, id"),
                {"t": world["target"]},
            )
        ).all()
    return rows


def _assert_intact(rows):
    """Every row's prev_hash is the previous row's entry_hash, and only the first row has none: a fork or a second 'genesis' fails."""
    assert rows, "no audit rows in the target's chain"
    assert rows[0][1] is None
    for before, after in zip(rows, rows[1:], strict=False):
        assert after[1] == before[2], f"the chain is broken: {after[1]!r} does not follow {before[2]!r}"


async def _view(world, setting, *, undecorated=False):
    from app.services import view_as

    record = view_as.record_view.__wrapped__ if undecorated else view_as.record_view
    async with world["sessions"]() as db:
        if setting is not None:
            await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(setting)})
        return await record(db, world["user"], world["target"])


@pytest.mark.asyncio
async def test_negative_control_without_the_block_a_session_tagged_with_the_home_tenant_cannot_record_the_view(world):
    """What the hook would do to view-as today. If this stops failing, the tests below no longer prove anything."""
    with pytest.raises(Exception, match="row-level security"):
        await _view(world, world["home"], undecorated=True)


@pytest.mark.asyncio
async def test_with_no_tenant_set_the_view_is_recorded_in_the_targets_chain(world):
    assert await _view(world, None) is True
    rows = await _chain(world)
    assert [r[0] for r in rows] == ["tenant:viewed"]
    _assert_intact(rows)


@pytest.mark.asyncio
async def test_with_the_home_tenant_set_the_view_is_still_recorded_in_the_targets_chain(world):
    """The hook's state. Without acting_as_tenant the insert was rejected, and the chain read returned None."""
    assert await _view(world, world["home"]) is True
    rows = await _chain(world)
    assert [r[0] for r in rows] == ["tenant:viewed"]
    _assert_intact(rows)


@pytest.mark.asyncio
async def test_a_second_view_within_the_window_is_not_recorded_again_even_from_a_home_tagged_session(world):
    """The dedupe is a read of the TARGET's audit rows. Under the home tag it saw none and would have written a duplicate every time."""
    assert await _view(world, world["home"]) is True
    assert await _view(world, world["home"]) is False
    assert len(await _chain(world)) == 1


@pytest.mark.asyncio
async def test_the_chain_stays_intact_when_another_actors_event_follows_a_view_recorded_from_a_home_tagged_session(world):
    """The view is recorded in the hook's state; then someone else's event is written into the same tenant's chain. The second row must
    chain to the FIRST row's hash, not start a new chain."""
    from app.services.audit import emit_audit

    assert await _view(world, world["home"]) is True
    async with world["sessions"]() as db:
        await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(world["target"])})
        await emit_audit(db=db, tenant_id=world["target"], action="cases:create", resource="case", resource_id="1")
        await db.commit()
    rows = await _chain(world)
    assert [r[0] for r in rows] == ["tenant:viewed", "cases:create"]
    _assert_intact(rows)
    assert rows[1][1] == rows[0][2], "the second event chains to the view's hash"
