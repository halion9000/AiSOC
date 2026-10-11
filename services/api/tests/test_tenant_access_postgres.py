"""Tenant access management (tenants.py: list, grant, revoke) against a REAL Postgres, as the restricted role, with the RLS plan's hook
EMULATED.

A platform holder may manage ANY tenant's access and an MSP parent its children's (`may_manage_access`), so these routes read and write
the TARGET tenant's `tenant_access_grants` (an RLS table) and write an audit event into the TARGET's log, from a session whose own tenant
is the caller's. With the session tagged with the caller's home tenant (what step 3 of docs/security/rls-fail-closed-plan.md does) the
grant insert and the audit insert are rejected by the policies (neither has a WITH CHECK, so USING applies to writes).
`acting_as_argument("tenant_id")` runs each route as the tenant its path names.
The handlers commit, and on a race they roll back and re-query, and the tenant setting is TRANSACTION-local: it survives into the next
transaction only through the hook. So this test registers an `after_begin` listener that does what the hook will (re-apply the session's
tag at every transaction), and runs the routes in both session states: no tenant set (today) and tagged with the caller's home tenant (the
hook).
Opt in as for test_view_as_audit_postgres.py: AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), a DISPOSABLE, fully
migrated API database. It CANNOT CLEAN UP (audit_log is immutable, which also blocks the cascade from deleting a tenant), so each run
leaves uniquely named tenants, users and audit rows behind. Skipped without the variables; CI does not set them yet.
"""

import os
import uuid
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

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


def _apply_tag(session, transaction, connection):
    """The step-3 hook, emulated: re-apply the session's tag at the start of EVERY transaction."""
    tag = session.info.get("rls_tenant_id")
    if tag:
        connection.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": tag})


@pytest.fixture
async def world():
    from app.models.tenant import User

    owner, app = create_async_engine(PG_URL), create_async_engine(APP_URL)
    tag = uuid.uuid4().hex[:8]
    parent, child, manager, grantee = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with owner.begin() as conn:
        await conn.execute(
            text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
            {"i": parent, "n": f"ta-parent-{tag}", "s": f"ta-parent-{tag}"},
        )
        await conn.execute(
            text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, :p)"),
            {"i": child, "n": f"ta-child-{tag}", "s": f"ta-child-{tag}", "p": parent},
        )
        for uid, name in ((manager, "manager"), (grantee, "grantee")):
            values = _required(
                User.__table__,
                id=uid,
                tenant_id=parent,
                email=f"{name}-{tag}@example.com",
                username=f"{name}-{tag}",
                account_name=f"{name}-{tag}",
            )
            await conn.execute(text(f"insert into users ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)
    caller = SimpleNamespace(
        user_id=manager,
        email=f"manager-{tag}@example.com",
        role="admin",
        tenant_id=parent,
        home_tenant_id=parent,
        holds=lambda permission: permission == "users:write",
    )
    event.listen(Session, "after_begin", _apply_tag)
    try:
        yield {
            "parent": parent,
            "child": child,
            "caller": caller,
            "grantee_name": f"grantee-{tag}",
            "grantee_id": grantee,
            "sessions": async_sessionmaker(app, expire_on_commit=False),
            "owner": owner,
        }
    finally:
        event.remove(Session, "after_begin", _apply_tag)
        await owner.dispose()
        await app.dispose()


async def _grant_rows(world):
    async with world["owner"].connect() as conn:
        return (
            await conn.execute(
                text("select access from tenant_access_grants where tenant_id = :t and user_id = :u"),
                {"t": world["child"], "u": world["grantee_id"]},
            )
        ).all()


async def _chain(world):
    async with world["owner"].connect() as conn:
        return (
            await conn.execute(
                text("select action, prev_hash, entry_hash from audit_log where tenant_id = :t order by created_at, id"),
                {"t": world["child"]},
            )
        ).all()


def _assert_intact(rows):
    assert rows and rows[0][1] is None
    for before, after in zip(rows, rows[1:], strict=False):
        assert after[1] == before[2], f"the chain is broken: {after[1]!r} does not follow {before[2]!r}"


async def _session(world, state):
    db = world["sessions"]()
    db = await db.__aenter__()
    if state == "hook":  # the caller's session as the hook will leave it: tagged with the HOME tenant
        db.info["rls_tenant_id"] = str(world["parent"])
        await db.execute(text("select set_config('app.current_tenant_id', :t, true)"), {"t": str(world["parent"])})
    return db


STATES = ["none", "hook"]


@pytest.mark.asyncio
async def test_negative_control_without_the_decorator_a_home_tagged_session_cannot_grant_access_to_the_child(world):
    from app.api.v1.endpoints import tenants

    db = await _session(world, "hook")
    try:
        with pytest.raises(Exception, match="row-level security"):
            await tenants.grant_tenant_access.__wrapped__(
                tenant_id=world["child"], account_name=world["grantee_name"], current_user=world["caller"], db=db
            )
    finally:
        await db.rollback()
        await db.close()
    assert await _grant_rows(world) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_grant_writes_the_grant_and_a_chained_audit_event_into_the_child(world, state):
    from app.api.v1.endpoints import tenants

    db = await _session(world, state)
    try:
        response = await tenants.grant_tenant_access(
            tenant_id=world["child"], account_name=world["grantee_name"], current_user=world["caller"], db=db
        )
    finally:
        await db.close()
    assert response.access == "view" and response.tenant_id == world["child"]
    assert [r[0] for r in await _grant_rows(world)] == ["view"]
    rows = await _chain(world)
    assert [r[0] for r in rows] == ["tenant:access_granted"]
    _assert_intact(rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_changing_the_level_writes_a_second_event_that_chains_to_the_first(world, state):
    from app.api.v1.endpoints import tenants
    from app.api.v1.endpoints.tenants import GrantAccessRequest

    for level in ("view", "full"):
        db = await _session(world, state)
        try:
            await tenants.grant_tenant_access(
                tenant_id=world["child"],
                account_name=world["grantee_name"],
                current_user=world["caller"],
                db=db,
                body=GrantAccessRequest(access=level),
            )
        finally:
            await db.close()
    assert [r[0] for r in await _grant_rows(world)] == ["full"]
    rows = await _chain(world)
    assert [r[0] for r in rows] == ["tenant:access_granted", "tenant:access_changed"]
    _assert_intact(rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_list_shows_the_grant_the_children_grant_table_holds(world, state):
    """Under the home tag the read of the CHILD's grants saw nothing: a manager would see an empty list of the people who can view their
    own tenant."""
    from app.api.v1.endpoints import tenants

    db = await _session(world, "none")
    try:
        await tenants.grant_tenant_access(tenant_id=world["child"], account_name=world["grantee_name"], current_user=world["caller"], db=db)
    finally:
        await db.close()
    db = await _session(world, state)
    try:
        listed = await tenants.list_tenant_access(tenant_id=world["child"], current_user=world["caller"], db=db)
    finally:
        await db.close()
    assert [g.account_name for g in listed] == [world["grantee_name"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("state", STATES)
async def test_revoke_removes_the_grant_and_records_it_in_the_childs_chain(world, state):
    from app.api.v1.endpoints import tenants

    db = await _session(world, "none")
    try:
        await tenants.grant_tenant_access(tenant_id=world["child"], account_name=world["grantee_name"], current_user=world["caller"], db=db)
    finally:
        await db.close()
    db = await _session(world, state)
    try:
        await tenants.revoke_tenant_access(
            tenant_id=world["child"], account_name=world["grantee_name"], current_user=world["caller"], db=db
        )
    finally:
        await db.close()
    assert await _grant_rows(world) == []
    rows = await _chain(world)
    assert len(rows) == 2 and rows[0][0] == "tenant:access_granted"
    _assert_intact(rows)
