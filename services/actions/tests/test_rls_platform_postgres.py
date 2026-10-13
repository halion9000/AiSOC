"""The actions service keeps working with fail-closed row-level security switched ON (step 4b of docs/security/rls-fail-closed-plan.md).

The service has no tenant on a request: callers authenticate with a service token, an action is read and changed BY ID, and a submitted action is INSERTED for whatever tenant
its request names. With the API's fail-closed policies on (migration 081), a session that never set a tenant sees nothing and cannot insert, so without the platform session
(app/db.py) every action route would fail. These tests run the REAL store functions on a real Postgres as the restricted role with the switch ON, beside a negative control.

What they do NOT show: that fail-closed protects `response_actions` here. It does not: this service keeps the switch off for its own transactions (see `_PlatformSession`),
so tenant isolation for actions rests on its callers. A test that said otherwise would be wrong.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (`aisoc_app`), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API database (the actions
table comes from services/api/migrations/055_response_actions.sql); without them the tests are skipped.
"""

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


@pytest_asyncio.fixture
async def world():
    from app.db import make_session_factory

    tenant, other, tag = uuid.uuid4(), uuid.uuid4(), uuid.uuid4().hex[:8]
    owner = create_async_engine(PG_URL)
    on = create_async_engine(
        APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}}
    )  # as ALTER DATABASE ... SET does
    try:
        async with owner.begin() as conn:
            for key, name in ((tenant, "a"), (other, "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": key, "n": f"act-{name}-{tag}", "s": f"act-{name}-{tag}"},
                )
        yield {
            "tenant": tenant,
            "other": other,
            "owner": owner,
            "platform": make_session_factory(on),
            "plain": async_sessionmaker(on, expire_on_commit=False),
        }
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from response_actions where tenant_id in (:a, :b)"), {"a": tenant, "b": other})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": tenant, "b": other})
        await on.dispose()
        await owner.dispose()


def request_for(tenant):
    from app.models.action import ActionRequest, ActionType

    return ActionRequest(
        id=uuid.uuid4(), incident_id=uuid.uuid4(), tenant_id=tenant, action_type=list(ActionType)[0], target="host-1", rationale="rls test"
    )


async def create(db, request):
    from app.models.action import ActionStatus, BlastRadius
    from app.services import action_store

    return await action_store.create(db, request, status=ActionStatus.PENDING, blast_radius=list(BlastRadius)[0], gate_reason="test")


async def owner_count(world, action_id):
    async with world["owner"].connect() as conn:
        return (await conn.execute(text("select count(*) from response_actions where id = :i"), {"i": action_id})).scalar_one()


@pytest.mark.asyncio
async def test_control_a_plain_session_with_the_switch_on_cannot_store_an_action(world):
    async with world["plain"]() as db:
        assert (await db.execute(text("select rls_fail_closed()"))).scalar_one() is True
        await db.rollback()
        with pytest.raises(DBAPIError, match="row-level security"):
            await create(db, request_for(world["tenant"]))


@pytest.mark.asyncio
async def test_the_service_session_stores_reads_claims_and_lists_an_action_across_commits(world):
    from app.models.action import ActionStatus
    from app.services import action_store

    request = request_for(world["tenant"])
    async with world["platform"]() as db:
        record, created = await create(db, request)  # create() commits: everything below is a LATER transaction
        assert created is True and record["tenant_id"] == str(world["tenant"])
        assert (await action_store.get(db, request.id))["id"] == str(request.id)
        assert await action_store.claim(db, request.id, expected=ActionStatus.PENDING) is True
        assert [a["id"] for a in await action_store.list_actions(db, tenant_id=world["tenant"])] == [str(request.id)]
    assert await owner_count(world, request.id) == 1


@pytest.mark.asyncio
async def test_an_action_for_another_tenant_is_stored_by_the_same_session(world):
    """A platform service stores for whatever tenant the (authorized) caller names: the same session handles both tenants."""
    first, second = request_for(world["tenant"]), request_for(world["other"])
    async with world["platform"]() as db:
        await create(db, first)
        await create(db, second)
    assert await owner_count(world, first.id) == 1 and await owner_count(world, second.id) == 1


@pytest.mark.asyncio
async def test_a_plain_session_cannot_see_what_the_service_stored(world):
    request = request_for(world["tenant"])
    async with world["platform"]() as db:
        await create(db, request)
    async with world["plain"]() as db:
        assert (await db.execute(text("select count(*) from response_actions where id = :i"), {"i": request.id})).scalar_one() == 0
