"""The tag keeps the tenant in force ACROSS TRANSACTIONS, on a REAL Postgres, as the restricted role (step 3 of docs/security/rls-fail-closed-plan.md).

The property: `set_config('app.current_tenant_id', ..., true)` lasts for ONE transaction, so after a handler's `commit()` the next statement runs with no
tenant. The listener in app/db/rls_hook.py re-applies the tag at every BEGIN. Opt in with AISOC_TEST_PG_URL and AISOC_TEST_PG_APP_URL as for the other
Postgres-backed tests (a disposable, migrated database); this test creates no rows, it only reads the session setting, and CI runs it
(.github/workflows/postgres-tests.yml, which fails if any of these is skipped).
"""

import os
import uuid

import pytest
from app.core.config import settings
from app.db import rls_hook
from app.db.rls_scope import acting_as_tenant, cross_tenant_reads
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(not (PG_URL and APP_URL), reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app)")

A, B = str(uuid.uuid4()), str(uuid.uuid4())
READ = text("SELECT coalesce(current_setting('app.current_tenant_id', TRUE), '')")


@pytest.fixture
async def session(monkeypatch):
    monkeypatch.setattr(settings, "AISOC_RLS_TAG_SESSIONS", True)
    engine = create_async_engine(APP_URL)
    async with async_sessionmaker(engine, expire_on_commit=False)() as s:
        yield s
    await engine.dispose()


async def current(s) -> str:
    return (await s.execute(READ)).scalar_one()


@pytest.mark.asyncio
async def test_the_role_under_test_is_the_restricted_one(session):
    row = (await session.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
    assert tuple(row) == (False, False), "RLS does not apply to a superuser or BYPASSRLS role: this test would prove nothing"


@pytest.mark.asyncio
async def test_a_tagged_session_has_its_tenant_in_the_FIRST_transaction_without_any_explicit_set(session):
    await rls_hook.tag_session(session, A)
    assert await current(session) == A


@pytest.mark.asyncio
async def test_a_tagged_session_still_has_its_tenant_after_a_commit(session):
    await rls_hook.tag_session(session, A)
    assert await current(session) == A
    await session.commit()
    assert await current(session) == A, "the tenant must survive the commit: this is the whole point of the hook"
    await session.rollback()
    assert await current(session) == A, "and a rollback"


@pytest.mark.asyncio
async def test_NEGATIVE_CONTROL_an_untagged_session_loses_its_tenant_at_the_commit(session):
    await session.execute(text("SELECT set_config('app.current_tenant_id', :t, TRUE)"), {"t": A})  # what get_tenant_db does today
    assert await current(session) == A
    await session.commit()
    assert await current(session) == "", "without the tag the SET LOCAL ends with the transaction (this is what the hook exists to fix)"


@pytest.mark.asyncio
async def test_cross_tenant_reads_clears_the_tenant_inside_and_restores_the_tag_for_later_transactions(session):
    await rls_hook.tag_session(session, A)
    async with cross_tenant_reads(session):
        assert await current(session) == ""
        await session.commit()  # a new transaction INSIDE the block must not re-apply the tenant
        assert await current(session) == ""
    assert session.info[rls_hook.TAG] == A
    assert await current(session) == A
    await session.commit()
    assert await current(session) == A


@pytest.mark.asyncio
async def test_acting_as_another_tenant_is_scoped_to_the_block_and_the_home_tag_comes_back(session):
    await rls_hook.tag_session(session, A)
    async with acting_as_tenant(session, uuid.UUID(B)):
        assert await current(session) == B
        await session.commit()
        assert await current(session) == B, "a commit inside the block (record_view commits) keeps the TARGET in force"
    assert session.info[rls_hook.TAG] == A
    assert await current(session) == A
    await session.commit()
    assert await current(session) == A


@pytest.mark.asyncio
async def test_with_the_flag_off_the_session_is_untagged_and_the_hook_does_nothing(session, monkeypatch):
    monkeypatch.setattr(settings, "AISOC_RLS_TAG_SESSIONS", False)
    await rls_hook.tag_session(session, A)
    assert session.info == {} and await current(session) == ""


@pytest.mark.asyncio
async def test_tagging_a_session_that_is_ALREADY_in_a_transaction_applies_the_tenant_to_that_transaction(session):
    """The case that failed 199 of 409 flow steps before it was handled: get_current_user queries on the session (so it has begun a transaction)
    and only THEN tags it; the listener has already run for that BEGIN."""
    await session.execute(text("SELECT 1"))  # the authentication query: the transaction begins here, with no tenant
    assert await current(session) == ""
    await rls_hook.tag_session(session, A)
    assert await current(session) == A, "the transaction in progress must get the tenant too, not only the NEXT one"
    await session.commit()
    assert await current(session) == A
