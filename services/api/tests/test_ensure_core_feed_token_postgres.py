"""The CORE feed token (``ensure_core_feed_token``) against a REAL Postgres, as the restricted role (`aisoc_app`) with the fail-closed row-level-security switch ON.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The two tenants the fixture creates (and their tokens) are
deleted afterwards.
"""

import os
import uuid

import pytest
from app.scripts.ensure_core_feed_token import LABEL, TEMPLATE_ID, ensure_token
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    a, b = uuid.uuid4(), uuid.uuid4()
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool)
    try:
        async with owner.begin() as conn:
            for tid, key in ((a, "a"), (b, "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": tid, "n": f"ft-{key}-{tag}", "s": f"ft-{key}-{tag}"},
                )
        yield {"tag": tag, "a": a, "b": b, "owner": owner, "app": app}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from tenant_inbox_tokens where tenant_id in (:a, :b)"), {"a": a, "b": b})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})
        await app.dispose()
        await owner.dispose()


async def _ensure(world, tenant, candidate):
    """Run exactly as main() does: a session as the restricted role, switch ON, one transaction, committed."""
    async with AsyncSession(world["app"]) as session:
        await session.execute(text("select set_config('app.rls_fail_closed', 'on', false)"))
        result = await ensure_token(session, tenant, candidate)
        await session.commit()
    return result


async def _rows(world, tenant):
    async with world["owner"].connect() as conn:
        res = await conn.execute(
            text("select token, template_id, label, revoked_at from tenant_inbox_tokens where tenant_id = :t order by created_at"),
            {"t": tenant},
        )
        return res.all()


async def test_first_call_creates_the_token_with_the_generic_template_and_label(world):
    token, created = await _ensure(world, world["a"], f"aitnb_{world['tag']}_one")
    assert created is True and token == f"aitnb_{world['tag']}_one"
    rows = await _rows(world, world["a"])
    assert [(r.token, r.template_id, r.label, r.revoked_at) for r in rows] == [(token, TEMPLATE_ID, LABEL, None)]


async def test_second_call_returns_the_same_token_and_creates_nothing(world):
    first, _ = await _ensure(world, world["a"], f"aitnb_{world['tag']}_one")
    second, created = await _ensure(world, world["a"], f"aitnb_{world['tag']}_two")
    assert created is False and second == first, "running the step on every launch must not mint a new token each time"
    assert len(await _rows(world, world["a"])) == 1


async def test_a_revoked_token_is_not_reused(world):
    first, _ = await _ensure(world, world["a"], f"aitnb_{world['tag']}_one")
    async with world["owner"].begin() as conn:
        await conn.execute(text("update tenant_inbox_tokens set revoked_at = now() where token = :t"), {"t": first})
    second, created = await _ensure(world, world["a"], f"aitnb_{world['tag']}_two")
    assert created is True and second == f"aitnb_{world['tag']}_two", "a revoked token is rejected by ingest, so a new one must be issued"


async def test_each_tenant_gets_its_own_token_and_never_sees_another(world):
    a, _ = await _ensure(world, world["a"], f"aitnb_{world['tag']}_a")
    b, created = await _ensure(world, world["b"], f"aitnb_{world['tag']}_b")
    assert created is True and a != b
    assert await _ensure(world, world["a"], "unused-a") == (a, False)
    assert await _ensure(world, world["b"], "unused-b") == (b, False)


async def test_other_labels_on_the_same_tenant_are_left_alone(world):
    async with world["owner"].begin() as conn:
        await conn.execute(
            text("insert into tenant_inbox_tokens (token, tenant_id, template_id, label) values (:k, :t, :tpl, 'someone-elses')"),
            {"k": f"aitnb_{world['tag']}_other", "t": world["a"], "tpl": TEMPLATE_ID},
        )
    token, created = await _ensure(world, world["a"], f"aitnb_{world['tag']}_mine")
    assert (
        created is True and token == f"aitnb_{world['tag']}_mine"
    ), "a token an operator made for something else must not be picked up as the CORE feed"
