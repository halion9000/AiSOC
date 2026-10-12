"""Lookups that happen BEFORE the tenant is known still work when fail-closed row-level security is switched on (step 4b of docs/security/rls-fail-closed-plan.md).

Four code paths find a row first and learn the tenant from it, on a plain session that has no tenant: API-key authentication (the key's hash), the ITSM webhook (the
token in the URL), the OAuth callback (the `state` nonce) and the public replay page (the slug). With migration 081's switch on, a tenant-less session sees nothing, so
each would silently fail for everyone: API keys would answer 401 for CORE, the agents service and every SDK user; webhooks 401; callbacks 400; public replays 404.
The isolation flows could not see any of this (they log in as users), which is how the first plan missed it. Each path now does its lookup in an explicit
`cross_tenant_reads` block and, where it goes on to act for a tenant, `adopt_tenant`s the validated one. These tests run the REAL functions on a real Postgres as the
restricted role with the switch ON, each beside a negative control, and check the failure paths too: a rejected lookup must not leave the session adopted or widened.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (`aisoc_app`), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API database; without
them the tests are skipped, and CI sets them (.github/workflows/postgres-tests.yml).
"""

import datetime as dt
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def _required_values(table, **given):
    values = {}
    for col in table.columns:
        if col.nullable or col.default is not None or col.server_default is not None or col.primary_key:
            continue
        kind = col.type
        if isinstance(kind, sa.String | sa.Text):
            values[col.name] = "x"
        elif "JSON" in type(kind).__name__:
            values[col.name] = json.dumps({})
        elif isinstance(kind, sa.Boolean):
            values[col.name] = False
        elif isinstance(kind, sa.Integer):
            values[col.name] = 0
        elif isinstance(kind, sa.DateTime):
            values[col.name] = dt.datetime.now(dt.UTC)
        else:
            values[col.name] = uuid.uuid4()
    values.update(given)
    return values


async def _insert(conn, table, **given):
    values = _required_values(table, **given)
    await conn.execute(text(f"insert into {table.name} ({', '.join(values)}) values ({', '.join(':' + k for k in values)})"), values)


@pytest.fixture
async def world():
    from app.api.v1.deps import hash_api_key
    from app.models.connector import Connector
    from app.models.inbox import TenantInboxToken
    from app.models.oauth import OAuthState
    from app.models.published_replay import PublishedReplay
    from app.models.tenant import ApiKey

    tag = uuid.uuid4().hex[:10]
    a, b = uuid.uuid4(), uuid.uuid4()
    w = {
        "a": a,
        "b": b,
        "tag": tag,
        "raw_key": f"aisoc_{tag}validkey",
        "raw_expired": f"aisoc_{tag}expiredkey",
        "raw_inactive": f"aisoc_{tag}inactivekey",
        "key_id": uuid.uuid4(),
        "expired_id": uuid.uuid4(),
        "slug": f"r{tag}x"[
            :12
        ].lower(),  # exactly 12 characters: the length `_unique_slug` mints, so it can be offered as a colliding candidate
        "inbox_token": f"tok-{tag}",
        "conn_a": uuid.uuid4(),
        "conn_b": uuid.uuid4(),
        "state": f"state-{tag}",
        "state_unused": f"state-unknown-{tag}",
    }
    owner = create_async_engine(PG_URL)
    on = create_async_engine(
        APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}}
    )  # as ALTER DATABASE ... SET does
    try:
        async with owner.begin() as conn:
            for key, name in ((a, "a"), (b, "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": key, "n": f"pre-{name}-{tag}", "s": f"pre-{name}-{tag}"},
                )
            await _insert(
                conn,
                ApiKey.__table__,
                id=w["key_id"],
                tenant_id=a,
                name="valid",
                key_prefix="aisoc_va",
                hashed_key=hash_api_key(w["raw_key"]),
                is_active=True,
            )
            await _insert(
                conn,
                ApiKey.__table__,
                id=w["expired_id"],
                tenant_id=a,
                name="expired",
                key_prefix="aisoc_ex",
                hashed_key=hash_api_key(w["raw_expired"]),
                is_active=True,
                expires_at=dt.datetime(2000, 1, 1, tzinfo=dt.UTC),
            )
            await _insert(
                conn,
                ApiKey.__table__,
                tenant_id=a,
                name="inactive",
                key_prefix="aisoc_in",
                hashed_key=hash_api_key(w["raw_inactive"]),
                is_active=False,
            )
            await _insert(
                conn,
                PublishedReplay.__table__,
                tenant_id=a,
                slug=w["slug"],
                title="a replay",
                snapshot=json.dumps({"events": []}),
                view_count=0,
            )
            await _insert(conn, TenantInboxToken.__table__, tenant_id=a, token=w["inbox_token"], template_id="itsm-inbound")
            await _insert(
                conn,
                Connector.__table__,
                id=w["conn_a"],
                tenant_id=a,
                name=f"pre-conn-a-{tag}",
                connector_type="jira",
                category="itsm",
                is_enabled=True,
            )
            await _insert(
                conn,
                Connector.__table__,
                id=w["conn_b"],
                tenant_id=b,
                name=f"pre-conn-b-{tag}",
                connector_type="jira",
                category="itsm",
                is_enabled=True,
            )
            await _insert(
                conn,
                OAuthState.__table__,
                tenant_id=a,
                state=w["state"],
                connector_type="jira",
                expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
            )
        w["owner"], w["factory"] = owner, async_sessionmaker(on, expire_on_commit=False)
        yield w
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})  # the foreign keys cascade
        await on.dispose()
        await owner.dispose()


async def owner_scalar(world, sql, **params):
    async with world["owner"].connect() as conn:
        return (await conn.execute(text(sql), params)).scalar_one()


async def count_visible(session, sql, **params):
    return (await session.execute(text(sql), params)).scalar_one()


# ---------------------------------------------------------------- the control


async def test_control_a_plain_session_with_the_switch_on_sees_none_of_the_rows_these_paths_look_up(world):
    async with world["factory"]() as session:
        assert await count_visible(session, "select count(*) from api_keys where tenant_id = :t", t=world["a"]) == 0
        assert await count_visible(session, "select count(*) from published_replays where slug = :s", s=world["slug"]) == 0
        assert await count_visible(session, "select count(*) from tenant_inbox_tokens where token = :t", t=world["inbox_token"]) == 0
        assert await count_visible(session, "select count(*) from oauth_states where state = :s", s=world["state"]) == 0
    assert (
        await owner_scalar(world, "select count(*) from api_keys where tenant_id = :t", t=world["a"]) == 3
    )  # the rows exist: only the plain session cannot see them


# ---------------------------------------------------------------- API keys


async def test_a_valid_api_key_resolves_to_its_tenant_and_last_used_is_bumped(world):
    from app.api.v1.deps import _resolve_api_key

    async with world["factory"]() as session:
        user = await _resolve_api_key(world["raw_key"], session)
        await session.commit()
    assert user.tenant_id == world["a"] and user.role == "api_service"
    assert await owner_scalar(world, "select last_used_at is not null from api_keys where id = :i", i=world["key_id"]) is True


async def test_an_unknown_expired_or_inactive_key_is_refused_and_an_expired_key_is_not_bumped(world):
    from app.api.v1.deps import _resolve_api_key

    async with world["factory"]() as session:
        for raw in (f"aisoc_{world['tag']}nosuchkey", world["raw_expired"], world["raw_inactive"]):
            with pytest.raises(HTTPException) as refused:
                await _resolve_api_key(raw, session)
            assert refused.value.status_code == 401
    assert await owner_scalar(world, "select last_used_at is null from api_keys where id = :i", i=world["expired_id"]) is True


async def test_resolving_a_key_does_not_leave_the_session_wider_than_it_was(world):
    from app.api.v1.deps import _resolve_api_key

    async with world["factory"]() as session:
        await _resolve_api_key(world["raw_key"], session)
        assert (
            await count_visible(session, "select count(*) from api_keys where tenant_id = :t", t=world["a"]) == 0
        ), "the bypass must end with the lookup"
        assert (await session.execute(text("select rls_fail_closed()"))).scalar_one() is True


# ---------------------------------------------------------------- public replay


async def test_a_published_replay_is_readable_without_any_tenant_and_its_view_count_is_bumped(world):
    from app.api.v1.endpoints.replay import get_public_replay

    async with world["factory"]() as session:
        replay = await get_public_replay(world["slug"], session)
    assert replay.slug == world["slug"] and replay.title == "a replay"
    assert await owner_scalar(world, "select view_count from published_replays where slug = :s", s=world["slug"]) == 1


async def test_an_unknown_replay_slug_is_a_404(world):
    from app.api.v1.endpoints.replay import get_public_replay

    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as missing:
            await get_public_replay(f"nope{world['tag']}"[:12], session)
    assert missing.value.status_code == 404


async def test_a_slug_that_another_tenant_owns_is_not_handed_out_again(world, monkeypatch):
    """`_unique_slug` runs in a request tagged with the PUBLISHER's tenant, but slugs are unique across all tenants."""
    from app.api.v1.endpoints import replay
    from app.db.rls_sessions import mark_tenant

    candidates = iter([world["slug"], "zz99yy88xx77"])
    monkeypatch.setattr(replay.secrets, "token_urlsafe", lambda _n: next(candidates))
    async with world["factory"]() as session:
        mark_tenant(session, world["b"])  # tenant B publishing: it cannot see tenant A's slug without the explicit bypass
        slug = await replay._unique_slug(session)  # noqa: SLF001
    assert slug == "zz99yy88xx77", "the first candidate is tenant A's slug: it must be skipped, not returned"


# ---------------------------------------------------------------- ITSM webhook


async def test_the_itsm_token_resolves_and_the_session_then_works_for_the_tokens_tenant(world):
    from app.api.v1.endpoints.inbox_itsm import _fetch_token_and_connector

    async with world["factory"]() as session:
        token_row, connector_row = await _fetch_token_and_connector(
            session, tenant_token=world["inbox_token"], connector_instance_id=world["conn_a"]
        )
        assert token_row.tenant_id == world["a"] and connector_row.id == world["conn_a"]
        seen = await count_visible(session, "select count(*) from connectors where id in (:a, :b)", a=world["conn_a"], b=world["conn_b"])
        assert seen == 1, "after the lookup the session is tenant A's: it sees its own connector and NOT tenant B's"
        await session.commit()
        assert (
            await count_visible(session, "select count(*) from connectors where id in (:a, :b)", a=world["conn_a"], b=world["conn_b"]) == 1
        )


async def test_a_connector_of_another_tenant_is_a_403_not_the_404_that_row_level_security_would_make_it(world):
    from app.api.v1.endpoints.inbox_itsm import _fetch_token_and_connector

    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as mismatch:
            await _fetch_token_and_connector(session, tenant_token=world["inbox_token"], connector_instance_id=world["conn_b"])
    assert mismatch.value.status_code == 403
    assert "different tenants" in str(mismatch.value.detail)


async def test_an_unknown_itsm_token_is_a_401_and_leaves_the_session_without_a_tenant(world):
    from app.api.v1.endpoints.inbox_itsm import _fetch_token_and_connector

    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as unknown:
            await _fetch_token_and_connector(session, tenant_token=f"tok-nosuch-{world['tag']}", connector_instance_id=world["conn_a"])
        assert unknown.value.status_code == 401
        assert (
            await count_visible(session, "select count(*) from connectors where id in (:a, :b)", a=world["conn_a"], b=world["conn_b"]) == 0
        ), "a rejected token adopts nothing"


# ---------------------------------------------------------------- OAuth callback


async def test_the_oauth_callback_finds_its_state_and_consumes_it_under_the_states_tenant(world):
    """The single-use DELETE is a tenant-scoped write: without adopting the state's tenant it would silently delete NOTHING and the state could be replayed."""
    from app.api.v1.endpoints.oauth import oauth_callback

    assert await owner_scalar(world, "select count(*) from oauth_states where state = :s", s=world["state"]) == 1
    async with world["factory"]() as session:
        response = await oauth_callback(session, code=None, state=world["state"], error="access_denied", error_description="no")
    assert response is not None
    assert (
        await owner_scalar(world, "select count(*) from oauth_states where state = :s", s=world["state"]) == 0
    ), "the state must be consumed"


async def test_an_unknown_oauth_state_is_a_400_and_adopts_nothing(world):
    from app.api.v1.endpoints.oauth import oauth_callback

    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as unknown:
            await oauth_callback(session, code=None, state=world["state_unused"], error=None, error_description=None)
        assert unknown.value.status_code == 400
        assert await count_visible(session, "select count(*) from connectors where id = :a", a=world["conn_a"]) == 0
    assert (
        await owner_scalar(world, "select count(*) from oauth_states where state = :s", s=world["state"]) == 1
    ), "an unknown state must not consume anyone else's"
