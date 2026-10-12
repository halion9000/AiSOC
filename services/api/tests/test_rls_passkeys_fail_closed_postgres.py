"""The passkey SIGN-IN flow works with fail-closed row-level security switched on (step 4b of docs/security/rls-fail-closed-plan.md).

Sign-in has no session, so no tenant, yet it reads and writes tenant-scoped rows: `authenticate/begin` lists the user's credentials and stores a challenge (tagged with the
user's tenant, or with none when the sign-in is usernameless), and `authenticate/finish` consumes that challenge by its secret value and finds the credential by its id.
With migration 081's switch on, a tenant-less session sees none of it, and worse, an UPDATE that row-level security filters out does not even raise: the challenge would
be silently left unconsumed. The flow now finds rows in explicit `cross_tenant_reads` blocks and works for the tenant it learns (`adopt_tenant`).

`finish` is driven far enough that the KIND of failure shows how far it got: a 404 'Unknown or revoked passkey' means the challenge was consumed but the credential was not
found; a 401 'Passkey verification failed' means it found both and reached the cryptographic check (a real assertion needs a real authenticator, which a test cannot have).

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (`aisoc_app`), both postgresql+asyncpg:// URLs for a DISPOSABLE, fully migrated API database; without them
the tests are skipped, and CI sets them (.github/workflows/postgres-tests.yml).
"""

import base64
import datetime as dt
import os
import uuid

import pytest
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


def b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    a, b, user_a, user_b = (uuid.uuid4() for _ in range(4))
    w = {
        "a": a,
        "b": b,
        "user_a": user_a,
        "tag": tag,
        "login": f"pk-a-{tag}",
        "cred_a": b64(f"cred-a-{tag}"),
        "cred_b": b64(f"cred-b-{tag}"),
        "chal_a": b64(f"chal-a-{tag}"),
        "chal_none": b64(f"chal-none-{tag}"),
        "chal_unknown_cred": b64(f"chal-unk-{tag}"),
        "chal_known_cred": b64(f"chal-known-{tag}"),
        "chal_none_cred": b64(f"chal-none-cred-{tag}"),
    }
    owner = create_async_engine(PG_URL)
    on = create_async_engine(
        APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}}
    )  # as ALTER DATABASE ... SET does
    future = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    try:
        async with owner.begin() as conn:
            for key, name in ((a, "a"), (b, "b")):
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id) values (:i, :n, :s, null)"),
                    {"i": key, "n": f"pk-{name}-{tag}", "s": f"pk-{name}-{tag}"},
                )
            for uid, tid, name in ((user_a, a, w["login"]), (user_b, b, f"pk-b-{tag}")):
                await conn.execute(
                    text(
                        "insert into users (id, tenant_id, email, username, account_name, hashed_password, role, is_active) values (:i, :t, :e, :u, :u, 'x', 'analyst', true)"
                    ),
                    {"i": uid, "t": tid, "e": f"{name}@example.com", "u": name},
                )
            for tid, uid, cred in ((a, user_a, w["cred_a"]), (b, user_b, w["cred_b"])):
                await conn.execute(
                    text(
                        "insert into passkey_credentials (id, tenant_id, user_id, credential_id, public_key, device_name) values (:i, :t, :u, :c, 'cHVibGlj', 'test key')"
                    ),
                    {"i": uuid.uuid4(), "t": tid, "u": uid, "c": cred},
                )
            for tenant, user, chal in (
                (a, user_a, w["chal_a"]),
                (None, None, w["chal_none"]),
                (a, user_a, w["chal_unknown_cred"]),
                (a, user_a, w["chal_known_cred"]),
                (None, None, w["chal_none_cred"]),
            ):
                await conn.execute(
                    text(
                        "insert into passkey_challenges (id, purpose, challenge, tenant_id, user_id, rp_id, expires_at) values (:i, 'authenticate', :c, :t, :u, 'localhost', :e)"
                    ),
                    {"i": uuid.uuid4(), "c": chal, "t": tenant, "u": user, "e": future},
                )
        w["owner"], w["factory"] = owner, async_sessionmaker(on, expire_on_commit=False)
        yield w
    finally:
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "delete from passkey_challenges where challenge in (select challenge from passkey_challenges where rp_id = 'localhost' and tenant_id in (:a, :b) or user_id = :u)"
                ),
                {"a": a, "b": b, "u": user_a},
            )
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})  # users and credentials cascade
        await on.dispose()
        await owner.dispose()


async def owner_scalar(world, sql, **params):
    async with world["owner"].connect() as conn:
        return (await conn.execute(text(sql), params)).scalar_one()


async def visible_credentials(session, world):
    return (
        await session.execute(
            text("select count(*) from passkey_credentials where credential_id in (:a, :b)"), {"a": world["cred_a"], "b": world["cred_b"]}
        )
    ).scalar_one()


async def test_control_a_plain_session_with_the_switch_on_sees_no_credentials(world):
    async with world["factory"]() as session:
        assert await visible_credentials(session, world) == 0
    assert (
        await owner_scalar(world, "select count(*) from passkey_credentials where tenant_id in (:a, :b)", a=world["a"], b=world["b"]) == 2
    )


async def test_begin_for_a_known_user_lists_that_users_credentials_and_stores_the_challenge_for_their_tenant(world):
    from app.api.v1.endpoints.passkeys import AuthenticateBeginRequest, passkey_authenticate_begin

    async with world["factory"]() as session:
        result = await passkey_authenticate_begin(AuthenticateBeginRequest(identifier=world["login"]), session)
    allowed = result["publicKey"].get("allowCredentials") or []
    assert len(allowed) == 1, "the user's credential must be listed: without the tenant it would be invisible and the list silently empty"
    assert await owner_scalar(world, "select tenant_id from passkey_challenges where challenge = :c", c=result["challenge"]) == world["a"]


@pytest.mark.parametrize("identifier", [None, "nobody-by-that-name"])
async def test_begin_without_a_known_user_stores_a_challenge_with_no_tenant_and_lists_no_credentials(world, identifier):
    from app.api.v1.endpoints.passkeys import AuthenticateBeginRequest, passkey_authenticate_begin

    async with world["factory"]() as session:
        result = await passkey_authenticate_begin(AuthenticateBeginRequest(identifier=identifier), session)
    assert not (result["publicKey"].get("allowCredentials") or [])
    assert await owner_scalar(world, "select tenant_id is null from passkey_challenges where challenge = :c", c=result["challenge"]) is True


async def test_consuming_a_users_challenge_marks_it_consumed_and_the_session_then_works_for_that_tenant(world):
    from app.api.v1.endpoints.passkeys import _consume_challenge

    async with world["factory"]() as session:
        row = await _consume_challenge(session, encoded=world["chal_a"], purpose="authenticate", pre_session=True)
        assert row.consumed_at is not None
        assert (
            await visible_credentials(session, world) == 1
        ), "after consuming tenant A's challenge the session is tenant A's: it sees A's credential and not B's"
    assert (
        await owner_scalar(world, "select consumed_at is not null from passkey_challenges where challenge = :c", c=world["chal_a"]) is True
    ), "the UPDATE must really have happened"


async def test_consuming_a_usernameless_challenge_works_and_adopts_no_tenant(world):
    from app.api.v1.endpoints.passkeys import _consume_challenge

    async with world["factory"]() as session:
        await _consume_challenge(session, encoded=world["chal_none"], purpose="authenticate", pre_session=True)
        assert await visible_credentials(session, world) == 0
    assert (
        await owner_scalar(world, "select consumed_at is not null from passkey_challenges where challenge = :c", c=world["chal_none"])
        is True
    )


async def test_the_default_consumption_for_authenticated_flows_cannot_read_a_tenants_challenge_it_has_no_tenant_for(world):
    """The opt-in is the point: the registration flow must not gain a cross-tenant read."""
    from app.api.v1.endpoints.passkeys import _consume_challenge

    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as refused:
            await _consume_challenge(session, encoded=world["chal_a"], purpose="authenticate")
    assert refused.value.status_code == 400


async def test_finish_with_an_unknown_credential_consumes_the_challenge_then_answers_404(world):
    from app.api.v1.endpoints.passkeys import FinishRequest, passkey_authenticate_finish

    body = FinishRequest(challenge=world["chal_unknown_cred"], credential={"id": b64(f"no-such-credential-{world['tag']}")})
    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as unknown:
            await passkey_authenticate_finish(body, session)
    assert unknown.value.status_code == 404 and "Unknown or revoked passkey" in str(unknown.value.detail)
    assert (
        await owner_scalar(
            world, "select consumed_at is not null from passkey_challenges where challenge = :c", c=world["chal_unknown_cred"]
        )
        is True
    )


async def test_finish_with_a_known_credential_reaches_the_cryptographic_check(world):
    from app.api.v1.endpoints.passkeys import FinishRequest, passkey_authenticate_finish

    body = FinishRequest(challenge=world["chal_known_cred"], credential={"id": world["cred_a"], "response": {}})
    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as failed:
            await passkey_authenticate_finish(body, session)
    assert (
        failed.value.status_code == 401 and "verification failed" in str(failed.value.detail).lower()
    ), "found the challenge AND the credential, then failed on the (fake) assertion"


async def test_a_usernameless_finish_adopts_the_credentials_tenant_before_anything_is_written(world):
    """With no tenant on the challenge the CREDENTIAL is what reveals the tenant. If the session did not adopt it, the later write of the credential's sign_count (and the
    user's last_login) would be filtered out by row-level security without an error. It must be adopted by the time verification runs, which fails here (no real authenticator)."""
    from app.api.v1.endpoints.passkeys import FinishRequest, passkey_authenticate_finish

    body = FinishRequest(challenge=world["chal_none_cred"], credential={"id": world["cred_a"], "response": {}})
    async with world["factory"]() as session:
        with pytest.raises(HTTPException) as failed:
            await passkey_authenticate_finish(body, session)
        assert failed.value.status_code == 401
        assert await visible_credentials(session, world) == 1, "the session must be tenant A's by now: it sees A's credential and not B's"
