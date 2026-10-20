"""One client's posture page against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database; the role must be allowed to write every table)."""

import os
import uuid
from types import SimpleNamespace as NS

import pytest
from app.api.v1.endpoints import client_posture as ep
from app.db.rls import set_rls_context
from app.models.signin import IdentityMfaUser
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:8]
    ids = {k: uuid.uuid4() for k in ("msp", "client", "stranger")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, tid in ids.items():
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                {
                    "i": tid,
                    "n": f"po-{key}-{tag}",
                    "s": f"po-{key}-{tag}",
                    "p": ids["msp"] if key == "client" else None,
                    "r": "child" if key == "client" else "parent",
                },
            )
        for sev, status, ticketed in (
            ("critical", "new", False),
            ("high", "investigating", True),
            ("low", "new", False),
            ("critical", "resolved", False),
        ):
            enrichment = '{"tickets": [{"id": 1}]}' if ticketed else "{}"
            await c.execute(
                text(
                    "insert into alerts (id, tenant_id, title, severity, status, enrichment_data) "
                    "values (gen_random_uuid(), :t, 'x', :sev, :st, cast(:e as jsonb))"
                ),
                {"t": ids["client"], "sev": sev, "st": status, "e": enrichment},
            )
        for n, status in enumerate(("new", "investigating", "closed")):
            await c.execute(
                text("insert into cases (id, tenant_id, case_number, title, status) values (gen_random_uuid(), :t, :n, 'c', :s)"),
                {"t": ids["client"], "n": f"PO-{tag}-{n}", "s": status},
            )
    yield ids
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from cases where tenant_id = :t"), {"t": ids["client"]})
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def run(owner, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, owner)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def test_the_posture_counts_open_alerts_cases_and_second_factor_coverage(world):
    snap = uuid.uuid4()

    async def add_people(db):
        from app.db.rls_scope import acting_as_tenant

        async with acting_as_tenant(db, world["client"]):
            for uid, registered, admin in (("1", True, False), ("2", False, True), ("3", False, False)):
                db.add(
                    IdentityMfaUser(
                        tenant_id=world["client"],
                        source="cipp",
                        user_id=uid,
                        upn=f"{uid}@x.com",
                        enabled=True,
                        user_type="Member",
                        admin=admin,
                        licensed=True,
                        registered=registered,
                        ca_enforced=True,
                        snapshot_id=snap,
                    )
                )
            await db.flush()

    await run(world["msp"], add_people)
    user = NS(tenant_id=world["msp"])
    p = await run(world["msp"], lambda db: ep.client_posture(world["client"], user, db))
    assert p.client_id == world["client"] and p.client_name.startswith("po-client-")
    assert (p.alerts.open, p.alerts.critical, p.alerts.high, p.alerts.without_ticket) == (
        3,
        1,
        1,
        2,
    ), "the resolved one is not open; one open alert has a ticket"
    assert p.open_cases == 2, "the closed case is not open"
    assert p.identity is not None
    assert (p.identity.people, p.identity.with_mfa, p.identity.without_mfa, p.identity.admins_without_mfa) == (3, 1, 2, 1)
    assert p.devices.devices == 0


async def test_a_client_with_no_identity_data_says_so_and_a_stranger_is_not_found(world):
    user = NS(tenant_id=world["msp"])
    p = await run(world["msp"], lambda db: ep.client_posture(world["client"], user, db))
    assert p.identity is None
    with pytest.raises(HTTPException) as err:
        await run(world["msp"], lambda db: ep.client_posture(world["stranger"], user, db))
    assert err.value.status_code == 404
