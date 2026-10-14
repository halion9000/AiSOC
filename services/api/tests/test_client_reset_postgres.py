"""Start over (``POST /mssp/clients/reset``) against a REAL Postgres, as the restricted role (`aisoc_app`) with the fail-closed row-level-security switch ON.

The mocked tests could not see what the database does when a client tenant is deleted: every table cascades from ``tenants``, but ``audit_log`` and
``investigation_events`` have triggers that refuse DELETE, so removing a tenant that owns one raised a database error the mocks never produced (a 500 in the app).
This runs the real endpoint function on a real database.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. audit_log is append-only, so the tenant that owns an audit row cannot be
cleaned up afterwards: the database must be disposable.
"""

import os
import uuid
from types import SimpleNamespace as NS

import pytest
from app.api.v1.endpoints import mssp_clients as mc
from app.db.rls import set_rls_context
from app.db.rls_hook import tag_session
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


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "plain", "worked", "audited")}
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            for key, tid in ids.items():
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {
                        "i": tid,
                        "n": f"rs-{key}-{tag}",
                        "s": f"rs-{key}-{tag}",
                        "p": None if key == "parent" else ids["parent"],
                        "r": "parent" if key == "parent" else "child",
                    },
                )
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            for key, status in (("plain", "new"), ("worked", "resolved"), ("audited", "new")):
                await conn.execute(
                    text("insert into alerts (id, tenant_id, title, severity, status) values (gen_random_uuid(), :t, 'x', 'low', :s)"),
                    {"t": ids[key], "s": status},
                )
            await conn.execute(
                text("insert into audit_log (id, tenant_id, action) values (gen_random_uuid(), :t, 'test')"), {"t": ids["audited"]}
            )
            await conn.execute(
                text(
                    "insert into client_aliases (id, tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored, match_source) "
                    "values (gen_random_uuid(), :p, 'huntress', '1', 'Plain', 'plain', :c, false, 'manual')"
                ),
                {"p": ids["parent"], "c": ids["plain"]},
            )
        yield {**ids, "owner": owner, "factory": async_sessionmaker(app, expire_on_commit=False)}
    finally:
        async with owner.connect() as conn:
            for key in ("plain", "worked", "parent"):
                try:
                    async with conn.begin():
                        await conn.execute(text("delete from tenants where id = :i"), {"i": ids[key]})
                except DBAPIError:
                    pass  # something still owns an audit row; the database is disposable
        await app.dispose()
        await owner.dispose()


async def test_reset_removes_plain_clients_and_keeps_ones_with_work_or_audit_records(world):
    user = NS(tenant_id=world["parent"], user_id=None)
    async with world["factory"]() as session:
        await tag_session(session, world["parent"])
        await set_rls_context(session, world["parent"])
        out = await mc.reset_clients(mc.ResetRequest(confirm=True), NS(headers={}, client=None, scope={}), user, session)
        await session.commit()

    assert out.removed == 1
    assert {k.name.split("-")[1]: k.reason for k in out.kept} == {
        "worked": "it has alerts someone worked on",
        "audited": "it has audit records",
    }
    async with world["owner"].connect() as conn:
        left = {
            r[0].split("-")[1]
            for r in (await conn.execute(text("select name from tenants where parent_tenant_id = :p"), {"p": world["parent"]})).all()
        }
        alias = (
            await conn.execute(text("select child_tenant_id from client_aliases where tenant_id = :p"), {"p": world["parent"]})
        ).scalar_one()
    assert left == {"worked", "audited"} and alias is None
