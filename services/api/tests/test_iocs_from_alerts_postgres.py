"""Threat Intel indicators recorded from alerts, against a REAL Postgres as the restricted role (`aisoc_app`) with fail-closed row-level security ON.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. The database must be disposable.
"""

import os
import uuid
from datetime import UTC, datetime

import pytest
from app.db.rls import set_rls_context
from app.db.rls_hook import tag_session
from app.services import iocs_from_alerts as ifa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)
SHA = "c" * 64


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "child", "other")}
    owner = create_async_engine(PG_URL)
    app = create_async_engine(APP_URL, poolclass=NullPool, connect_args={"server_settings": {"app.rls_fail_closed": "on"}})
    try:
        async with owner.begin() as conn:
            for key, tid in ids.items():
                await conn.execute(
                    text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                    {
                        "i": tid,
                        "n": f"ioc-{key}-{tag}",
                        "s": f"ioc-{key}-{tag}",
                        "p": ids["parent"] if key == "child" else None,
                        "r": "child" if key == "child" else "parent",
                    },
                )
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            rows = [  # tenant, status, ips, raw_event, age (days)
                ("child", "new", ["8.8.8.8", "10.0.0.5"], f'{{"source": "huntress", "sha256": "{SHA}"}}', 1),
                ("child", "new", ["8.8.8.8"], '{"source": "petra"}', 2),
                ("child", "fp", ["1.1.1.1"], '{"source": "huntress"}', 1),
                ("child", "new", ["9.9.9.9"], '{"source": "huntress"}', 30),
                ("other", "new", ["4.4.4.4"], '{"source": "huntress"}', 1),
            ]
            for who, st, ips, raw, age in rows:
                await conn.execute(
                    text(
                        "insert into alerts (id, tenant_id, title, severity, status, affected_ips, raw_event, created_at, event_time, first_seen, last_seen) "
                        "values (:id, :t, 'a', 'high', :st, cast(:ips as jsonb), cast(:raw as jsonb), now() - make_interval(days => :age), now(), now(), now())"
                    ),
                    {"id": uuid.uuid4(), "t": ids[who], "st": st, "ips": __import__("json").dumps(ips), "raw": raw, "age": age},
                )
        yield {**ids, "owner": owner, "factory": async_sessionmaker(app, expire_on_commit=False)}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from threat_intel_iocs where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from alerts where tenant_id = any(:t)"), {"t": list(ids.values())})
            await conn.execute(text("delete from tenants where id = any(:t)"), {"t": [ids["child"], ids["other"], ids["parent"]]})
        await app.dispose()
        await owner.dispose()


async def _run(world):
    async with world["factory"]() as session:
        await tag_session(session, world["parent"])
        await set_rls_context(session, world["parent"])
        made = await ifa.sync_children(session, world["parent"], now=datetime.now(UTC))
        await session.commit()
    return made


async def _iocs(world, tenant):
    async with world["owner"].connect() as conn:
        await conn.execute(text("select set_config('app.rls_fail_closed', 'off', false)"))
        return (
            await conn.execute(
                text(
                    "select ioc_type, value, source, tags, array_length(linked_alerts, 1), severity from threat_intel_iocs where tenant_id = :t order by value"
                ),
                {"t": tenant},
            )
        ).all()


async def test_records_public_ips_and_hashes_once_in_the_right_tenant(world):
    assert await _run(world) == 2  # 8.8.8.8 and the hash; not the private IP, the false positive, the old alert or the unrelated tenant
    assert await _run(world) == 0  # seen again: refreshed, not duplicated

    rows = await _iocs(world, world["child"])
    assert [(r[0], r[1], r[2]) for r in rows] == [("ip", "8.8.8.8", "alerts"), ("file_hash_sha256", SHA, "alerts")]
    assert {r[5] for r in rows} == {"info"}
    assert rows[0][4] == 2  # linked to both alerts that carried it
    assert "from-alert" in rows[0][3] and {"huntress", "petra"} <= set(rows[0][3])
    assert await _iocs(world, world["parent"]) == []
    assert await _iocs(world, world["other"]) == []
