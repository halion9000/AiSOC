"""Migration 088 fills affected_hosts/users/ips from the older entities and iocs columns, against a REAL, fully migrated Postgres (AISOC_TEST_PG_URL)."""

import json
import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "088_alert_entities_backfill.sql"


async def test_backfill_fills_empty_columns_only_and_is_repeatable():
    tid = uuid.uuid4()
    tag = tid.hex[:10]
    engine = create_async_engine(PG_URL)
    sql = MIGRATION.read_text()
    body = "\n".join(line for line in sql.splitlines() if line.strip() not in ("BEGIN;", "COMMIT;") and not line.lstrip().startswith("--"))
    try:
        async with engine.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(
                text("insert into tenants (id, name, slug, mssp_role) values (:i, :n, :n, 'parent')"), {"i": tid, "n": f"bf-{tag}"}
            )
            rows = [
                (
                    "old",
                    [{"type": "host", "value": "PC-1"}, {"type": "user", "value": "bob"}, {"type": "host", "value": "PC-1"}],
                    [{"type": "ip", "value": "1.2.3.4"}, {"type": "hash", "value": "abc"}],
                    [],
                    [],
                ),
                ("filled", [{"type": "host", "value": "NEW"}], [], ["kept"], []),
                ("none", [], [], [], []),
            ]
            for title, ents, iocs, hosts, users in rows:
                await conn.execute(
                    text(
                        "insert into alerts (tenant_id, title, severity, status, entities, iocs, affected_hosts, affected_users) "
                        "values (:t, :ti, 'low', 'new', cast(:e as jsonb), cast(:i as jsonb), cast(:h as jsonb), cast(:u as jsonb))"
                    ),
                    {"t": tid, "ti": title, "e": json.dumps(ents), "i": json.dumps(iocs), "h": json.dumps(hosts), "u": json.dumps(users)},
                )
            for _ in range(2):  # twice: it must be repeatable
                for stmt in [s for s in body.split(";") if s.strip()]:
                    await conn.execute(text(stmt))
            got = {
                r.title: (r.affected_hosts, r.affected_users, r.affected_ips)
                for r in (
                    await conn.execute(
                        text("select title, affected_hosts, affected_users, affected_ips from alerts where tenant_id = :t"), {"t": tid}
                    )
                ).all()
            }
        assert got["old"] == (["PC-1"], ["bob"], ["1.2.3.4"])
        assert got["filled"][0] == ["kept"], "a column that already has values is left alone"
        assert got["none"] == ([], [], [])
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
            await conn.execute(text("delete from alerts where tenant_id = :t"), {"t": tid})
            await conn.execute(text("delete from tenants where id = :t"), {"t": tid})
        await engine.dispose()
