"""The values the code writes into limited columns are all allowed by the database's own rules, on a REAL Postgres.

Why this exists: migration 084 limited ``vendor_actions.action`` to approve, reject and resolve; the Run script feature later wrote ``run_script``. Every test of that feature used
a mock database, so nothing noticed until a real-database test failed (fixed by migration 098). This test lists the values the code can write into each limited column, taken
from the code's own constants where it has them, and checks each is allowed by a CHECK constraint on that column in the migrated database. Adding a value in code without a
migration now fails here.

Opt in with AISOC_TEST_PG_URL (any role that can read the catalog; the database must be fully migrated).
"""

import os
import typing

import pytest
from app.api.v1.endpoints import alert_scripts as scripts
from app.api.v1.endpoints.inbox_core_feed import SourceReport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")

RUN_STATUSES = list(typing.get_args(SourceReport.model_fields["status"].annotation))

# (table, column, the values the code can write, where they come from)
CONTRACT = [
    (
        "vendor_actions",
        "action",
        ["approve", "reject", "resolve", scripts.SCRIPT_ACTION],
        "alert_vendor_actions.py (approve, reject, resolve) and alert_scripts.SCRIPT_ACTION",
    ),
    (
        "vendor_actions",
        "status",
        ["pending", "claimed", "done", "failed"],
        "inbox_core_feed.py claim and result routes, services/vendor_actions.py",
    ),
    ("connector_run_log", "status", RUN_STATUSES, "the status CORE may report (SourceReport.status)"),
    ("client_aliases", "match_source", ["manual", "suggested"], "mssp_clients.py (map, unmap, reset)"),
    (
        "client_vcio_proposals",
        "status",
        ["suggested", "approved", "rejected", "sent", "failed", "cleared"],
        "vcio_proposals.py (suggest, decide, CORE's result)",
    ),
    ("client_vcio_proposals", "kind", ["recommendation", "risk"], "vcio_proposals.py"),
]


async def definitions(table: str, column: str) -> list[str]:
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "select pg_get_constraintdef(c.oid) from pg_constraint c join pg_class t on t.oid = c.conrelid "
                        "join pg_attribute a on a.attrelid = t.oid and a.attnum = any(c.conkey) "
                        "where c.contype = 'c' and t.relname = :t and a.attname = :c"
                    ),
                    {"t": table, "c": column},
                )
            ).all()
    finally:
        await engine.dispose()
    return [r[0] for r in rows]


@pytest.mark.parametrize("table, column, values, source", CONTRACT, ids=[f"{t}.{c}" for t, c, _, _ in CONTRACT])
async def test_every_value_the_code_writes_is_allowed_by_the_database(table, column, values, source):
    defs = await definitions(table, column)
    assert defs, f"{table}.{column} has no CHECK constraint any more; update this contract ({source})"
    for value in values:
        assert any(
            f"'{value}'" in d for d in defs
        ), f"{table}.{column}: the code can write {value!r} ({source}) but the database does not allow it: {defs}"


async def test_the_contract_notices_a_value_the_database_does_not_allow():
    defs = await definitions("vendor_actions", "action")
    assert not any("'made_up_action'" in d for d in defs), "sanity: the check really looks inside the constraint text"
