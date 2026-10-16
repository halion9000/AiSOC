"""The vendor-incident lookups CORE's reports make must use an index (migration 087), not read the whole alerts table.

Opt in with AISOC_TEST_PG_URL (a disposable, fully migrated database). The planner is told to avoid sequential scans, so the plan can only avoid an index scan if NO usable index exists
for the lookup; the test fails then. It runs the exact statement ``apply_tickets`` issues, compiled by SQLAlchemy, so a change to the query that stops matching the index is caught too.
"""

from __future__ import annotations

import os
import uuid

import pytest
from app.models.alert import Alert
from sqlalchemy import select, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database"),
]


async def _plan(statement) -> str:
    sql = str(statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("set local enable_seqscan = off"))
            rows = (await conn.execute(text(f"explain {sql}"))).scalars().all()
        return "\n".join(rows)
    finally:
        await engine.dispose()


async def test_the_incident_lookup_for_a_tenant_uses_the_index():
    t = uuid.uuid4()
    plan = await _plan(select(Alert.id).where(Alert.tenant_id == t, Alert.raw_event["finding"]["uid"].astext == "huntress:1"))
    assert "idx_alerts_tenant_finding_uid" in plan, plan


async def test_the_linked_ticket_update_uses_the_index():
    t = uuid.uuid4()
    plan = await _plan(
        update(Alert).where(Alert.tenant_id == t, Alert.raw_event["finding"]["uid"].astext == "huntress:1").values(status="new")
    )
    assert "idx_alerts_tenant_finding_uid" in plan, plan
