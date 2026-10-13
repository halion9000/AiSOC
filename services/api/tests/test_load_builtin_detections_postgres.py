"""The built-in detection loader against a REAL Postgres, as the restricted role (`aisoc_app`) with the fail-closed row-level-security switch ON, the way a
tenant-scoped transaction runs in production once that switch is on.

Opt in with AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app), as the sibling tests do. Test rules use ids that start with "test-<random>-" and
are deleted afterwards, together with the two tenants the fixture creates.
"""

import os
import uuid

import pytest
from app.scripts.load_builtin_detections import list_tenant_ids, load, normalise
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
APP_URL = os.environ.get("AISOC_TEST_PG_APP_URL", "")
pytestmark = pytest.mark.skipif(
    not (PG_URL and APP_URL),
    reason="set AISOC_TEST_PG_URL (owner) and AISOC_TEST_PG_APP_URL (aisoc_app) to a DISPOSABLE, fully migrated API database",
)


def _rule(tag: str, n: int, severity: str = "high") -> dict:
    row = normalise(
        f"""id: test-{tag}-{n}
name: Loader test rule {tag} {n}
description: test
version: 1.0.0
severity: {severity}
tags: [mitre.attack.t1059.001]
category: endpoint
detection:
  condition: 'x == "y"'
enabled: true
""",
        f"test/{tag}-{n}.yaml",
    )
    assert row is not None
    return row


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
                    {"i": tid, "n": f"ld-{key}-{tag}", "s": f"ld-{key}-{tag}"},
                )
        yield {"tag": tag, "a": a, "b": b, "owner": owner, "app": app}
    finally:
        async with owner.begin() as conn:
            await conn.execute(text("delete from detection_rules where tenant_id in (:a, :b)"), {"a": a, "b": b})
            await conn.execute(text("delete from tenants where id in (:a, :b)"), {"a": a, "b": b})
        await app.dispose()
        await owner.dispose()


async def _run(world, tenant, rules):
    """Load as the restricted role, switch ON, exactly as main() does: one session and transaction per tenant."""
    async with AsyncSession(world["app"]) as session:
        await session.execute(text("select set_config('app.rls_fail_closed', 'on', false)"))
        report = await load(session, rules, tenant)
        await session.commit()
        return report


async def _rows(world, tenant):
    async with world["owner"].connect() as conn:
        return (
            await conn.execute(
                text(
                    "select provenance->>'source_id', tenant_id, is_builtin, rule_language, status, severity, mitre_techniques from detection_rules where tenant_id = :t order by name"
                ),
                {"t": tenant},
            )
        ).all()


async def test_the_restricted_role_loads_rules_into_that_tenant_only(world):
    tag = world["tag"]
    report = await _run(world, world["a"], [_rule(tag, 1), _rule(tag, 2)])
    assert (report.created, report.updated, report.unchanged) == (2, 0, 0)
    rows = await _rows(world, world["a"])
    assert len(rows) == 2
    for _src, tenant_id, is_builtin, language, status, _sev, techniques in rows:
        assert tenant_id == world["a"] and is_builtin is True and language == "aisoc" and status == "active" and techniques == ["T1059.001"]
    assert await _rows(world, world["b"]) == [], "another tenant got nothing"


async def test_each_tenant_gets_its_own_independent_copy(world):
    tag = world["tag"]
    await _run(world, world["a"], [_rule(tag, 1)])
    await _run(world, world["b"], [_rule(tag, 1)])
    assert len(await _rows(world, world["a"])) == 1 and len(await _rows(world, world["b"])) == 1
    async with world["owner"].begin() as conn:
        await conn.execute(text("update detection_rules set status = 'disabled' where tenant_id = :t"), {"t": world["a"]})
    assert [r[4] for r in await _rows(world, world["b"])] == ["active"], "disabling one tenant's copy does not touch another's"


async def test_loading_again_changes_nothing_and_duplicates_nothing(world):
    tag = world["tag"]
    await _run(world, world["a"], [_rule(tag, 1), _rule(tag, 2)])
    again = await _run(world, world["a"], [_rule(tag, 1), _rule(tag, 2)])
    assert (again.created, again.updated, again.unchanged) == (0, 0, 2)
    assert len(await _rows(world, world["a"])) == 2


async def test_a_tenants_own_tuning_survives_a_reload_when_the_file_is_unchanged(world):
    tag = world["tag"]
    await _run(world, world["a"], [_rule(tag, 1, "high")])
    async with world["owner"].begin() as conn:
        await conn.execute(text("update detection_rules set status = 'disabled', severity = 'low' where tenant_id = :t"), {"t": world["a"]})
    report = await _run(world, world["a"], [_rule(tag, 1, "high")])
    assert report.unchanged == 1 and report.updated == 0
    (row,) = await _rows(world, world["a"])
    assert row[4] == "disabled" and row[5] == "low", "a rule someone disabled stays disabled, and their severity is kept"


async def test_a_changed_file_refreshes_the_rule_but_keeps_the_tenants_status(world):
    tag = world["tag"]
    await _run(world, world["a"], [_rule(tag, 1, "high")])
    async with world["owner"].begin() as conn:
        await conn.execute(text("update detection_rules set status = 'disabled' where tenant_id = :t"), {"t": world["a"]})
    report = await _run(world, world["a"], [_rule(tag, 1, "critical")])
    assert (report.created, report.updated) == (0, 1)
    (row,) = await _rows(world, world["a"])
    assert row[5] == "critical", "the new shipped severity is applied"
    assert row[4] == "disabled", "but a rule the tenant disabled does not come back on"


async def test_the_tenant_list_is_readable_as_the_restricted_role_with_the_switch_on(world):
    async with AsyncSession(world["app"]) as session:
        await session.execute(text("select set_config('app.rls_fail_closed', 'on', false)"))
        ids = await list_tenant_ids(session)
    assert world["a"] in ids and world["b"] in ids
