"""The suggestion lifecycle and the hand-off to CORE, against a REAL Postgres (opt in with AISOC_TEST_PG_URL, a DISPOSABLE, fully migrated database)."""

import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import vcio_proposals as ep
from app.db.rls import set_rls_context
from app.db.rls_scope import acting_as_tenant
from app.models.signin import ClientVcioProposal
from app.services.vcio_proposals import Draft, sync_suggestions
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

PG_URL = os.environ.get("AISOC_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AISOC_TEST_PG_URL to a DISPOSABLE, fully migrated API database")

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def draft(key="mfa_admins", name="Require MFA for every administrator", priority="High"):
    return Draft(key=key, name=name, description=f"{name}. Evidence.", priority=priority, evidence="Evidence.")


@pytest.fixture
async def world():
    tag = uuid.uuid4().hex[:10]
    ids = {k: uuid.uuid4() for k in ("parent", "mapped", "unmapped")}
    engine = create_async_engine(PG_URL)
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        for key, tid in ids.items():
            await c.execute(
                text("insert into tenants (id, name, slug, parent_tenant_id, mssp_role) values (:i, :n, :s, :p, :r)"),
                {
                    "i": tid,
                    "n": f"vp-{key}-{tag}",
                    "s": f"vp-{key}-{tag}",
                    "p": None if key == "parent" else ids["parent"],
                    "r": "parent" if key == "parent" else "child",
                },
            )
        await c.execute(
            text(
                "insert into client_aliases (id, tenant_id, vendor, vendor_client_id, vendor_client_name, normalized_name, child_tenant_id, ignored) "
                "values (gen_random_uuid(), :p, 'vciotoolbox', '363990', 'Acme', 'acme', :c, false)"
            ),
            {"p": ids["parent"], "c": ids["mapped"]},
        )
    yield ids
    async with engine.begin() as c:
        await c.execute(text("select set_config('app.rls_fail_closed', 'off', true)"))
        await c.execute(text("delete from tenants where id = any(cast(:t as uuid[]))"), {"t": [str(x) for x in ids.values()]})
    await engine.dispose()


async def run(tenant, work):
    engine = create_async_engine(PG_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            await set_rls_context(db, tenant)
            out = await work(db)
            await db.commit()
            return out
    finally:
        await engine.dispose()


async def states(world, client):
    async def work(db):
        async with acting_as_tenant(db, world[client]):
            rows = (await db.execute(select(ClientVcioProposal).where(ClientVcioProposal.tenant_id == world[client]))).scalars().all()
        return {r.key: r.status for r in rows}

    return await run(world["parent"], work)


async def sync(world, client, drafts):
    async def work(db):
        async with acting_as_tenant(db, world[client]):
            return await sync_suggestions(db, world[client], drafts, NOW)

    return await run(world["parent"], work)


async def test_new_checks_become_suggestions_a_repeat_adds_nothing_and_a_check_that_stops_failing_clears(world):
    assert await sync(world, "mapped", [draft(), draft("edr", "EDR everywhere", "Medium")]) == {"added": 2, "refreshed": 0, "cleared": 0}
    assert await sync(world, "mapped", [draft(), draft("edr", "EDR everywhere", "Medium")]) == {"added": 0, "refreshed": 2, "cleared": 0}
    assert await sync(world, "mapped", [draft()]) == {"added": 0, "refreshed": 1, "cleared": 1}
    assert await states(world, "mapped") == {"mfa_admins": "suggested", "edr": "cleared"}
    await sync(world, "mapped", [draft(), draft("edr", "EDR everywhere", "Medium")])
    assert await states(world, "mapped") == {"mfa_admins": "suggested", "edr": "suggested"}, "it comes back when the check fails again"


async def proposal_id(world, client, key="mfa_admins"):
    async def work(db):
        async with acting_as_tenant(db, world[client]):
            return (
                await db.execute(
                    select(ClientVcioProposal.id).where(ClientVcioProposal.tenant_id == world[client], ClientVcioProposal.key == key)
                )
            ).scalar_one()

    return await run(world["parent"], work)


def person(world):
    return SimpleNamespace(tenant_id=world["parent"], id=uuid.uuid4())


async def test_approving_needs_the_client_mapped_to_a_vcio_customer(world):
    await sync(world, "unmapped", [draft()])
    pid = await proposal_id(world, "unmapped")
    with pytest.raises(HTTPException) as e:
        await run(world["parent"], lambda db: ep.approve_proposal(world["unmapped"], pid, person(world), db))
    assert e.value.status_code == 409 and "Map this client" in e.value.detail
    assert await states(world, "unmapped") == {"mfa_admins": "suggested"}


async def test_a_mapped_clients_suggestion_can_be_approved_once_and_not_after_it_is_sent(world):
    await sync(world, "mapped", [draft()])
    pid = await proposal_id(world, "mapped")
    out = await run(world["parent"], lambda db: ep.approve_proposal(world["mapped"], pid, person(world), db))
    assert out.status == "approved" and out.decided_at is not None
    with pytest.raises(HTTPException) as e:
        await run(world["parent"], lambda db: ep.approve_proposal(world["mapped"], pid, person(world), db))
    assert e.value.status_code == 409, "already approved"
    with pytest.raises(HTTPException) as e:
        await run(world["parent"], lambda db: ep.reject_proposal(world["mapped"], pid, person(world), db))
    assert e.value.status_code == 409, "an approved one is CORE's now"


async def test_a_rejected_suggestion_stays_rejected_when_the_check_still_fails(world):
    await sync(world, "mapped", [draft()])
    pid = await proposal_id(world, "mapped")
    await run(world["parent"], lambda db: ep.reject_proposal(world["mapped"], pid, person(world), db))
    await sync(world, "mapped", [draft()])
    assert await states(world, "mapped") == {"mfa_admins": "rejected"}


async def test_one_client_cannot_decide_another_tenants_suggestion(world):
    await sync(world, "mapped", [draft()])
    pid = await proposal_id(world, "mapped")
    with pytest.raises(HTTPException) as e:
        await run(world["parent"], lambda db: ep.reject_proposal(world["unmapped"], pid, person(world), db))
    assert e.value.status_code == 404


async def test_core_collects_what_was_approved_with_the_customer_id_and_reports_the_result_once(world, monkeypatch):
    await sync(world, "mapped", [draft(), draft("edr", "EDR everywhere", "Medium")])
    pid = await proposal_id(world, "mapped")
    await run(world["parent"], lambda db: ep.approve_proposal(world["mapped"], pid, person(world), db))

    async def verified(_db, _token):
        return world["parent"]

    monkeypatch.setattr(ep, "_verify_core_feed_token", verified)
    got = await run(world["parent"], lambda db: ep.approved_proposals("tok", db))
    assert [(i.id, i.vendor_client_id, i.key, i.priority) for i in got.items] == [
        (pid, "363990", "mfa_admins", "High")
    ], "only the approved one, with the vCIO customer it is for"

    body = ep.ProposalResult(ok=True, vendor_id="9001", message="created")
    done = await run(world["parent"], lambda db: ep.proposal_result("tok", pid, body, db))
    assert (done.status, done.result_message) == ("sent", "created") and done.sent_at is not None
    again = await run(world["parent"], lambda db: ep.proposal_result("tok", pid, ep.ProposalResult(ok=False, message="late"), db))
    assert again.status == "sent", "a repeated or late report changes nothing"
    assert (await run(world["parent"], lambda db: ep.approved_proposals("tok", db))).items == []


async def test_a_failed_send_can_be_approved_again(world, monkeypatch):
    await sync(world, "mapped", [draft()])
    pid = await proposal_id(world, "mapped")
    await run(world["parent"], lambda db: ep.approve_proposal(world["mapped"], pid, person(world), db))

    async def verified(_db, _token):
        return world["parent"]

    monkeypatch.setattr(ep, "_verify_core_feed_token", verified)
    failed = await run(world["parent"], lambda db: ep.proposal_result("tok", pid, ep.ProposalResult(ok=False, message="vCIO said 422"), db))
    assert (failed.status, failed.result_message) == ("failed", "vCIO said 422")
    out = await run(world["parent"], lambda db: ep.approve_proposal(world["mapped"], pid, person(world), db))
    assert out.status == "approved" and out.result_message is None
