"""Folding a duplicate client tenant into the one to keep."""

import asyncio
import uuid

import pytest
from app.db.database import Base
from app.models.client_alias import ClientAlias
from app.models.tenant import Tenant
from app.services.client_mapping import MergeError, merge_clients, set_tenant_hidden, tenant_hidden
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def run(fn):
    async def main():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as c:
            await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[Tenant.__table__, ClientAlias.__table__]))
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            try:
                return await fn(s)
            finally:
                await engine.dispose()

    return asyncio.run(main())


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=f"{name}-{uuid.uuid4().hex[:6]}".lower().replace(" ", "-"), parent_tenant_id=parent)


def alias(parent, vendor, n, child):
    return ClientAlias(
        tenant_id=parent.id, vendor=vendor, vendor_client_id=str(n), vendor_client_name=f"c{n}", normalized_name=f"c{n}", child_tenant_id=child.id if child else None, ignored=False, match_source="suggested"
    )  # fmt: skip


async def world(s):
    parent, other_parent = tenant("Parent"), tenant("Someone else")
    s.add_all([parent, other_parent])
    await s.flush()
    keep, dupe, stranger = tenant("Asylum", parent.id), tenant("Asylum Inc", parent.id), tenant("Not mine", other_parent.id)
    s.add_all([keep, dupe, stranger])
    await s.flush()
    s.add_all(
        [
            alias(parent, "huntress", 1, dupe),
            alias(parent, "petra", 2, dupe),
            alias(parent, "halopsa", 3, keep),
            alias(parent, "ninjaone", 4, None),
        ]
    )
    await s.flush()
    return parent, keep, dupe, stranger


def test_the_duplicates_tool_clients_move_to_the_one_kept_and_the_duplicate_is_hidden_not_deleted():
    async def body(s):
        parent, keep, dupe, _ = await world(s)
        source, target, moved = await merge_clients(s, parent.id, dupe.id, keep.id)
        await s.flush()
        owners = {a.vendor: a.child_tenant_id for a in (await s.execute(select(ClientAlias))).scalars()}
        return parent, keep, dupe, source, target, moved, owners

    parent, keep, dupe, source, target, moved, owners = run(body)
    assert moved == 2 and source.id == dupe.id and target.id == keep.id
    assert owners == {"huntress": keep.id, "petra": keep.id, "halopsa": keep.id, "ninjaone": None}
    assert tenant_hidden(dupe) and dupe.settings["merged_into"] == str(keep.id)
    assert not tenant_hidden(keep)


@pytest.mark.parametrize("which", ["same", "stranger", "unknown", "hidden_target"])
def test_it_refuses_what_it_should_and_changes_nothing(which):
    async def body(s):
        parent, keep, dupe, stranger = await world(s)
        source_id, target_id = dupe.id, keep.id
        if which == "same":
            target_id = dupe.id
        elif which == "stranger":
            target_id = stranger.id
        elif which == "unknown":
            target_id = uuid.uuid4()
        else:
            set_tenant_hidden(keep, True)
        with pytest.raises(MergeError) as err:
            await merge_clients(s, parent.id, source_id, target_id)
        await s.flush()
        owners = {a.vendor: a.child_tenant_id for a in (await s.execute(select(ClientAlias))).scalars()}
        return err.value, owners, dupe, keep

    err, owners, dupe, keep = run(body)
    assert err.status == (404 if which in ("stranger", "unknown") else 422)
    assert owners["huntress"] == dupe.id and owners["petra"] == dupe.id, "nothing was re-pointed"
    assert not tenant_hidden(dupe)
