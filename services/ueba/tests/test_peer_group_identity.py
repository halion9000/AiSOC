"""A peer group is identified by its (tenant, label); its primary key is a generated UUID.

The service used the caller's string ("dept:engineering") as the primary key, but the real table's key is a ``uuid`` (the alembic migration), so the first message carrying a
peer_group_id raised a DataError on a real database, and (before the consumer survived errors) ended UEBA's consumer for good. The label is the business key.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.models.ueba import PeerGroup
from app.services.peer_group import PeerGroupService
from sqlalchemy.dialects import postgresql

TENANT = uuid.uuid4()


def _session(existing=None):
    db = MagicMock()
    db.statements = []
    db.added = []

    async def execute(stmt, *a, **k):
        db.statements.append(stmt)
        result = MagicMock()
        result.scalar_one_or_none.return_value = existing
        return result

    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock(side_effect=db.added.append)
    db.flush = AsyncMock()
    return db


def test_the_model_key_is_a_uuid_like_the_table():
    assert PeerGroup.__table__.c.id.type.python_type is uuid.UUID


@pytest.mark.asyncio
async def test_a_new_group_is_created_with_a_generated_uuid_id_and_the_callers_string_as_its_label():
    db = _session(existing=None)
    group = await PeerGroupService(db).get_or_create(TENANT, "dept:engineering", "user")
    assert isinstance(group.id, uuid.UUID) or group.id is None  # None until the database generates it (server default)
    assert group.label == "dept:engineering"
    assert db.added == [group]


@pytest.mark.asyncio
async def test_the_lookup_is_by_tenant_and_label_never_by_comparing_the_uuid_key_to_a_string():
    db = _session(existing=None)
    await PeerGroupService(db).get_or_create(TENANT, "dept:engineering", "user")
    sql = str(db.statements[0].compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": False}))
    assert "ueba_peer_groups.label" in sql and "ueba_peer_groups.tenant_id" in sql
    assert "ueba_peer_groups.id =" not in sql


@pytest.mark.asyncio
async def test_deviation_score_looks_the_group_up_by_label_too():
    db = _session(existing=None)
    assert await PeerGroupService(db).deviation_score(TENANT, "dept:engineering", {"x": 1.0}) is None
    sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
    assert "ueba_peer_groups.label" in sql and "ueba_peer_groups.id =" not in sql
