"""A tenant's FIRST retention save no longer crashes when the body omits a field.

Found by calling the real endpoint with an empty body against a tenant that had never saved a policy: PUT /data-lifecycle/retention raised `TypeError: int() argument must be ... not 'NoneType'`. A new RetentionPolicyRow's columns are still None until it is flushed, so
a field the caller omitted fell through as None into resolve_policy. This is the endpoint through which operators set the windows the retention sweeper enforces.
"""
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import data_lifecycle as dl
from app.models.data_lifecycle import RetentionPolicyRow
from app.services.retention import resolve_policy

DEFAULTS = resolve_policy({}).as_dict()


def _user() -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="a@example.com")


def _db(row):
    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=res)
    db.add, db.commit = MagicMock(), AsyncMock()
    return db


async def put(row, **fields):
    user = _user()
    db = _db(row)
    out = await dl.put_retention(body=dl.RetentionUpdate(**fields), current_user=user, db=db)
    return out, db, user


@pytest.mark.asyncio
class TestFirstSave:
    async def test_a_partial_body_for_a_tenant_with_no_row_uses_the_defaults_for_the_rest(self):
        out, db, _ = await put(None, alerts_days=30)
        assert out.alerts_days == 30 and out.raw_events_days == DEFAULTS["raw_events_days"] and out.audit_days == DEFAULTS["audit_days"]
        db.add.assert_called_once()
        db.commit.assert_awaited_once()

    async def test_an_empty_body_for_a_tenant_with_no_row_is_all_defaults_not_a_crash(self):
        out, _, _ = await put(None)
        assert out.model_dump() == DEFAULTS

    async def test_each_single_field_on_its_own_works(self):
        for field in ("raw_events_days", "alerts_days", "audit_days"):
            out, _, _ = await put(None, **{field: 45})
            assert getattr(out, field) == 45

    async def test_the_new_row_is_stored_for_the_callers_tenant_with_the_merged_values(self):
        out, db, user = await put(None, audit_days=400)
        row = db.add.call_args.args[0]
        assert isinstance(row, RetentionPolicyRow) and row.tenant_id == user.tenant_id and row.audit_days == 400 and row.updated_by == user.user_id
        assert (row.raw_events_days, row.alerts_days) == (DEFAULTS["raw_events_days"], DEFAULTS["alerts_days"])

    async def test_all_three_fields_on_a_first_save_still_work(self):
        out, _, _ = await put(None, raw_events_days=10, alerts_days=20, audit_days=30)
        assert out.model_dump() == {"raw_events_days": 10, "alerts_days": 20, "audit_days": 30}


@pytest.mark.asyncio
class TestExistingRow:
    def row(self):
        return SimpleNamespace(raw_events_days=11, alerts_days=22, audit_days=33, updated_by=None)

    async def test_an_omitted_field_keeps_its_stored_value(self):
        row = self.row()
        out, db, _ = await put(row, alerts_days=99)
        assert out.model_dump() == {"raw_events_days": 11, "alerts_days": 99, "audit_days": 33}
        db.add.assert_not_called()

    async def test_the_row_is_updated_in_place_and_attributed(self):
        row = self.row()
        _, db, user = await put(row, audit_days=500)
        assert (row.raw_events_days, row.alerts_days, row.audit_days, row.updated_by) == (11, 22, 500, user.user_id)
        db.commit.assert_awaited_once()

    async def test_an_empty_body_changes_nothing(self):
        row = self.row()
        out, _, _ = await put(row)
        assert out.model_dump() == {"raw_events_days": 11, "alerts_days": 22, "audit_days": 33}

    async def test_the_query_is_scoped_to_the_callers_tenant(self):
        _, db, user = await put(self.row(), alerts_days=5)
        stmt = db.execute.call_args.args[0]
        assert "tenant_id" in str(stmt) and user.tenant_id in stmt.compile().params.values()


def test_the_model_defaults_are_python_side_so_a_new_row_really_is_none_until_flush():
    """The reason the crash happened: documented here so nobody 'simplifies' the handler back."""
    row = RetentionPolicyRow(tenant_id=uuid.uuid4())
    assert row.raw_events_days is None and row.alerts_days is None and row.audit_days is None
