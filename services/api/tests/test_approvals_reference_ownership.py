"""An approval may point only at the caller's own investigation run and a user of the caller's own tenant.

Found by a scan for handlers that build a row from an `*_id` taken straight from the request body where the column is a foreign key to a
tenant-owned table. A foreign key is checked for EXISTENCE only, and by the database's owner privileges, so it ignores row-level security:
even on a tenant-scoped session, tenant A could store tenant B's run or user id in an approval (and probe whether such an id exists from
the foreign-key error). The `users` table has no RLS, so the approver's tenant has to be compared explicitly.
What it is NOT, checked rather than assumed: a cross-tenant push channel. `required_user_id` goes into the realtime service's
`notify_user_ids`, but the realtime service looks subscriptions up by tenant AND user and requires the record's tenant to equal the
event's (`push.ts` resolveSubscriptions), so a foreign user id reaches nobody. This closes the integrity hole and the existence oracle.
"""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import approvals
from app.models.investigation import InvestigationRun
from app.models.tenant import User
from fastapi import HTTPException

MINE, THEIRS = uuid.uuid4(), uuid.uuid4()


class FakeDB:
    """Scripted get(); records what the handler adds. It returns whatever row is scripted, including a FOREIGN one, as the
    owner-privileged foreign key check effectively would."""

    def __init__(self, rows):
        self.rows, self.added, self.committed = rows, [], 0

    async def get(self, model, key):
        return self.rows.get((model, key))

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.committed += 1

    async def refresh(self, row):
        row.id = row.id or uuid.uuid4()
        row.created_at = row.updated_at = datetime.now(UTC)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    async def no_notify(row, *, event):
        return None

    monkeypatch.setattr(approvals, "_notify_realtime", no_notify)
    monkeypatch.setattr(approvals.ApprovalResponse, "model_validate", classmethod(lambda cls, row: row))


def _body(**kw):
    return approvals.ApprovalCreateRequest(title="Isolate host", summary="why", **kw)


def _call(db, **kw):
    return approvals.create_approval(body=_body(**kw), user=SimpleNamespace(tenant_id=MINE, user_id=uuid.uuid4()), db=db)


def _world():
    own_run, foreign_run, mine, theirs = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rows = {
        (InvestigationRun, own_run): SimpleNamespace(tenant_id=MINE),
        (InvestigationRun, foreign_run): SimpleNamespace(tenant_id=THEIRS),
        (User, mine): SimpleNamespace(tenant_id=MINE),
        (User, theirs): SimpleNamespace(tenant_id=THEIRS),
    }
    return SimpleNamespace(db=FakeDB(rows), own_run=own_run, foreign_run=foreign_run, mine=mine, theirs=theirs)


@pytest.mark.asyncio
async def test_an_approval_with_no_references_is_unchanged():
    w = _world()
    await _call(w.db)
    assert len(w.db.added) == 1 and w.db.committed == 1


@pytest.mark.asyncio
async def test_the_callers_own_run_and_a_user_of_the_callers_tenant_are_accepted():
    w = _world()
    await _call(w.db, run_id=w.own_run, required_user_id=w.mine)
    assert w.db.added[0].run_id == w.own_run and w.db.added[0].required_user_id == w.mine and w.db.added[0].tenant_id == MINE


@pytest.mark.asyncio
async def test_another_tenants_run_is_refused_and_nothing_is_stored():
    w = _world()
    with pytest.raises(HTTPException) as refused:
        await _call(w.db, run_id=w.foreign_run)
    assert refused.value.status_code == 422 and w.db.added == [] and w.db.committed == 0


@pytest.mark.asyncio
async def test_another_tenants_user_is_refused_and_nothing_is_stored():
    w = _world()
    with pytest.raises(HTTPException) as refused:
        await _call(w.db, required_user_id=w.theirs)
    assert refused.value.status_code == 422 and w.db.added == [] and w.db.committed == 0


@pytest.mark.asyncio
async def test_a_foreign_id_and_a_missing_id_are_refused_identically_so_there_is_no_existence_oracle():
    w = _world()
    outcomes = []
    for field, foreign in (("run_id", w.foreign_run), ("required_user_id", w.theirs)):
        for value in (foreign, uuid.uuid4()):
            with pytest.raises(HTTPException) as refused:
                await _call(w.db, **{field: value})
            outcomes.append((field, refused.value.status_code, refused.value.detail))
    assert outcomes[0] == outcomes[1] and outcomes[2] == outcomes[3], outcomes


@pytest.mark.asyncio
async def test_the_run_is_checked_before_the_approver_and_both_are_needed_to_pass():
    w = _world()
    with pytest.raises(HTTPException):
        await _call(w.db, run_id=w.own_run, required_user_id=w.theirs)
    with pytest.raises(HTTPException):
        await _call(w.db, run_id=w.foreign_run, required_user_id=w.mine)
    assert w.db.added == []
