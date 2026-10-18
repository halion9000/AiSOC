"""Merging duplicate alerts: which row is kept, and which duplicates may be touched.

The same vendor incident was stored more than once (the entity extraction, then the fingerprint, changed under already-stored incidents). The merge keeps ONE row per (tenant, incident id)
and closes the rest as duplicates of it: nothing is deleted, and a duplicate somebody is working on is left alone.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.scripts.merge_duplicate_alerts import Row, plan_merge

T0 = datetime(2026, 10, 14, tzinfo=UTC)


def row(n: int, *, status="new", case_id=None, assigned_to_id=None, minutes=0, tickets=0) -> Row:
    return Row(id=uuid.UUID(int=n), status=status, case_id=case_id, assigned_to_id=assigned_to_id, created_at=T0 + timedelta(minutes=minutes), has_tickets=bool(tickets))


def test_the_oldest_row_is_kept_when_nothing_distinguishes_them():
    plan = plan_merge([row(2, minutes=5), row(1, minutes=0), row(3, minutes=9)])
    assert plan.keeper == uuid.UUID(int=1)
    assert sorted(plan.close) == [uuid.UUID(int=2), uuid.UUID(int=3)]


def test_a_row_with_a_case_beats_an_older_one_without():
    plan = plan_merge([row(1, minutes=0), row(2, minutes=5, case_id="CASE-1")])
    assert plan.keeper == uuid.UUID(int=2)


def test_an_assigned_row_beats_an_older_unassigned_one():
    plan = plan_merge([row(1, minutes=0), row(2, minutes=5, assigned_to_id=uuid.uuid4())])
    assert plan.keeper == uuid.UUID(int=2)


def test_a_duplicate_somebody_is_working_on_is_left_alone():
    working = row(3, status="in_progress", minutes=9)
    plan = plan_merge([row(1, minutes=0), row(2, minutes=5, status="resolved"), working])
    assert plan.keeper == uuid.UUID(int=1)
    assert uuid.UUID(int=3) in plan.leave and uuid.UUID(int=3) not in plan.close
    assert uuid.UUID(int=2) in plan.close  # already resolved: still marked as a duplicate


def test_a_single_row_has_nothing_to_merge():
    plan = plan_merge([row(1)])
    assert plan.close == [] and plan.leave == []


def test_a_row_that_carries_the_linked_tickets_is_preferred_over_an_older_bare_one():
    plan = plan_merge([row(1, minutes=0), row(2, minutes=5, tickets=1)])
    assert plan.keeper == uuid.UUID(int=2)


def test_one_incident_in_the_parent_and_one_client_is_kept_by_the_client():
    from app.scripts.merge_duplicate_alerts import plan_cross_tenant

    parent, client = uuid.uuid4(), uuid.uuid4()
    plan = plan_cross_tenant({parent: [row(1)], client: [row(2, minutes=3)]}, {client})
    assert plan == (client, uuid.UUID(int=2), [(parent, uuid.UUID(int=1))])


def test_several_client_tenants_holding_it_is_left_alone():
    from app.scripts.merge_duplicate_alerts import plan_cross_tenant

    parent, a, b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    assert plan_cross_tenant({parent: [row(1)], a: [row(2)], b: [row(3)]}, {a, b}) is None


def test_a_parent_copy_somebody_is_working_on_is_not_closed():
    from app.scripts.merge_duplicate_alerts import plan_cross_tenant

    parent, client = uuid.uuid4(), uuid.uuid4()
    assert plan_cross_tenant({parent: [row(1, status="in_progress")], client: [row(2)]}, {client}) is None
