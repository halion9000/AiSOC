"""Tenant-isolation tests for the /cases API (regression: P2-W1).

Mirrors ``test_hunts_tenant_isolation.py`` (Batch 2 / C-2): call the endpoint
functions directly with a mocked :class:`DBSession` and assert that **every**
SQL statement touching ``aisoc_cases``, ``aisoc_case_comments`` or
``aisoc_case_tasks`` filters on ``tenant_id = :tenant_id`` *and* binds the
caller's tenant id.

The contract being protected: under no circumstances should an authenticated
caller be able to read or mutate a case, comment, or task belonging to a
different tenant — including via the human-readable ``INC-NNN`` short id.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.cases import (
    AddAlertsRequest,
    AddCommentRequest,
    CreateCaseRequest,
    CreateTaskRequest,
    UpdateCaseRequest,
    UpdateObservablesRequest,
    UpdateTaskRequest,
    _resolve_case_id,
    add_alerts,
    add_comment,
    case_timeline,
    create_case,
    create_task,
    evidence_report,
    get_case,
    list_cases,
    list_comments,
    list_tasks,
    update_case,
    update_observables,
    update_task,
)
from fastapi import HTTPException

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


def _case_row(**overrides: Any) -> MagicMock:
    """A row object shaped like a SQLAlchemy ``aisoc_cases`` result."""
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "case_number": "INC-001",
        "title": "Phish wave",
        "description": "Phishing detected",
        "severity": "high",
        "status": "new",
        "assignee": "analyst@example.com",
        "mitre_techniques": [],
        "alert_ids": [],
        "observable_graph": {},
        "evidence_chain": [],
        "compliance_frameworks": [],
        "opened_at": now,
        "triaged_at": None,
        "resolved_at": None,
        "closed_at": None,
        "created_at": now,
        "updated_at": now,
        "created_by": "analyst@example.com",
        "tags": {},
        "sla_due_at": None,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _task_row(**overrides: Any) -> MagicMock:
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "title": "Investigate sender",
        "status": "todo",
        "assignee": None,
        "due_at": None,
        "created_at": now,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _comment_row(**overrides: Any) -> MagicMock:
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "case_id": uuid.uuid4(),
        "author": "analyst@example.com",
        "body": "note body",
        "is_system": False,
        "created_at": now,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock DBSession that returns queued rows one execute() at a time."""
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        if isinstance(payload, list):
            result.fetchall = MagicMock(return_value=payload)
            result.fetchone = MagicMock(return_value=payload[0] if payload else None)
        else:
            result.fetchone = MagicMock(return_value=payload)
            result.fetchall = MagicMock(return_value=[payload] if payload else [])
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


_TENANT_TABLES = ("aisoc_cases", "aisoc_case_comments", "aisoc_case_tasks")


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every executed statement against a tenant-owned table must scope on tenant_id."""
    assert executed, "expected at least one DB call"
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if any(table in normalized for table in _TENANT_TABLES):
            assert "tenant_id" in normalized, f"tenant_id missing from SQL: {sql}"
            assert "tenant_id" in params, f"tenant_id not bound for SQL: {sql}"
            assert params["tenant_id"] == tenant_id, f"wrong tenant bound: {params['tenant_id']} != {tenant_id}"


# ────────────────────────────────────────────────────────────────────────────
# _resolve_case_id — the human-readable INC-NNN form must be tenant-scoped
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_case_id_uuid_does_not_hit_db() -> None:
    """UUID identifiers are returned as-is; per-endpoint queries enforce tenant."""
    user = _user()
    db = _mk_db([])  # no rows; if a query fires, fetch will return None.
    target = uuid.uuid4()
    result = await _resolve_case_id(str(target), db, user.tenant_id)
    assert result == target
    # No DB round-trip needed for the UUID branch.
    assert db.executed == []


@pytest.mark.asyncio
async def test_resolve_case_id_case_number_scopes_by_tenant() -> None:
    user = _user()
    expected_id = uuid.uuid4()
    row = MagicMock()
    row.id = expected_id
    db = _mk_db([row])
    result = await _resolve_case_id("INC-001", db, user.tenant_id)
    assert result == expected_id
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id
    assert params["case_number"] == "INC-001"


@pytest.mark.asyncio
async def test_resolve_case_id_cross_tenant_returns_404() -> None:
    """Tenant B's INC-001 must 404 for tenant A even if it exists somewhere."""
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await _resolve_case_id("INC-001", db, user.tenant_id)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# list_cases / get_case
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_cases_scopes_by_tenant() -> None:
    user = _user()
    db = _mk_db([[_case_row(title="A"), _case_row(title="B")]])
    result = await list_cases(db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_cases_with_filters_keeps_tenant_scope() -> None:
    user = _user()
    db = _mk_db([[]])
    await list_cases(
        db=db,
        user=user,
        status_filter="investigating",
        severity="high",
        assignee="analyst@example.com",
    )
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id
    assert params["status"] == "investigating"
    assert params["severity"] == "high"


@pytest.mark.asyncio
async def test_get_case_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_case(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_get_case_returns_row_when_tenant_matches() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid)])
    result = await get_case(case_id=str(cid), db=db, user=user)
    assert result.id == cid
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# create_case — INSERT must carry tenant_id
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_case_binds_tenant_id() -> None:
    user = _user()
    db = _mk_db([_case_row(title="phish")])
    result = await create_case(
        body=CreateCaseRequest(title="phish wave", severity="high"),
        db=db,
        user=user,
    )
    assert result.title == "phish"
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "insert into aisoc_cases" in normalized
    assert "tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


# ────────────────────────────────────────────────────────────────────────────
# update_case / add_alerts / update_observables — cross-tenant must 404
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_case_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # SELECT existing returns no row.
    with pytest.raises(HTTPException) as exc:
        await update_case(
            case_id=str(uuid.uuid4()),
            body=UpdateCaseRequest(title="rename"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_case_scopes_update_statement() -> None:
    user = _user()
    cid = uuid.uuid4()
    existing = MagicMock()
    existing.status = "new"
    db = _mk_db([existing, _case_row(id=cid, title="renamed")])
    await update_case(
        case_id=str(cid),
        body=UpdateCaseRequest(title="renamed"),
        db=db,
        user=user,
    )
    # Two statements: SELECT then UPDATE. Both must scope by tenant_id.
    assert len(db.executed) >= 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    upd_sql, upd_params = db.executed[1]
    assert "update aisoc_cases" in re.sub(r"\s+", " ", upd_sql).lower()
    assert upd_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_add_alerts_cross_tenant_returns_404() -> None:
    """A case that is not the caller's: the alerts are the caller's, so the ownership query passes and it is the UPDATE ... RETURNING that yields nothing.
    (Before alert ownership was checked this test's single scripted result answered the UPDATE; scripting both keeps it exercising the UPDATE path.)"""
    user = _user()
    alert_id = uuid.uuid4()
    db = _mk_db([[(alert_id,)], None])  # 1) the alerts are owned  2) UPDATE ... RETURNING * yields nothing.
    with pytest.raises(HTTPException) as exc:
        await add_alerts(
            case_id=str(uuid.uuid4()),
            body=AddAlertsRequest(alert_ids=[alert_id]),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404 and exc.value.detail == "Case not found."
    assert len(db.executed) == 2 and "update aisoc_cases" in re.sub(r"\s+", " ", db.executed[1][0]).lower()
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ---- alert ownership: a tenant may only link ITS OWN alerts to its cases ----
# The case was always checked against the caller's tenant; the alerts never were, so a tenant could plant references to alerts it does not own (or that do not exist) in its own cases.
# Found by a two-tenant flow test run against the real API as the superuser AND as the non-superuser role: the only step of 70 that failed in BOTH.


def _executed_sql(db: Any, n: int) -> str:
    return re.sub(r"\s+", " ", db.executed[n][0]).lower()


@pytest.mark.asyncio
async def test_add_alerts_refuses_a_foreign_alert_and_never_updates_the_case() -> None:
    user = _user()
    foreign = uuid.uuid4()
    db = _mk_db([[]])  # the ownership query finds none of the ids for THIS tenant
    with pytest.raises(HTTPException) as exc:
        await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[foreign]), db=db, user=user)
    assert exc.value.status_code == 404
    assert len(db.executed) == 1, "the case must not be updated when an alert is not the caller's"
    assert "from alerts" in _executed_sql(db, 0) and "update" not in _executed_sql(db, 0)
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_add_alerts_refuses_the_whole_request_if_any_one_alert_is_not_the_callers() -> None:
    user = _user()
    mine, theirs = uuid.uuid4(), uuid.uuid4()
    db = _mk_db([[(mine,)]])  # only one of the two is owned
    with pytest.raises(HTTPException) as exc:
        await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[mine, theirs]), db=db, user=user)
    assert exc.value.status_code == 404 and len(db.executed) == 1


@pytest.mark.asyncio
async def test_a_foreign_alert_and_a_nonexistent_one_get_the_identical_answer() -> None:
    """So the endpoint cannot be used to probe which alert ids exist in other tenants."""
    user = _user()
    answers = []
    for _ in range(2):
        db = _mk_db([[]])
        with pytest.raises(HTTPException) as exc:
            await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[uuid.uuid4()]), db=db, user=user)
        answers.append((exc.value.status_code, exc.value.detail))
    assert answers[0] == answers[1] == (404, "One or more alerts were not found.")


@pytest.mark.asyncio
async def test_the_ownership_query_is_bound_to_the_callers_tenant_and_the_requested_ids() -> None:
    user = _user()
    a, b = uuid.uuid4(), uuid.uuid4()
    db = _mk_db([[(a,), (b,)], _case_row(alert_ids=[a, b])])
    await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[a, b]), db=db, user=user)
    sql, params = db.executed[0]
    assert "tenant_id = :tenant_id" in re.sub(r"\s+", " ", sql).lower() and "id = any(" in re.sub(r"\s+", " ", sql).lower()
    assert params["tenant_id"] == user.tenant_id and params["ids"] == [str(a), str(b)]


@pytest.mark.asyncio
async def test_owned_alerts_are_linked_and_the_update_is_still_tenant_scoped() -> None:
    user = _user()
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    out = await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[a]), db=db, user=user)
    assert out.alert_ids == [a] and len(db.executed) == 3  # ownership check, the case update, then the alert link
    assert "update aisoc_cases" in _executed_sql(db, 1) and db.executed[1][1]["tenant_id"] == user.tenant_id
    assert "update alerts set case_id" in _executed_sql(db, 2)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_the_same_alert_listed_twice_is_fine() -> None:
    user = _user()
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[a, a]), db=db, user=user)
    assert len(db.executed) == 3


@pytest.mark.asyncio
async def test_update_observables_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await update_observables(
            case_id=str(uuid.uuid4()),
            body=UpdateObservablesRequest(nodes=[], edges=[]),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# Comments — INSERT and SELECT must both carry tenant_id
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_comment_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # parent case check returns no row.
    with pytest.raises(HTTPException) as exc:
        await add_comment(
            case_id=str(uuid.uuid4()),
            body=AddCommentRequest(body="hi"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_add_comment_inserts_with_tenant_id() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), _comment_row(case_id=cid)])
    await add_comment(
        case_id=str(cid),
        body=AddCommentRequest(body="manual note"),
        db=db,
        user=user,
    )
    # Two statements: parent SELECT then INSERT. Both must scope by tenant_id.
    assert len(db.executed) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    ins_sql, ins_params = db.executed[1]
    normalized = re.sub(r"\s+", " ", ins_sql).lower()
    assert "insert into aisoc_case_comments" in normalized
    assert ins_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_list_comments_scopes_by_tenant() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([[_comment_row(case_id=cid)]])
    result = await list_comments(case_id=str(cid), db=db, user=user)
    assert len(result) == 1
    _assert_tenant_scoped(db.executed, user.tenant_id)
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "from aisoc_case_comments" in normalized
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


# ────────────────────────────────────────────────────────────────────────────
# Evidence / timeline
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_evidence_report_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await evidence_report(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_case_timeline_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await case_timeline(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_case_timeline_scopes_comments_and_tasks() -> None:
    user = _user()
    cid = uuid.uuid4()
    # Sequence: case row → comments → (no alerts loop) → tasks
    db = _mk_db(
        [
            _case_row(id=cid),
            [_comment_row(case_id=cid)],
            [_task_row()],
        ]
    )
    await case_timeline(case_id=str(cid), db=db, user=user)
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Verify both the comments and tasks queries reference their tenant column.
    joined = " | ".join(re.sub(r"\s+", " ", s).lower() for s, _ in db.executed)
    assert "from aisoc_case_comments" in joined
    assert "from aisoc_case_tasks" in joined


# ────────────────────────────────────────────────────────────────────────────
# Tasks
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_tasks_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # parent check returns no row.
    with pytest.raises(HTTPException) as exc:
        await list_tasks(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_tasks_scopes_by_tenant() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), [_task_row(), _task_row()]])
    result = await list_tasks(case_id=str(cid), db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Second statement is the tasks SELECT; check it filters by tenant_id.
    sql, params = db.executed[1]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "from aisoc_case_tasks" in normalized
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_create_task_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await create_task(
            case_id=str(uuid.uuid4()),
            body=CreateTaskRequest(title="Investigate"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_create_task_inserts_with_tenant_id() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), _task_row()])
    await create_task(
        case_id=str(cid),
        body=CreateTaskRequest(title="Investigate"),
        db=db,
        user=user,
    )
    assert len(db.executed) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    ins_sql, ins_params = db.executed[1]
    normalized = re.sub(r"\s+", " ", ins_sql).lower()
    assert "insert into aisoc_case_tasks" in normalized
    assert ins_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_update_task_cross_tenant_returns_404() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([None])  # UPDATE ... RETURNING yields nothing.
    with pytest.raises(HTTPException) as exc:
        await update_task(
            case_id=str(cid),
            task_id=uuid.uuid4(),
            body=UpdateTaskRequest(status="in_progress"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_task_scopes_update_statement() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_task_row()])
    await update_task(
        case_id=str(cid),
        task_id=uuid.uuid4(),
        body=UpdateTaskRequest(status="done"),
        db=db,
        user=user,
    )
    _assert_tenant_scoped(db.executed, user.tenant_id)
    upd_sql, upd_params = db.executed[0]
    normalized = re.sub(r"\s+", " ", upd_sql).lower()
    assert "update aisoc_case_tasks" in normalized
    assert upd_params["tenant_id"] == user.tenant_id


# --- POST /cases must not cite alerts the caller does not own -------------------------------------------------------------------------------------------------------------------------------------------------------------
# POST /cases/{id}/alerts was fixed to check alert ownership; POST /cases never was: on real Postgres tenant B created a case citing tenant A's alert id and got 201.
# Both now share one check (_require_owned_alerts); foreign and nonexistent ids get the same 404, so it cannot be used to probe which alert ids exist elsewhere.


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).lower()


@pytest.mark.asyncio
async def test_create_case_with_a_foreign_or_nonexistent_alert_is_404_and_nothing_is_inserted() -> None:
    user = _user()
    a = uuid.uuid4()
    db = _mk_db([[]])  # the ownership query finds none of the caller's
    with pytest.raises(HTTPException) as exc:
        await create_case(body=CreateCaseRequest(title="citing someone else", alert_ids=[a]), db=db, user=user)
    assert exc.value.status_code == 404 and exc.value.detail == "One or more alerts were not found."
    assert len(db.executed) == 1 and "insert into" not in _norm(db.executed[0][0])
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_case_with_one_foreign_alert_among_owned_ones_is_refused() -> None:
    user = _user()
    mine, theirs = uuid.uuid4(), uuid.uuid4()
    db = _mk_db([[(mine,)]])  # only one of the two is the caller's
    with pytest.raises(HTTPException) as exc:
        await create_case(body=CreateCaseRequest(title="mixed ownership", alert_ids=[mine, theirs]), db=db, user=user)
    assert exc.value.status_code == 404
    assert all("insert into" not in _norm(sql) for sql, _ in db.executed)


@pytest.mark.asyncio
async def test_the_answer_is_identical_for_foreign_and_nonexistent_alerts() -> None:
    answers = []
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            await create_case(body=CreateCaseRequest(title="probing ids", alert_ids=[uuid.uuid4()]), db=_mk_db([[]]), user=_user())
        answers.append((exc.value.status_code, exc.value.detail))
    assert answers[0] == answers[1] == (404, "One or more alerts were not found.")


@pytest.mark.asyncio
async def test_create_case_with_owned_alerts_checks_ownership_first_then_inserts_them() -> None:
    user = _user()
    a, b = uuid.uuid4(), uuid.uuid4()
    db = _mk_db([[(a,), (b,)], _case_row(alert_ids=[a, b])])
    await create_case(body=CreateCaseRequest(title="both mine", alert_ids=[a, b]), db=db, user=user)
    check_sql, check_params = db.executed[0]
    assert "from alerts" in _norm(check_sql) and "tenant_id = :tenant_id" in _norm(check_sql) and "id = any(" in _norm(check_sql)
    assert check_params["tenant_id"] == user.tenant_id and check_params["ids"] == [str(a), str(b)]
    assert "insert into aisoc_cases" in _norm(db.executed[1][0])


@pytest.mark.asyncio
async def test_a_case_that_names_no_alerts_runs_no_ownership_query() -> None:
    db = _mk_db([_case_row(title="no alerts")])
    await create_case(body=CreateCaseRequest(title="no alerts"), db=db, user=_user())
    assert len(db.executed) == 1 and "insert into aisoc_cases" in _norm(db.executed[0][0])


@pytest.mark.asyncio
async def test_a_duplicated_alert_id_in_the_request_is_not_a_false_refusal() -> None:
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    await create_case(body=CreateCaseRequest(title="dupes are fine", alert_ids=[a, a]), db=db, user=_user())
    assert "insert into aisoc_cases" in _norm(db.executed[1][0])


def test_create_and_attach_share_one_ownership_check() -> None:
    import ast
    from pathlib import Path

    import app.api.v1.endpoints.cases as cases_mod

    tree = ast.parse(Path(cases_mod.__file__).read_text(encoding="utf-8"))
    calls = {n.name: {ast.unparse(c.func) for c in ast.walk(n) if isinstance(c, ast.Call)} for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name in ("create_case", "add_alerts")}
    assert "_require_owned_alerts" in calls["create_case"] and "_require_owned_alerts" in calls["add_alerts"]


# --- alerts.case_id is kept in step with the case side -------------------------------------------------------------------------------------------------------------------------------------------------------------------
# The alert <-> case link was recorded only on the case (aisoc_cases.alert_ids): alerts.case_id was NULL for every live alert (only the demo seed set it), so the alert queue's case_id, the SLA metrics' case count, the narrative projection and the rail's case pivot were silently inert.
# Now POST /cases and POST /cases/{id}/alerts set it in the same transaction; the FIRST case to claim an alert keeps it; migration 065 backfills existing links.


def _link_statement(db: MagicMock):
    for sql, params in db.executed:
        if _norm(sql).startswith("update alerts set case_id"):
            return _norm(sql), params
    return None


@pytest.mark.asyncio
async def test_creating_a_case_with_alerts_links_them_after_the_insert_and_before_the_commit() -> None:
    user = _user()
    a, b = uuid.uuid4(), uuid.uuid4()
    db = _mk_db([[(a,), (b,)], _case_row(alert_ids=[a, b])])
    order: list[str] = []
    original = db.execute.side_effect

    async def traced(clause: Any, *args: Any, **kwargs: Any) -> Any:
        order.append(" ".join(_norm(str(clause)).strip().split(" ")[:2]))
        return await original(clause, *args, **kwargs)

    db.execute.side_effect = traced
    db.commit.side_effect = lambda: order.append("COMMIT")
    await create_case(body=CreateCaseRequest(title="both mine", alert_ids=[a, b]), db=db, user=user)
    assert order == ["select id", "insert into", "update alerts", "COMMIT"]


@pytest.mark.asyncio
async def test_the_link_names_the_new_case_the_callers_tenant_and_the_alerts() -> None:
    user = _user()
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    await create_case(body=CreateCaseRequest(title="one alert", alert_ids=[a]), db=db, user=user)
    sql, params = _link_statement(db)
    insert_params = db.executed[1][1]
    assert "where id = any(cast(:ids as uuid[])) and tenant_id = :tenant_id and case_id is null" in sql
    assert params["tenant_id"] == user.tenant_id and params["ids"] == [str(a)] and params["case_id"] == insert_params["id"]


@pytest.mark.asyncio
async def test_the_first_case_to_claim_an_alert_keeps_it() -> None:
    """`case_id IS NULL` in the UPDATE: a second case citing the alert never moves it."""
    sql, _ = _link_statement(await _linked_db())
    assert sql.endswith("and case_id is null")


async def _linked_db() -> MagicMock:
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    await create_case(body=CreateCaseRequest(title="claims it", alert_ids=[a]), db=db, user=_user())
    return db


@pytest.mark.asyncio
async def test_a_case_without_alerts_issues_no_link_statement() -> None:
    db = _mk_db([_case_row(title="no alerts")])
    await create_case(body=CreateCaseRequest(title="no alerts"), db=db, user=_user())
    assert _link_statement(db) is None and len(db.executed) == 1


@pytest.mark.asyncio
async def test_attaching_alerts_links_them_to_that_case() -> None:
    user = _user()
    a = uuid.uuid4()
    cid = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(id=cid, alert_ids=[a])])
    await add_alerts(case_id=str(cid), body=AddAlertsRequest(alert_ids=[a]), db=db, user=user)
    sql, params = _link_statement(db)
    assert params["tenant_id"] == user.tenant_id and params["ids"] == [str(a)] and str(params["case_id"]) == str(cid)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_refused_attach_never_reaches_the_link() -> None:
    db = _mk_db([[]])  # ownership check finds nothing
    with pytest.raises(HTTPException):
        await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[uuid.uuid4()]), db=db, user=_user())
    assert _link_statement(db) is None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failing_link_rolls_back_instead_of_committing_a_half_linked_case_on_attach() -> None:
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    original = db.execute.side_effect
    calls = {"n": 0}

    async def failing_on_the_link(clause: Any, *args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("alerts update failed")
        return await original(clause, *args, **kwargs)

    db.execute.side_effect = failing_on_the_link
    with pytest.raises(HTTPException) as exc:
        await add_alerts(case_id=str(uuid.uuid4()), body=AddAlertsRequest(alert_ids=[a]), db=db, user=_user())
    assert exc.value.status_code == 503
    db.rollback.assert_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failing_link_does_not_commit_the_created_case() -> None:
    a = uuid.uuid4()
    db = _mk_db([[(a,)], _case_row(alert_ids=[a])])
    original = db.execute.side_effect
    calls = {"n": 0}

    async def failing_on_the_link(clause: Any, *args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("alerts update failed")
        return await original(clause, *args, **kwargs)

    db.execute.side_effect = failing_on_the_link
    with pytest.raises(HTTPException):
        await create_case(body=CreateCaseRequest(title="atomic", alert_ids=[a]), db=db, user=_user())
    db.commit.assert_not_awaited()


def test_both_writers_call_the_link_helper() -> None:
    import ast
    from pathlib import Path

    import app.api.v1.endpoints.cases as cases_mod

    tree = ast.parse(Path(cases_mod.__file__).read_text(encoding="utf-8"))
    calls = {n.name: {ast.unparse(c.func) for c in ast.walk(n) if isinstance(c, ast.Call)} for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name in ("create_case", "add_alerts")}
    assert "_link_alerts_to_case" in calls["create_case"] and "_link_alerts_to_case" in calls["add_alerts"]


class TestMigration065:
    from pathlib import Path as _P

    sql = (_P(__file__).resolve().parent.parent / "migrations" / "065_backfill_alert_case_id.sql").read_text(encoding="utf-8")

    def norm(self) -> str:
        return " ".join(re.sub(r"--[^\n]*", "", self.sql).split())

    def test_it_is_transactional_and_follows_064(self) -> None:
        from pathlib import Path

        assert self.sql.count("BEGIN;") == 1 and self.sql.count("COMMIT;") == 1
        names = sorted(p.name for p in (Path(__file__).resolve().parent.parent / "migrations").glob("*.sql"))
        assert names.index("065_backfill_alert_case_id.sql") == names.index("064_detection_proposal_source.sql") + 1

    def test_the_earliest_opened_case_wins(self) -> None:
        n = self.norm()
        assert "DISTINCT ON (x.alert_id, x.tenant_id)" in n and "ORDER BY x.alert_id, x.tenant_id, x.opened_at ASC, x.case_id" in n

    def test_only_same_tenant_alerts_with_no_case_yet_are_touched(self) -> None:
        n = self.norm()
        assert "a.tenant_id = first_case.tenant_id" in n and "a.case_id IS NULL" in n and "a.id = first_case.alert_id" in n

    def test_it_reads_the_case_side_link(self) -> None:
        assert "unnest(alert_ids)" in self.norm() and "FROM aisoc_cases" in self.norm()
