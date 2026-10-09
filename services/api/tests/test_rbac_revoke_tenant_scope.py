"""CROSS-TENANT WRITE, FIXED: DELETE /api/v1/rbac/users/{user_id}/roles/{role_id}.

revoke_role deleted the assignment by the two ids alone (user_roles has no tenant column), so any tenant admin with users:write could strip any role from any user of ANY tenant. Shown on real Postgres by the two-tenant flows: tenant B removed tenant A's role assignment (HTTP 204) and A's roles then read as empty. assign_role and get_user_roles already scoped by tenant; revoke had been forgotten.
It now requires the role AND the user to belong to the caller's tenant, like assign_role. A role or user that is not the caller's is the same 404 as one that does not exist, and nothing is deleted.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import rbac

TENANT, OTHER = uuid.uuid4(), uuid.uuid4()


def user():
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="a@example.test")


class FakeDB:
    """execute() answers queued rows through scalar_one_or_none(); statements and their bound parameters are recorded."""

    def __init__(self, *payloads):
        self.queue, self.statements = list(payloads), []
        self.commit, self.rollback = AsyncMock(), AsyncMock()
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        comp = stmt.compile()
        self.statements.append((" ".join(str(comp).split()).upper(), dict(comp.params)))
        payload = self.queue.pop(0) if self.queue else None
        res = MagicMock()
        res.scalar_one_or_none.return_value = payload
        return res

    @property
    def deletes(self):
        return [s for s in self.statements if s[0].startswith("DELETE")]


ROLE, USER = object(), object()


@pytest.mark.asyncio
class TestRevokeRole:
    async def test_the_callers_own_role_and_user_are_revoked_with_a_commit(self):
        db = FakeDB(ROLE, USER)
        await rbac.revoke_role(user_id=uuid.uuid4(), role_id=uuid.uuid4(), current_user=user(), db=db)
        assert len(db.deletes) == 1 and "USER_ROLES" in db.deletes[0][0]
        db.commit.assert_awaited_once()

    async def test_a_role_that_is_not_the_callers_is_a_404_and_nothing_is_deleted(self):
        db = FakeDB(None, USER)
        with pytest.raises(HTTPException) as exc:
            await rbac.revoke_role(user_id=uuid.uuid4(), role_id=uuid.uuid4(), current_user=user(), db=db)
        assert exc.value.status_code == 404 and exc.value.detail == "Role not found"
        assert db.deletes == []
        db.commit.assert_not_awaited()

    async def test_a_user_that_is_not_the_callers_is_a_404_and_nothing_is_deleted(self):
        db = FakeDB(ROLE, None)
        with pytest.raises(HTTPException) as exc:
            await rbac.revoke_role(user_id=uuid.uuid4(), role_id=uuid.uuid4(), current_user=user(), db=db)
        assert exc.value.status_code == 404 and exc.value.detail == "User not found in tenant"
        assert db.deletes == []
        db.commit.assert_not_awaited()

    async def test_both_lookups_are_scoped_to_the_callers_tenant(self):
        db = FakeDB(ROLE, USER)
        rid, uid = uuid.uuid4(), uuid.uuid4()
        await rbac.revoke_role(user_id=uid, role_id=rid, current_user=user(), db=db)
        role_sql, role_params = db.statements[0]
        user_sql, user_params = db.statements[1]
        assert "ROLES.TENANT_ID" in role_sql and TENANT in role_params.values() and rid in role_params.values()
        assert "USERS.TENANT_ID" in user_sql and TENANT in user_params.values() and uid in user_params.values()

    async def test_the_lookups_happen_before_the_delete(self):
        db = FakeDB(ROLE, USER)
        await rbac.revoke_role(user_id=uuid.uuid4(), role_id=uuid.uuid4(), current_user=user(), db=db)
        assert [s[0].split(" ")[0] for s in db.statements] == ["SELECT", "SELECT", "DELETE"]

    async def test_the_delete_names_exactly_the_requested_user_and_role(self):
        db = FakeDB(ROLE, USER)
        rid, uid = uuid.uuid4(), uuid.uuid4()
        await rbac.revoke_role(user_id=uid, role_id=rid, current_user=user(), db=db)
        params = set(db.deletes[0][1].values())
        assert rid in params and uid in params


class TestTheOtherAssignmentEndpointsStayScoped:
    """The siblings were already right; pin them so the three user-role endpoints cannot drift apart again."""

    def test_assign_role_checks_the_role_and_the_user(self):
        import ast
        from pathlib import Path

        tree = ast.parse(Path(rbac.__file__).read_text(encoding="utf-8"))
        fns = {n.name: ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
        assert "_get_role_or_404" in fns["assign_role"] and "User.tenant_id == current_user.tenant_id" in fns["assign_role"]
        assert "_get_role_or_404" in fns["revoke_role"] and "User.tenant_id == current_user.tenant_id" in fns["revoke_role"]
        assert "Role.tenant_id == current_user.tenant_id" in fns["get_user_roles"]
