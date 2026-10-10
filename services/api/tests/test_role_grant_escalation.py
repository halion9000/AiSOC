"""PRIVILEGE ESCALATION, FIXED: a tenant_admin could create a platform_admin user, or promote itself to one, with a single request.

POST /tenants/me/users and PATCH /tenants/me/users/{id} took any `role` string from the request. Roles holding users:write include tenant_admin, so (shown live) a tenant_admin created a platform_admin user (201) that then succeeded at an action the tenant_admin itself was refused (plugin administration), and promoted ITSELF (200).
Now nobody can grant a role whose permissions they do not all hold, an unknown role is refused, nobody changes their own role, and nobody edits a user whose role grants more than their own."""
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import tenants as tn
from app.core.security import ROLE_PERMISSIONS

TENANT = uuid.uuid4()


def principal(role, scopes=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@example.test", scopes=scopes)


class TestCanGrantRole:
    @pytest.mark.parametrize("grantor", ["tenant_admin", "soc_lead", "soc_analyst", "threat_hunter", "viewer", "api_service"])
    @pytest.mark.parametrize("target", ["platform_admin", "admin"])
    def test_nobody_below_the_wildcard_roles_can_grant_them(self, grantor, target):
        assert not principal(grantor).can_grant_role(target)

    @pytest.mark.parametrize("target", sorted(ROLE_PERMISSIONS))
    def test_a_wildcard_holder_can_grant_every_role(self, target):
        assert principal("platform_admin").can_grant_role(target)

    def test_a_tenant_admin_can_grant_the_roles_that_are_within_its_own_permissions(self):
        ta = principal("tenant_admin")
        assert ta.can_grant_role("tenant_admin") and ta.can_grant_role("viewer")

    def test_nobody_can_grant_a_role_with_a_permission_they_lack(self):
        """The rule itself, for every pair: a grant is allowed exactly when the grantor holds every permission of the target (a wildcard target needs a wildcard)."""
        for grantor in ROLE_PERMISSIONS:
            for target, perms in ROLE_PERMISSIONS.items():
                expected = ("*" not in perms or "*" in ROLE_PERMISSIONS[grantor]) and all(principal(grantor).holds(p) for p in perms if p != "*")
                assert principal(grantor).can_grant_role(target) == expected, (grantor, target)

    @pytest.mark.parametrize("bad", ["", "root", "superuser", "Platform_Admin", "platform_admin ", "*", "../admin"])
    def test_an_unknown_role_is_never_grantable_not_even_by_a_wildcard_holder(self, bad):
        assert not principal("platform_admin").can_grant_role(bad)

    def test_an_api_key_can_only_grant_roles_within_its_scopes(self):
        narrow = principal("tenant_admin", scopes=["users:write", "alerts:read"])
        assert not narrow.can_grant_role("tenant_admin") and not narrow.can_grant_role("platform_admin") and not narrow.can_grant_role("admin")

    def test_an_api_key_with_the_wildcard_scope_can_grant_a_wildcard_role(self):
        assert principal("viewer", scopes=["*"]).can_grant_role("admin")

    def test_an_api_key_is_judged_by_its_scopes_not_by_the_role_string_it_carries(self):
        assert not principal("platform_admin", scopes=["users:write"]).can_grant_role("platform_admin")

    def test_holds_is_the_yes_no_form_of_require_permission(self):
        u = principal("viewer")
        assert u.holds("alerts:read") and not u.holds("users:write")
        with pytest.raises(HTTPException):
            u.require_permission("users:write")


class FakeDB:
    def __init__(self, *payloads):
        self.queue, self.added, self.statements = list(payloads), [], []
        self.add = MagicMock(side_effect=self.added.append)
        self.commit, self.rollback = AsyncMock(), AsyncMock()
        self.refresh = AsyncMock(side_effect=self._refresh)
        self.execute = AsyncMock(side_effect=self._execute)

    async def _refresh(self, obj):
        obj.id = getattr(obj, "id", None) or uuid.uuid4()
        obj.created_at = getattr(obj, "created_at", None) or datetime.now(UTC)
        if getattr(obj, "is_active", None) is None:
            obj.is_active = True

    async def _execute(self, stmt, *a, **k):
        text = " ".join(str(stmt).split()).upper()
        self.statements.append(text)
        res = MagicMock()
        if "LOWER(USERS.ACCOUNT_NAME)" in text:
            # "Is this account name free?": always, and it does not use up a payload queued for the OTHER lookups (the email check).
            res.first.return_value = None
            return res
        payload = self.queue.pop(0) if self.queue else None
        res.scalar_one_or_none.return_value = payload
        return res

    @property
    def writes(self):
        return [s for s in self.statements if s.startswith(("UPDATE", "INSERT", "DELETE"))]


def row(role, uid=None, active=True):
    from app.models.tenant import User  # the ORM user, built without a database

    return User(id=uid or uuid.uuid4(), tenant_id=TENANT, email=f"{role}-{uuid.uuid4().hex[:4]}@example.test", account_name=f"user-{uuid.uuid4().hex[:8]}", username="u", hashed_password="x", role=role, is_active=active, created_at=datetime.now(UTC))


@pytest.mark.asyncio
class TestCreateUser:
    def body(self, role):
        return tn.CreateUserRequest(email="new@example.com", username="new", password="Trial-Passw0rd!x", role=role)

    async def test_a_tenant_admin_cannot_create_a_platform_admin(self):
        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await tn.create_user(request=self.body("platform_admin"), current_user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403
        db.add.assert_not_called()

    async def test_a_tenant_admin_cannot_create_a_wildcard_admin(self):
        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await tn.create_user(request=self.body("admin"), current_user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403 and db.added == []

    async def test_an_unknown_role_is_a_422_and_creates_nothing(self):
        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await tn.create_user(request=self.body("overlord"), current_user=principal("platform_admin"), db=db)
        assert exc.value.status_code == 422 and db.added == []
        db.commit.assert_not_awaited()

    async def test_the_refusal_happens_before_the_database_is_even_asked_about_the_email(self):
        db = FakeDB(None)
        with pytest.raises(HTTPException):
            await tn.create_user(request=self.body("platform_admin"), current_user=principal("tenant_admin"), db=db)
        assert db.statements == []

    async def test_a_tenant_admin_can_still_create_a_role_within_its_permissions(self):
        db = FakeDB(None)
        out = await tn.create_user(request=self.body("soc_analyst"), current_user=principal("tenant_admin"), db=db)
        assert out.role == "soc_analyst" and len(db.added) == 1
        db.commit.assert_awaited_once()

    async def test_a_platform_admin_can_create_a_platform_admin(self):
        db = FakeDB(None)
        out = await tn.create_user(request=self.body("platform_admin"), current_user=principal("platform_admin"), db=db)
        assert out.role == "platform_admin" and len(db.added) == 1


@pytest.mark.asyncio
class TestUpdateUser:
    async def run(self, caller, target, body):
        db = FakeDB(target)
        out = await tn.update_user(user_id=target.id, request=tn.UpdateUserRequest(**body), current_user=caller, db=db)
        return out, db

    async def test_a_tenant_admin_cannot_promote_itself(self):
        caller = principal("tenant_admin")
        me = row("tenant_admin", uid=caller.user_id)
        with pytest.raises(HTTPException) as exc:
            await self.run(caller, me, {"role": "platform_admin"})
        assert exc.value.status_code == 403 and "own role" in exc.value.detail

    async def test_nobody_changes_their_own_role_at_all_even_downward(self):
        caller = principal("platform_admin")
        me = row("platform_admin", uid=caller.user_id)
        with pytest.raises(HTTPException) as exc:
            await self.run(caller, me, {"role": "viewer"})
        assert exc.value.status_code == 403

    async def test_a_user_can_still_edit_their_own_username_and_keep_their_role(self):
        caller = principal("tenant_admin")
        me = row("tenant_admin", uid=caller.user_id)
        out, db = await self.run(caller, me, {"username": "renamed", "role": "tenant_admin"})
        assert len(db.writes) == 1

    async def test_a_tenant_admin_cannot_promote_someone_else_to_platform_admin(self):
        with pytest.raises(HTTPException) as exc:
            await self.run(principal("tenant_admin"), row("soc_analyst"), {"role": "platform_admin"})
        assert exc.value.status_code == 403

    @pytest.mark.parametrize("body", [{"is_active": False}, {"username": "pwned"}, {"role": "viewer"}])
    async def test_a_tenant_admin_cannot_modify_a_platform_admin_in_any_way(self, body):
        db_target = row("platform_admin")
        with pytest.raises(HTTPException) as exc:
            await self.run(principal("tenant_admin"), db_target, body)
        assert exc.value.status_code == 403 and "more than your own" in exc.value.detail

    async def test_an_unknown_role_is_a_422_and_changes_nothing(self):
        caller = principal("platform_admin")
        target = row("viewer")
        db = FakeDB(target)
        with pytest.raises(HTTPException) as exc:
            await tn.update_user(user_id=target.id, request=tn.UpdateUserRequest(role="overlord"), current_user=caller, db=db)
        assert exc.value.status_code == 422 and db.writes == []

    async def test_a_tenant_admin_can_still_change_a_lower_users_role_within_its_permissions(self):
        out, db = await self.run(principal("tenant_admin"), row("viewer"), {"role": "soc_analyst"})
        assert len(db.writes) == 1

    async def test_a_platform_admin_can_modify_anyone_else(self):
        out, db = await self.run(principal("platform_admin"), row("platform_admin"), {"is_active": False})
        assert len(db.writes) == 1
