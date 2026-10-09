"""Platform-level power is separate, explicit, and not covered by the wildcard.

Some permissions act on the whole platform rather than on the caller's own tenant: managing the shared plugin registry (plugins:admin), onboarding tenants (mssp:onboard) and searching across tenants (platform:cross_tenant_query). They used to be covered by the "*" wildcard that the `admin` role (the role tenant owners and the
bootstrap administrator carry) holds, so any tenant's administrator could change what every tenant shares. Now "*" and "<resource>:*" never cover them: a principal holds one only if it is named exactly, in a role list (only platform_admin lists them), in an API key's scopes, or in a database role.
The original primary administrator is a platform_admin by default (bootstrap_production, migration 067); more can be granted, by someone who holds the power, and a key or role can only carry what its creator holds."""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import api_keys as ak
from app.api.v1.endpoints import rbac
from app.core.security import PLATFORM_PERMISSIONS, ROLE_PERMISSIONS, has_permission, known_permissions, permission_in

TENANT = uuid.uuid4()


def principal(role, scopes=None):
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@example.test", scopes=scopes)


class TestThePermissionSet:
    def test_the_platform_permissions_are_exactly_these(self):
        assert PLATFORM_PERMISSIONS == {"plugins:admin", "mssp:onboard", "platform:cross_tenant_query"}

    @pytest.mark.parametrize("perm", sorted(PLATFORM_PERMISSIONS))
    def test_only_platform_admin_holds_each_through_a_role(self, perm):
        assert [r for r in ROLE_PERMISSIONS if has_permission(r, perm)] == ["platform_admin"]

    @pytest.mark.parametrize("perm", sorted(PLATFORM_PERMISSIONS))
    def test_the_wildcard_admin_does_not_hold_any(self, perm):
        assert "*" in ROLE_PERMISSIONS["admin"] and not has_permission("admin", perm)

    def test_the_wildcard_admin_still_holds_everything_tenant_level(self):
        for perm in known_permissions() - PLATFORM_PERMISSIONS:
            assert has_permission("admin", perm), perm

    def test_platform_admin_holds_everything_the_wildcard_admin_does_and_the_platform_set(self):
        for perm in known_permissions():
            assert has_permission("platform_admin", perm), perm

    def test_the_platform_permissions_are_known_names(self):
        assert PLATFORM_PERMISSIONS <= known_permissions()

    def test_no_other_role_lists_a_platform_permission(self):
        for role, perms in ROLE_PERMISSIONS.items():
            if role != "platform_admin":
                assert not (set(perms) & PLATFORM_PERMISSIONS), role


class TestMatching:
    @pytest.mark.parametrize("granted", [["*"], ["plugins:*"], ["*", "plugins:*"], ["plugins:read", "plugins:execute"]])
    def test_neither_a_wildcard_nor_a_resource_wildcard_covers_a_platform_permission(self, granted):
        assert not permission_in(granted, "plugins:admin")

    def test_only_the_exact_name_covers_it(self):
        assert permission_in(["plugins:admin"], "plugins:admin") and permission_in(("a:b", "mssp:onboard"), "mssp:onboard")

    def test_everything_else_matches_as_before(self):
        assert permission_in(["*"], "alerts:read") and permission_in(["alerts:*"], "alerts:delete") and permission_in(["alerts:read"], "alerts:read")
        assert not permission_in(["alerts:read"], "alerts:write") and not permission_in([], "alerts:read") and not permission_in(["cases:*"], "alerts:read")

    def test_it_accepts_any_iterable(self):
        assert permission_in(iter(["alerts:read"]), "alerts:read") and permission_in({"plugins:admin"}, "plugins:admin")


class TestApiKeyScopes:
    @pytest.mark.parametrize("scopes", [["*"], ["plugins:*"], ["*", "alerts:read"]])
    def test_a_wildcard_key_does_not_carry_platform_permissions(self, scopes):
        assert not principal("viewer", scopes=scopes).holds("plugins:admin")

    def test_a_key_with_the_exact_scope_does(self):
        assert principal("viewer", scopes=["plugins:admin"]).holds("plugins:admin")

    def test_a_wildcard_key_still_carries_every_tenant_level_permission(self):
        assert principal("viewer", scopes=["*"]).holds("alerts:delete")

    def test_require_permission_raises_for_a_wildcard_key_on_a_platform_permission(self):
        with pytest.raises(HTTPException) as exc:
            principal("platform_admin", scopes=["*"]).require_permission("plugins:admin")
        assert exc.value.status_code == 403


@pytest.mark.asyncio
class TestApiKeyCreationCarriesOnlyWhatTheCreatorHolds:
    @pytest.mark.parametrize("scope", ["*", "plugins:admin", "alerts:delete"])
    async def test_a_creator_cannot_grant_a_scope_they_lack(self, scope):
        creator = principal("soc_analyst")  # holds neither the wildcard, plugins:admin nor alerts:delete
        with pytest.raises(HTTPException) as exc:
            ak._require_scopes_held(creator, [scope])
        assert exc.value.status_code == 403 and repr(scope) in exc.value.detail

    def test_a_tenant_admin_cannot_mint_a_wildcard_key_or_a_platform_scope(self):
        ta = principal("tenant_admin")
        for scope in ("*", "plugins:admin"):
            with pytest.raises(HTTPException):
                ak._require_scopes_held(ta, [scope])

    def test_a_tenant_admin_can_mint_a_key_within_its_own_permissions(self):
        ak._require_scopes_held(principal("tenant_admin"), ["alerts:read", "cases:write"])

    def test_a_wildcard_admin_can_mint_a_wildcard_key_but_not_a_platform_scope(self):
        admin = principal("admin")
        ak._require_scopes_held(admin, ["*", "alerts:read"])
        with pytest.raises(HTTPException):
            ak._require_scopes_held(admin, ["plugins:admin"])

    def test_a_platform_admin_can_mint_a_platform_scope(self):
        ak._require_scopes_held(principal("platform_admin"), ["plugins:admin", "*"])

    def test_one_forbidden_scope_among_allowed_ones_refuses_the_lot(self):
        with pytest.raises(HTTPException):
            ak._require_scopes_held(principal("tenant_admin"), ["alerts:read", "plugins:admin", "cases:read"])

    def test_an_api_key_principal_is_judged_by_its_own_scopes(self):
        with pytest.raises(HTTPException):
            ak._require_scopes_held(principal("platform_admin", scopes=["alerts:read"]), ["alerts:write"])

    def test_both_endpoints_use_the_check(self):
        import ast
        from pathlib import Path

        tree = ast.parse(Path(ak.__file__).read_text(encoding="utf-8"))
        fns = {n.name: ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
        assert "_require_scopes_held" in fns["create_api_key"] and "_require_scopes_held" in fns["update_api_key"]


class FakeDB:
    def __init__(self, *payloads):
        self.queue, self.statements, self.added = list(payloads), [], []
        self.add = MagicMock(side_effect=self.added.append)
        self.commit, self.flush, self.refresh, self.rollback = AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock()
        self.execute = AsyncMock(side_effect=self._execute)

    async def _execute(self, stmt, *a, **k):
        self.statements.append(" ".join(str(stmt).split()).upper())
        payload = self.queue.pop(0) if self.queue else None
        res = MagicMock()
        res.scalar_one_or_none.return_value = payload
        res.scalars.return_value.all.return_value = payload if isinstance(payload, list) else []
        return res


def perm(name):
    from types import SimpleNamespace

    return SimpleNamespace(id=uuid.uuid4(), name=name)


@pytest.mark.asyncio
class TestDatabaseRolesCannotLaunderPower:
    async def test_a_creator_cannot_attach_a_permission_they_lack(self, monkeypatch):
        monkeypatch.setattr(rbac, "_resolve_permissions", AsyncMock(return_value=[perm("alerts:read"), perm("plugins:admin")]))
        db = FakeDB(None)
        with pytest.raises(HTTPException) as exc:
            await rbac.create_role(body=rbac.RoleIn(name="sneaky", permission_ids=[uuid.uuid4()]), current_user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403 and "plugins:admin" in exc.value.detail
        db.add.assert_not_called()  # nothing was created: the check runs BEFORE the role is
        db.commit.assert_not_awaited()

    async def test_a_creator_can_attach_permissions_they_hold(self, monkeypatch):
        monkeypatch.setattr(rbac, "_resolve_permissions", AsyncMock(return_value=[perm("alerts:read"), perm("cases:write")]))
        monkeypatch.setattr(rbac, "PermissionOut", MagicMock(model_validate=lambda p: p))
        monkeypatch.setattr(rbac, "RoleOut", lambda **kw: kw)
        db = FakeDB(None)
        db.refresh = AsyncMock(side_effect=lambda r: setattr(r, "id", uuid.uuid4()))
        out = await rbac.create_role(body=rbac.RoleIn(name="fine", permission_ids=[uuid.uuid4()]), current_user=principal("tenant_admin"), db=db)
        assert out["name"] == "fine"

    async def test_a_platform_admin_can_attach_a_platform_permission(self, monkeypatch):
        monkeypatch.setattr(rbac, "_resolve_permissions", AsyncMock(return_value=[perm("plugins:admin")]))
        monkeypatch.setattr(rbac, "PermissionOut", MagicMock(model_validate=lambda p: p))
        monkeypatch.setattr(rbac, "RoleOut", lambda **kw: kw)
        db = FakeDB(None)
        db.refresh = AsyncMock(side_effect=lambda r: setattr(r, "id", uuid.uuid4()))
        await rbac.create_role(body=rbac.RoleIn(name="operators", permission_ids=[uuid.uuid4()]), current_user=principal("platform_admin"), db=db)
        assert len(db.added) >= 1

    async def test_a_creator_cannot_assign_a_role_that_holds_what_they_lack(self, monkeypatch):
        role = MagicMock(id=uuid.uuid4())
        monkeypatch.setattr(rbac, "_get_role_or_404", AsyncMock(return_value=role))
        monkeypatch.setattr(rbac, "_load_role_permissions", AsyncMock(return_value=[perm("alerts:read"), perm("plugins:admin")]))
        uid = uuid.uuid4()
        db = FakeDB(object())
        with pytest.raises(HTTPException) as exc:
            await rbac.assign_role(user_id=uid, body=rbac.UserRoleAssignment(user_id=uid, role_id=role.id), current_user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403
        db.add.assert_not_called()

    async def test_a_creator_cannot_edit_a_role_that_already_holds_what_they_lack(self, monkeypatch):
        role = MagicMock(id=uuid.uuid4(), is_system=False)
        role.name = "ops"  # (MagicMock(name=...) would only name the mock itself)
        monkeypatch.setattr(rbac, "_get_role_or_404", AsyncMock(return_value=role))
        monkeypatch.setattr(rbac, "_resolve_permissions", AsyncMock(return_value=[perm("alerts:read")]))
        monkeypatch.setattr(rbac, "_load_role_permissions", AsyncMock(return_value=[perm("plugins:admin")]))
        db = FakeDB()
        with pytest.raises(HTTPException) as exc:
            await rbac.update_role(role_id=role.id, body=rbac.RoleUpdate(name="renamed", permission_ids=[uuid.uuid4()]), current_user=principal("tenant_admin"), db=db)
        assert exc.value.status_code == 403
        assert role.name == "ops" and not [s for s in db.statements if s.startswith("DELETE")]  # nothing was changed or deleted first
        db.commit.assert_not_awaited()

    async def test_a_wildcard_permission_name_needs_a_wildcard(self):
        with pytest.raises(HTTPException):
            rbac._require_permissions_held(principal("tenant_admin"), ["*"])
        rbac._require_permissions_held(principal("admin"), ["*"])


class TestTheDefaultHolder:
    def test_the_bootstrap_creates_the_primary_admin_as_platform_admin(self):
        from pathlib import Path

        src = (Path(__file__).resolve().parent.parent / "app" / "scripts" / "bootstrap_production.py").read_text(encoding="utf-8")
        assert 'role="platform_admin"' in src and 'role="admin"' not in src

    def test_a_newly_provisioned_tenants_first_admin_is_not_a_platform_admin(self):
        from pathlib import Path

        src = (Path(__file__).resolve().parent.parent / "app" / "services" / "tenant_provision" / "provisioner.py").read_text(encoding="utf-8")
        assert 'role="tenant_admin"' in src and "platform_admin" not in src
