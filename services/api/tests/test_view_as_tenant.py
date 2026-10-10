"""Viewing another tenant ("view as"): read-only, for the people entitled to, and never silently ignored.

The console's tenant switcher sent the chosen tenant as `X-Tenant-Id`, which the API never read, so an MSSP operator who "switched" to a customer kept seeing their OWN data under the customer's name. The server now honours an explicit
`X-View-As-Tenant` header, for a tenant the caller may view, for reading only (app.services.view_as). A real SQLite database and the real routers (mounted under /api/v1, as in production, so the account-level path rule sees real paths). Row-level
security follows the viewed tenant because the principal's tenant_id does; SQLite has none, so that was checked on real Postgres as the non-superuser role (the live scenario in the commit message).
"""
import asyncio
import itertools
import logging
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import platform_tenant_access as pta
from app.api.v1.endpoints import tenants as tn
from app.core.security import create_access_token, hash_api_key
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.models.tenant_access import AllTenantAccessGrant, TenantAccessGrant
from app.services import view_as
from app.services.view_as import ERROR_HEADER, VIEW_AS_HEADER, VIEWING_HEADER

V = VIEW_AS_HEADER


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=name.lower() + "-" + uuid.uuid4().hex[:6], parent_tenant_id=parent.id if parent else None, mssp_role="parent" if name == "P" else ("child" if parent else None))


def user(t, email, role):
    return User(id=uuid.uuid4(), tenant_id=t.id, email=email, username=email.split("@")[0], hashed_password="x", role=role)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """P is an MSSP parent with two children (C1, C2); X is unrelated; PL holds a platform admin. GRANTS: p_admin may view C1 and C2, p_analyst only C1, nobody else anything (being in P confers nothing by itself). Users are minted tokens directly (no password hashing)."""
    path = tmp_path / "viewas.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__, TenantAccessGrant.__table__, AllTenantAccessGrant.__table__])
    P, X, PL = tenant("P"), tenant("X"), tenant("PL")
    C1, C2 = tenant("C1", P), tenant("C2", P)
    users = {
        "p_admin": user(P, "p-admin@p.example", "admin"),
        "p_analyst": user(P, "p-analyst@p.example", "soc_analyst"),
        "p_viewer": user(P, "p-viewer@p.example", "viewer"),
        "p_lead": user(P, "p-lead@p.example", "soc_lead"),  # holds users:read but NOT users:write
        "p_service": user(P, "p-service@p.example", "api_service"),  # holds alerts:read; granted nothing
        "c1_admin": user(C1, "c1-admin@c1.example", "admin"),
        "c2_admin": user(C2, "c2-admin@c2.example", "admin"),
        "x_admin": user(X, "x-admin@x.example", "admin"),
        "platform": user(PL, "platform@pl.example", "platform_admin"),
        # Technicians at each access level. They belong to X, an MSP-like tenant unrelated to P and its customers.
        "tech_full": user(X, "tech-full@x.example", "soc_analyst"),  # FULL on C1, VIEW on C2
        "tech_view": user(X, "tech-view@x.example", "soc_analyst"),  # VIEW on C1 only
        "tech_all_full": user(X, "tech-all-full@x.example", "soc_analyst"),  # every tenant, full
        "tech_all_view": user(X, "tech-all-view@x.example", "soc_analyst"),  # every tenant, view
        "tech_mixed_a": user(X, "tech-mixed-a@x.example", "soc_analyst"),  # VIEW on C1 + every tenant full: the stronger wins
        "tech_mixed_b": user(X, "tech-mixed-b@x.example", "soc_analyst"),  # FULL on C1 + every tenant view: the stronger wins
        "admin_full": user(X, "admin-full@x.example", "admin"),  # FULL on C1; an admin holds users:write and the wildcard
        "platform_all_full": user(PL, "platform-all-full@pl.example", "platform_admin"),  # a platform admin who ALSO holds every tenant at full
    }
    raw_key = "aisoc_" + uuid.uuid4().hex
    key = ApiKey(id=uuid.uuid4(), tenant_id=P.id, user_id=users["p_admin"].id, name="ci", key_prefix=raw_key[:12], hashed_key=hash_api_key(raw_key), scopes=["*"], is_active=True)
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([P, X, PL, C1, C2, *users.values(), key])
        s.commit()
        s.add_all([TenantAccessGrant(user_id=users[who].id, tenant_id=t.id, access=level, granted_by=users["platform"].id, granted_by_label="platform@pl.example") for who, t, level in (("p_admin", C1, "view"), ("p_admin", C2, "view"), ("p_analyst", C1, "view"), ("tech_full", C1, "full"), ("tech_full", C2, "view"), ("tech_view", C1, "view"), ("tech_mixed_a", C1, "view"), ("tech_mixed_b", C1, "full"), ("admin_full", C1, "full"))])
        s.add_all([AllTenantAccessGrant(user_id=users[who].id, access=level, granted_by=users["platform"].id, granted_by_label="platform@pl.example") for who, level in (("tech_all_full", "full"), ("tech_all_view", "view"), ("tech_mixed_a", "full"), ("tech_mixed_b", "view"), ("platform_all_full", "full"))])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)

    async def not_revoked(jti):
        return False

    monkeypatch.setattr(deps, "is_revoked", not_revoked)
    views: list[tuple] = []  # what the dependency asked to be audited (audit_log is Postgres-only, so it is not in this SQLite world; record_view itself is tested below)

    async def record(db, user, target, request=None):
        views.append((user.user_id, user.tenant_id, target, request.method))
        return True

    monkeypatch.setattr(deps, "record_view", record)
    events: list[tuple] = []  # what happened, in order: ("audit", ...) from the write-intent record, ("handler", ...) from the probe route
    audit_state = {"fail": False}

    async def record_act(db, user, target, access, request):
        if audit_state["fail"]:
            raise RuntimeError("audit store down")
        events.append(("audit", user.user_id, target, access, request.method, request.url.path))

    monkeypatch.setattr(deps, "record_act_as", record_act)
    probe = APIRouter(prefix="/probe")

    def handler_event(u, name):
        events.append(("handler", name, u.tenant_id, u.home_tenant_id, u.acting_access))
        return {"tenant_id": str(u.tenant_id), "home_tenant_id": str(u.home_tenant_id), "access": u.acting_access}

    @probe.post("/write")
    async def probe_write(u: Annotated[deps.AuthUser, Depends(deps.require_permission("alerts:write"))]):
        return handler_event(u, "write")

    @probe.delete("/write")
    async def probe_delete(u: Annotated[deps.AuthUser, Depends(deps.require_permission("alerts:write"))]):
        return handler_event(u, "delete")

    @probe.post("/users-write")
    async def probe_users_write(u: Annotated[deps.AuthUser, Depends(deps.require_permission("users:write"))]):
        return handler_event(u, "users-write")

    @probe.post("/platform")
    async def probe_platform(u: Annotated[deps.AuthUser, Depends(deps.require_permission("platform:cross_tenant_query"))]):
        return handler_event(u, "platform")
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(tn.router, prefix="/api/v1")
    app.include_router(pta.router, prefix="/api/v1")
    app.include_router(probe, prefix="/api/v1")

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    tenants = {"P": P, "C1": C1, "C2": C2, "X": X, "PL": PL}
    token = lambda u: create_access_token({"sub": str(u.id), "tenant_id": str(u.tenant_id), "role": u.role, "email": u.email})  # noqa: E731
    yield SimpleNamespace(client=TestClient(app), views=views, events=events, audit_state=audit_state, factory=factory, sync=sync, users=users, tenants=tenants, api_key=raw_key, auth=lambda who: {"Authorization": "Bearer " + token(users[who])})
    sync.dispose()


def get_users(world, who, view=None, method="get", **kw):
    headers = {**world.auth(who), **({V: str(view)} if view is not None else {})}
    return getattr(world.client, method)("/api/v1/tenants/me/users", headers=headers, **kw)


def emails(r):
    return sorted(u["email"] for u in r.json())


class TestWhatEachCallerMayView:
    def listing(self, world, who):
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth(who))
        assert r.status_code == 200, r.text
        return [(t["relationship"], t["id"]) for t in r.json()["tenants"]]

    def test_a_person_may_view_their_own_tenant_and_the_tenants_they_were_granted_and_nothing_else(self, world):
        T = world.tenants
        assert self.listing(world, "p_admin") == [("self", str(T["P"].id)), ("granted", str(T["C1"].id)), ("granted", str(T["C2"].id))]
        assert self.listing(world, "p_analyst") == [("self", str(T["P"].id)), ("granted", str(T["C1"].id))]

    def test_a_child_or_an_unrelated_tenant_may_view_only_itself(self, world):
        T = world.tenants
        for who, own in (("c1_admin", "C1"), ("c2_admin", "C2"), ("x_admin", "X")):
            assert self.listing(world, who) == [("self", str(T[own].id))]

    def test_a_platform_admin_may_view_every_tenant_their_own_first(self, world):
        T = world.tenants
        got = self.listing(world, "platform")
        assert got[0] == ("self", str(T["PL"].id)) and {i for _, i in got} == {str(t.id) for t in T.values()} and {r for r, _ in got[1:]} == {"platform"}
        assert len(got) == len({i for _, i in got}) == len(T), "every tenant exactly once: a set of ids would hide a repeated one"

    @pytest.mark.parametrize("who", ["p_viewer", "p_service"])
    def test_belonging_to_the_parent_tenant_confers_nothing_over_its_children_without_a_grant(self, world, who):
        """The old rule let EVERY user of an MSSP parent view ALL its children, even a viewer. Now being in the parent tenant is not enough."""
        assert self.listing(world, who) == [("self", str(world.tenants["P"].id))]

    def test_a_tenant_is_always_viewable_by_its_own_people_whatever_their_permissions_and_another_is_not_without_a_reason(self, world):
        nobody = SimpleNamespace(tenant_id=world.tenants["P"].id, holds=lambda permission: False)
        assert view_as.may_view_tenant(nobody, world.tenants["P"]) is True
        assert view_as.may_view_tenant(nobody, world.tenants["C1"]) is False and view_as.may_view_tenant(nobody, world.tenants["X"]) is False
        assert view_as.may_view_tenant(nobody, world.tenants["C1"], granted={world.tenants["C1"].id}) is True and view_as.may_view_tenant(nobody, world.tenants["X"], granted={world.tenants["C1"].id}) is False

    @staticmethod
    async def grants_of(world, user):
        async with world.factory() as s:
            return await view_as.granted_tenant_ids(s, user)

    def test_every_rule_is_relative_to_the_persons_home_never_to_the_tenant_being_viewed(self, world):
        """A principal that is already viewing C1 is still the same PERSON: their grants are theirs (C2 too) and their list is theirs. It must not reason from C1's position (where C2 would be a stranger)."""
        T = world.tenants
        viewing = deps.CurrentUser(user_id=world.users["p_admin"].id, tenant_id=T["C1"].id, role="admin", email="p-admin@p.example", home_tenant_id=T["P"].id)
        assert view_as.home_tenant_of(viewing) == T["P"].id
        granted = asyncio.run(self.grants_of(world, viewing))
        assert granted == {T["C1"].id, T["C2"].id}
        assert view_as.may_view_tenant(viewing, T["C2"], granted) is True and view_as.may_view_tenant(viewing, T["P"], granted) is True and view_as.may_view_tenant(viewing, T["X"], granted) is False

        async def go():
            async with world.factory() as s:
                return await view_as.viewable_tenants(s, viewing), await tn.list_viewable_tenants(current_user=viewing, db=s), await view_as.resolve_view_as(s, viewing, str(T["P"].id), "GET")

        listing, response, naming_home = asyncio.run(go())
        assert [(rel, t.id) for t, rel in listing] == [("self", T["P"].id), ("granted", T["C1"].id), ("granted", T["C2"].id)]
        assert response.home_tenant_id == T["P"].id and naming_home is None, "naming the home tenant is 'no change', not a view"

    def test_the_answer_names_the_callers_home_tenant(self, world):
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth("p_admin"))
        assert r.json()["home_tenant_id"] == str(world.tenants["P"].id)

    def test_a_tenant_nobody_granted_is_never_listed(self, world):
        T = world.tenants
        assert str(T["C1"].id) not in [i for _, i in self.listing(world, "x_admin")] and str(T["C1"].id) not in [i for _, i in self.listing(world, "c2_admin")]

    def test_what_the_list_offers_is_exactly_what_the_server_honours(self, world):
        """For every caller and every tenant: it is in the list if and only if viewing it is allowed. The console can only offer what will work, and nothing that works is hidden."""
        for who, (name, t) in itertools.product(world.users, world.tenants.items()):
            offered = str(t.id) in [i for _, i in self.listing(world, who)]
            r = world.client.get("/api/v1/tenants/me/identity", headers={**world.auth(who), V: str(t.id)})  # readable by every role, and it says which tenant answered
            honoured = r.status_code == 200 and r.json()["id"] == str(t.id)
            assert offered == honoured, f"{who} -> {name}: offered={offered} honoured={honoured} ({r.status_code})"


class TestViewing:
    def test_without_the_header_a_caller_sees_their_own_tenant(self, world):
        assert emails(get_users(world, "p_admin")) == ["p-admin@p.example", "p-analyst@p.example", "p-lead@p.example", "p-service@p.example", "p-viewer@p.example"]

    def test_an_operator_viewing_a_child_sees_the_childs_data_not_their_own(self, world):
        r = get_users(world, "p_admin", view=world.tenants["C1"].id)
        assert r.status_code == 200 and emails(r) == ["c1-admin@c1.example"]

    def test_the_response_says_which_tenant_it_is_for(self, world):
        assert get_users(world, "p_admin", view=world.tenants["C2"].id).headers[VIEWING_HEADER] == str(world.tenants["C2"].id)

    def test_a_platform_admin_may_view_any_tenant(self, world):
        assert emails(get_users(world, "platform", view=world.tenants["X"].id)) == sorted(u.email for u in world.users.values() if u.tenant_id == world.tenants["X"].id)

    def test_naming_your_own_tenant_changes_nothing_and_says_nothing(self, world):
        r = get_users(world, "p_admin", view=world.tenants["P"].id)
        assert r.status_code == 200 and "p-admin@p.example" in emails(r) and VIEWING_HEADER not in r.headers

    @pytest.mark.parametrize("value", ["", "   "])
    def test_an_empty_header_is_the_same_as_none(self, world, value):
        r = world.client.get("/api/v1/tenants/me/users", headers={**world.auth("p_admin"), V: value})
        assert r.status_code == 200 and "p-admin@p.example" in emails(r)

    def test_the_viewer_is_unchanged_a_view_is_not_a_switch_of_who_they_are(self, world):
        get_users(world, "p_admin", view=world.tenants["C1"].id)
        with Session(world.sync) as s:
            assert s.scalars(select(User.tenant_id).where(User.email == "p-admin@p.example")).one() == world.tenants["P"].id

    @pytest.mark.parametrize("who,target", [("c1_admin", "P"), ("c1_admin", "C2"), ("c2_admin", "C1"), ("x_admin", "P"), ("x_admin", "C1"), ("p_service", "C1"), ("p_viewer", "C1"), ("p_viewer", "C2"), ("p_analyst", "C2"), ("p_admin", "X"), ("p_admin", "PL")])
    def test_a_tenant_the_caller_may_not_view_is_refused(self, world, who, target):
        r = get_users(world, who, view=world.tenants[target].id)
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "forbidden"

    def test_a_tenant_that_does_not_exist_gets_the_same_answer_so_it_is_no_way_to_find_out_which_exist(self, world):
        real = get_users(world, "p_admin", view=world.tenants["X"].id)
        ghost = get_users(world, "p_admin", view=uuid.uuid4())
        assert (ghost.status_code, ghost.headers[ERROR_HEADER], ghost.json()) == (real.status_code, real.headers[ERROR_HEADER], real.json())
        assert get_users(world, "platform", view=uuid.uuid4()).status_code == 403

    @pytest.mark.parametrize("value", ["default", "not-a-uuid", "12345", "00000000-0000-0000-0000-00000000000g", "null", "{}"])
    def test_a_value_that_is_not_a_tenant_id_is_an_error_never_silently_ignored(self, world, value):
        r = get_users(world, "p_admin", view=value)
        assert r.status_code == 400 and r.headers[ERROR_HEADER] == "invalid"

    def test_the_right_to_view_ends_the_moment_the_grant_is_revoked(self, world):
        c1 = world.tenants["C1"].id
        assert get_users(world, "p_admin", view=c1).status_code == 200
        with Session(world.sync) as s:
            s.query(TenantAccessGrant).filter_by(user_id=world.users["p_admin"].id, tenant_id=c1).delete()
            s.commit()
        r = get_users(world, "p_admin", view=c1)
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "forbidden"
        assert get_users(world, "p_admin", view=world.tenants["C2"].id).status_code == 200, "their other grant is untouched"

    def test_a_grant_is_the_persons_own_so_it_does_not_extend_to_a_colleague(self, world):
        c1 = world.tenants["C1"].id

        def who_answers(who):  # readable by every role, and it says which tenant answered
            r = world.client.get("/api/v1/tenants/me/identity", headers={**world.auth(who), V: str(c1)})
            return r.status_code, (r.json().get("id") if r.status_code == 200 else None)

        assert who_answers("p_analyst") == (200, str(c1))
        assert who_answers("p_viewer") == (403, None)

    def test_the_parent_child_link_alone_no_longer_lets_anyone_view_a_child(self, world):
        """The data still says P is C1's parent; that is what lets P's admins MANAGE access, not what lets anyone VIEW."""
        assert world.tenants["C1"].parent_tenant_id == world.tenants["P"].id
        assert get_users(world, "p_viewer", view=world.tenants["C1"].id).status_code == 403

    def test_a_grant_to_a_tenant_that_no_longer_exists_grants_nothing(self, world):
        assert get_users(world, "p_admin", view=uuid.uuid4()).status_code == 403


class TestViewingIsReadOnly:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get"])
    def test_reading_methods_are_allowed(self, world, method):
        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, SimpleNamespace(user_id=world.users["p_admin"].id, tenant_id=world.tenants["P"].id, holds=lambda p: False), str(world.tenants["C1"].id), method)

        result = asyncio.run(go())
        assert (result.tenant_id, result.access) == (world.tenants["C1"].id, "view")

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post", "Delete", "TRACE", "CONNECT"])
    def test_every_other_method_is_refused(self, world, method):
        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, SimpleNamespace(user_id=world.users["p_admin"].id, tenant_id=world.tenants["P"].id, holds=lambda p: False), str(world.tenants["C1"].id), method)

        with pytest.raises(HTTPException) as e:
            asyncio.run(go())
        assert e.value.status_code == 403 and e.value.headers[ERROR_HEADER] == "read_only"

    def test_creating_a_user_while_viewing_is_refused_and_creates_nothing_anywhere(self, world):
        body = {"email": "intruder@example.com", "username": "intruder", "password": "Str0ng-Passw0rd!", "role": "soc_analyst"}
        r = world.client.post("/api/v1/tenants/me/users", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)}, json=body)
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"
        with Session(world.sync) as s:
            assert s.scalars(select(User).where(User.email == "intruder@example.com")).all() == []

    def test_changing_a_user_while_viewing_is_refused_and_changes_nothing(self, world):
        target = world.users["c1_admin"]
        r = world.client.patch(f"/api/v1/tenants/me/users/{target.id}", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)}, json={"is_active": False})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"
        with Session(world.sync) as s:
            assert s.get(User, target.id).is_active is True

    def test_the_same_write_without_the_header_still_works_in_the_callers_own_tenant(self, world):
        body = {"email": "new@p.example", "username": "newuser", "password": "Str0ng-Passw0rd!", "role": "soc_analyst"}
        assert world.client.post("/api/v1/tenants/me/users", headers=world.auth("p_admin"), json=body).status_code == 201

    def test_a_write_to_a_tenant_the_caller_may_not_view_is_forbidden_not_read_only_so_nothing_is_revealed(self, world):
        body = {"email": "x@example.com", "username": "xx", "password": "Str0ng-Passw0rd!", "role": "soc_analyst"}
        r = world.client.post("/api/v1/tenants/me/users", headers={**world.auth("c1_admin"), V: str(world.tenants["X"].id)}, json=body)
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "forbidden"


class TestApiKeysAndAccountLevelRoutes:
    def test_an_api_key_may_not_view_another_tenant_it_acts_on_its_own(self, world):
        r = world.client.get("/api/v1/tenants/me/users", headers={"Authorization": "Bearer " + world.api_key, V: str(world.tenants["C1"].id)})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "session_only"

    def test_an_api_key_that_sends_the_header_for_its_own_tenant_is_refused_too_one_rule_not_two(self, world):
        r = world.client.get("/api/v1/tenants/me/users", headers={"Authorization": "Bearer " + world.api_key, V: str(world.tenants["P"].id)})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "session_only"

    def test_an_api_key_without_the_header_works_as_before(self, world):
        assert world.client.get("/api/v1/tenants/me/users", headers={"Authorization": "Bearer " + world.api_key}).status_code == 200

    def test_the_account_endpoint_is_still_the_person_while_a_view_is_requested(self, world):
        r = world.client.get("/api/v1/auth/me", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)})
        assert r.status_code == 200 and r.json()["email"] == "p-admin@p.example"

    def test_the_tenant_list_does_not_change_while_a_view_is_requested(self, world):
        plain = world.client.get("/api/v1/tenants/viewable", headers=world.auth("p_admin")).json()
        viewing = world.client.get("/api/v1/tenants/viewable", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)}).json()
        assert viewing == plain and viewing["home_tenant_id"] == str(world.tenants["P"].id)

    def test_a_bad_value_does_not_break_an_account_level_route(self, world):
        assert world.client.get("/api/v1/auth/me", headers={**world.auth("p_admin"), V: "default"}).status_code == 200

    @pytest.mark.parametrize("path", ["/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/me", "/api/v1/auth/me/preferences", "/api/v1/auth/refresh", "/api/v1/push/subscribe", "/api/v1/push/test", "/api/v1/passkeys/credentials", "/api/v1/passkeys/register/begin", "/api/v1/tenants/viewable", "/api/v2/auth/me"])
    def test_these_paths_always_act_as_the_signed_in_person(self, path):
        assert view_as.is_account_level(path)

    @pytest.mark.parametrize("path", ["/api/v1/tenants/me", "/api/v1/tenants/me/users", "/api/v1/tenants/selectable", "/api/v1/alerts", "/api/v1/cases", "/api/v1/authority", "/api/v1/pushy", "/api/v1/passkeysx", "/api/v1/tenants/viewable/extra", "/api/v1/tenants/viewables", "/api/v1/x/auth/me", "/auth/me", "/api/v1/mssp/children"])
    def test_these_do_not(self, path):
        assert not view_as.is_account_level(path)

    def test_every_real_account_level_route_is_matched_by_the_rule(self):
        """The rule is a path pattern: if a route under /auth, /push or /passkeys exists, the pattern must reach it (a new route there must not become a view-as target)."""
        import os

        os.environ.setdefault("ENVIRONMENT", "test")
        from app.main import app

        paths = [p for p in app.openapi()["paths"] if p.startswith(("/api/v1/auth/", "/api/v1/push/", "/api/v1/passkeys/", "/api/v1/tenants/viewable"))]
        assert len(paths) >= 17
        assert [p for p in paths if not view_as.is_account_level(p.replace("{credential_id}", "x"))] == []


class TestThePrincipalWhileViewing:
    def request(self, view, method="GET", path="/api/v1/tenants/me/users"):
        return SimpleNamespace(headers={V: str(view)} if view is not None else {}, method=method, url=SimpleNamespace(path=path), state=SimpleNamespace())

    def principal(self, world, who, view, **kw):
        creds = SimpleNamespace(credentials=world.auth(who)["Authorization"].split(" ", 1)[1])

        async def go():
            async with world.factory() as s:
                return await deps.get_current_user(creds, s, self.request(view, **kw), SimpleNamespace(headers={}))

        return asyncio.run(go())

    def test_it_is_for_the_viewed_tenant_with_the_callers_own_identity_and_home(self, world):
        u = self.principal(world, "p_admin", world.tenants["C1"].id)
        assert (u.tenant_id, u.home_tenant_id, u.user_id, u.role, u.email) == (world.tenants["C1"].id, world.tenants["P"].id, world.users["p_admin"].id, "admin", "p-admin@p.example")
        assert u.viewing_other_tenant is True

    def test_it_is_a_plain_principal_when_nothing_is_being_viewed(self, world):
        u = self.principal(world, "p_admin", None)
        assert (u.tenant_id, u.home_tenant_id, u.viewing_other_tenant) == (world.tenants["P"].id, world.tenants["P"].id, False)

    def test_viewing_never_confers_power_the_caller_does_not_have(self, world):
        u = self.principal(world, "p_admin", world.tenants["C1"].id)
        assert not u.holds("platform:cross_tenant_query") and not u.holds("plugins:admin") and u.holds("alerts:read")

    def test_a_platform_admin_keeps_exactly_their_own_power_while_viewing(self, world):
        u = self.principal(world, "platform", world.tenants["X"].id)
        assert u.holds("platform:cross_tenant_query") and u.tenant_id == world.tenants["X"].id

    def test_a_default_home_is_the_tenant(self):
        t = uuid.uuid4()
        u = deps.CurrentUser(user_id=uuid.uuid4(), tenant_id=t, role="viewer", email="a@b.c")
        assert u.home_tenant_id == t and u.viewing_other_tenant is False

    def test_a_direct_call_without_a_request_is_unchanged(self, world):
        creds = SimpleNamespace(credentials=world.auth("p_admin")["Authorization"].split(" ", 1)[1])

        async def go():
            async with world.factory() as s:
                return await deps.get_current_user(creds, s)

        assert asyncio.run(go()).tenant_id == world.tenants["P"].id

    def test_a_request_with_no_credentials_in_development_ignores_the_header(self, world, monkeypatch):
        monkeypatch.setattr(deps, "is_dev_mode", lambda: True)

        async def go():
            async with world.factory() as s:
                return await deps.get_current_user(None, s, self.request("default"), SimpleNamespace(headers={}))

        assert asyncio.run(go()).tenant_id == deps.DEMO_TENANT_ID


class TestTheViewIsLogged:
    def test_a_view_is_logged_with_who_home_and_viewed(self, world, caplog):
        with caplog.at_level(logging.INFO, logger=deps.logger.name):
            get_users(world, "p_admin", view=world.tenants["C1"].id)
        (rec,) = [r for r in caplog.records if r.name == deps.logger.name and "viewing" in r.getMessage()]
        assert (rec.viewer, rec.home_tenant, rec.viewed_tenant, rec.http_method, rec.path) == (str(world.users["p_admin"].id), str(world.tenants["P"].id), str(world.tenants["C1"].id), "GET", "/api/v1/tenants/me/users")

    def test_nothing_is_logged_when_nothing_is_viewed_or_when_it_is_refused(self, world, caplog):
        with caplog.at_level(logging.INFO, logger=deps.logger.name):
            get_users(world, "p_admin")
            get_users(world, "p_admin", view=world.tenants["X"].id)
            get_users(world, "p_admin", view=world.tenants["P"].id)
        assert [r for r in caplog.records if r.name == deps.logger.name] == []

    def test_the_log_call_uses_no_reserved_record_attribute(self):
        reserved = set(vars(logging.LogRecord("n", 20, "p", 1, "m", (), None))) | {"message", "asctime"}
        assert not ({"viewer", "home_tenant", "viewed_tenant", "http_method", "path"} & reserved)


class TestTheViewIsAuditedInTheViewedTenant:
    """The audit middleware records only writes, under the caller's home tenant: a customer would never know an operator looked. A view writes `tenant:viewed` into the VIEWED tenant's own log (record_view, tested below)."""

    def test_an_honoured_view_is_recorded_once_for_the_viewer_and_the_viewed_tenant(self, world):
        get_users(world, "p_admin", view=world.tenants["C1"].id)
        assert world.views == [(world.users["p_admin"].id, world.tenants["P"].id, world.tenants["C1"].id, "GET")]

    def test_every_honoured_request_asks_for_it_the_window_is_applied_when_writing_not_by_skipping_the_ask(self, world):
        for _ in range(3):
            get_users(world, "p_admin", view=world.tenants["C1"].id)
        assert len(world.views) == 3

    def test_a_platform_admin_viewing_any_tenant_is_recorded_too(self, world):
        get_users(world, "platform", view=world.tenants["X"].id)
        assert [(v[0], v[2]) for v in world.views] == [(world.users["platform"].id, world.tenants["X"].id)]

    def test_nothing_is_recorded_when_nothing_was_viewed_or_the_view_was_refused(self, world):
        get_users(world, "p_admin")  # no header
        get_users(world, "p_admin", view=world.tenants["P"].id)  # own tenant
        get_users(world, "p_admin", view=world.tenants["X"].id)  # not allowed
        get_users(world, "p_admin", view=uuid.uuid4())  # does not exist
        get_users(world, "p_admin", view="default")  # not a tenant id
        world.client.post("/api/v1/tenants/me/users", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)}, json={"email": "z@z.example", "username": "zz", "password": "Str0ng-Passw0rd!", "role": "soc_analyst"})  # a write
        world.client.get("/api/v1/tenants/me/users", headers={"Authorization": "Bearer " + world.api_key, V: str(world.tenants["C1"].id)})  # an API key
        world.client.get("/api/v1/auth/me", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)})  # an account-level route
        assert world.views == []

    def test_a_view_that_cannot_be_recorded_is_not_served(self, world, monkeypatch):
        async def broken(db, user, target, request=None):
            raise RuntimeError("audit store down")

        monkeypatch.setattr(deps, "record_view", broken)
        with pytest.raises(RuntimeError):
            get_users(world, "p_admin", view=world.tenants["C1"].id)


class FakeSession:
    def __init__(self, recent=None, fail_on=None):
        self.statements, self.commits, self.recent, self.fail_on = [], 0, recent, fail_on

    async def execute(self, stmt):
        if self.fail_on == "execute":
            raise RuntimeError("db down")
        self.statements.append(stmt)
        return SimpleNamespace(first=lambda: self.recent)

    async def commit(self):
        self.commits += 1


class TestRecordView:
    def setup_method(self):
        self.viewer = SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), home_tenant_id=None, email="op@msp.example", role="admin")
        self.viewer.home_tenant_id = self.viewer.tenant_id
        self.target = uuid.uuid4()
        self.request = SimpleNamespace(headers={})

    def run(self, db, monkeypatch, emit=None):
        calls = []

        async def fake_emit(**kw):
            calls.append(kw)

        monkeypatch.setattr(view_as, "emit_audit", emit or fake_emit)
        return asyncio.run(view_as.record_view(db, self.viewer, self.target, self.request)), calls

    def test_it_writes_one_event_into_the_VIEWED_tenants_log_naming_who_and_from_where(self, monkeypatch):
        db = FakeSession()
        wrote, calls = self.run(db, monkeypatch)
        assert wrote is True and db.commits == 1 and len(calls) == 1
        (call,) = calls
        assert call["db"] is db and call["tenant_id"] == self.target and call["tenant_id"] != self.viewer.tenant_id, "the viewed tenant's log, not the viewer's"
        assert (call["actor_id"], call["actor_email"], call["action"], call["resource"], call["resource_id"]) == (self.viewer.user_id, "op@msp.example", "tenant:viewed", "tenant", str(self.target))
        assert call["changes"] == {"viewer_home_tenant_id": str(self.viewer.tenant_id), "viewer_role": "admin"} and call["request"] is self.request

    def test_it_writes_nothing_when_this_person_already_has_one_inside_the_window(self, monkeypatch):
        db = FakeSession(recent=(uuid.uuid4(),))
        wrote, calls = self.run(db, monkeypatch)
        assert (wrote, calls, db.commits) == (False, [], 0)

    def test_the_lookup_is_for_this_viewer_in_this_viewed_tenant_for_this_action_since_the_cutoff(self, monkeypatch):
        from datetime import UTC, datetime, timedelta

        db = FakeSession()
        self.run(db, monkeypatch)
        (stmt,) = db.statements
        sql, params = str(stmt), stmt.compile().params
        for column in ("audit_log.tenant_id =", "audit_log.actor_id =", "audit_log.action =", "audit_log.created_at >="):
            assert column in sql, column
        assert self.target in params.values() and self.viewer.user_id in params.values() and "tenant:viewed" in params.values()
        (cutoff,) = [v for v in params.values() if isinstance(v, datetime)]
        assert abs((datetime.now(UTC) - view_as.VIEW_AUDIT_WINDOW) - cutoff) < timedelta(seconds=5)

    def test_the_window_is_fifteen_minutes(self):
        from datetime import timedelta

        assert view_as.VIEW_AUDIT_WINDOW == timedelta(minutes=15)

    def test_a_failure_to_write_is_not_swallowed_and_nothing_is_committed(self, monkeypatch):
        async def boom(**kw):
            raise RuntimeError("cannot write")

        db = FakeSession()
        with pytest.raises(RuntimeError):
            self.run(db, monkeypatch, emit=boom)
        assert db.commits == 0

    def test_a_failure_to_look_up_is_not_swallowed_either(self, monkeypatch):
        with pytest.raises(RuntimeError):
            self.run(FakeSession(fail_on="execute"), monkeypatch)

    def test_the_homes_of_a_principal_that_is_already_viewing_is_recorded_not_the_tenant_it_is_viewing(self, monkeypatch):
        self.viewer.tenant_id = uuid.uuid4()  # already viewing some other tenant; its home is unchanged
        _, calls = self.run(FakeSession(), monkeypatch)
        assert calls[0]["changes"]["viewer_home_tenant_id"] == str(self.viewer.home_tenant_id) != str(self.viewer.tenant_id)


def account(world, who):
    return world.users[who].account_name


def who_answers(world, who, tenant):
    """(status, the tenant that answered) for a view of `tenant`; the identity endpoint is readable by every role."""
    r = world.client.get("/api/v1/tenants/me/identity", headers={**world.auth(who), V: str(world.tenants[tenant].id)})
    return r.status_code, (r.json().get("id") if r.status_code == 200 else None)


@pytest.fixture
def audits(monkeypatch):
    """What the grant endpoints asked to be audited (audit_log is Postgres-only, so it is not in this SQLite world; the real write was checked on Postgres)."""
    calls: list[dict] = []

    async def record(**kw):
        calls.append(kw)

    monkeypatch.setattr(tn, "emit_audit", record)
    return calls


def put(world, who, tenant, name):
    return world.client.put(f"/api/v1/tenants/{world.tenants[tenant].id}/access/{name}", headers=world.auth(who))


def delete(world, who, tenant, name):
    return world.client.delete(f"/api/v1/tenants/{world.tenants[tenant].id}/access/{name}", headers=world.auth(who))


def count_grants(world):
    with Session(world.sync) as s:
        return len(s.scalars(select(TenantAccessGrant.id)).all())


def grants_of(world, tenant):
    with Session(world.sync) as s:
        return sorted((g.user_id, g.access) for g in s.scalars(select(TenantAccessGrant).where(TenantAccessGrant.tenant_id == world.tenants[tenant].id)))


class TestWhoMayManageAccess:
    """A platform admin: any tenant. Otherwise a holder of users:write whose HOME tenant is the tenant, or its parent. Nobody else, and never a child over its parent."""

    def may(self, world, who, tenant):
        u = world.users[who]
        principal = deps.CurrentUser(user_id=u.id, tenant_id=u.tenant_id, role=u.role, email=u.email)
        return view_as.may_manage_access(principal, world.tenants[tenant])

    @pytest.mark.parametrize("tenant", ["P", "C1", "C2", "X", "PL"])
    def test_a_platform_admin_may_manage_any_tenant(self, world, tenant):
        assert self.may(world, "platform", tenant) is True

    @pytest.mark.parametrize("who,tenant,expected", [
        ("p_admin", "P", True), ("p_admin", "C1", True), ("p_admin", "C2", True),  # an MSP's admin: their own tenant and their customers
        ("p_admin", "X", False), ("p_admin", "PL", False),
        ("c1_admin", "C1", True),  # a customer's admin: their own tenant
        ("c1_admin", "P", False), ("c1_admin", "C2", False), ("c1_admin", "X", False),  # never their parent, a sibling, or a stranger
        ("x_admin", "X", True), ("x_admin", "C1", False), ("x_admin", "P", False),
    ])
    def test_an_administrator_may_manage_their_own_tenant_and_the_ones_it_is_the_parent_of(self, world, who, tenant, expected):
        assert self.may(world, who, tenant) is expected

    @pytest.mark.parametrize("who", ["p_viewer", "p_analyst", "p_service", "p_lead"])
    @pytest.mark.parametrize("tenant", ["P", "C1"])
    def test_without_users_write_nobody_may_manage_access_even_in_their_own_tenant(self, world, who, tenant):
        assert self.may(world, who, tenant) is False

    def test_a_tenant_with_no_parent_is_not_managed_by_someone_whose_tenant_id_matches_nothing(self, world):
        """A NULL parent must never match: a sloppy comparison of two Nones would be true."""
        nobody = SimpleNamespace(tenant_id=world.tenants["X"].id, holds=lambda p: p == "users:write")
        assert world.tenants["PL"].parent_tenant_id is None and view_as.may_manage_access(nobody, world.tenants["PL"]) is False

    def test_the_rule_is_relative_to_the_persons_home_not_the_tenant_they_are_viewing(self, world):
        T = world.tenants
        viewing = deps.CurrentUser(user_id=world.users["p_admin"].id, tenant_id=T["C1"].id, role="admin", email="p-admin@p.example", home_tenant_id=T["P"].id)
        assert view_as.may_manage_access(viewing, T["C2"]) is True and view_as.may_manage_access(viewing, T["X"]) is False


class TestGrantingAccess:
    def test_a_platform_admin_grants_someone_access_to_a_tenant_and_they_can_then_view_it_read_only(self, world, audits):
        assert who_answers(world, "x_admin", "C1")[0] == 403
        r = put(world, "platform", "C1", account(world, "x_admin"))
        assert r.status_code == 200
        assert who_answers(world, "x_admin", "C1") == (200, str(world.tenants["C1"].id))
        w = world.client.post("/api/v1/tenants/me/users", headers={**world.auth("x_admin"), V: str(world.tenants["C1"].id)}, json={"account_name": "zzz-intruder", "password": "Str0ng-Passw0rd!"})
        assert w.status_code == 403 and w.headers[ERROR_HEADER] == "read_only", "a grant is read-only"

    def test_a_customers_own_admin_grants_an_msp_technician_access_to_their_tenant(self, world, audits):
        assert put(world, "c1_admin", "C1", account(world, "p_viewer")).status_code == 200
        assert who_answers(world, "p_viewer", "C1")[0] == 200

    def test_an_msps_admin_manages_which_of_their_staff_may_see_which_customer(self, world, audits):
        assert put(world, "p_admin", "C2", account(world, "x_admin")).status_code == 200
        assert who_answers(world, "x_admin", "C2")[0] == 200

    def test_the_grant_is_only_for_that_tenant(self, world, audits):
        put(world, "platform", "C1", account(world, "x_admin"))
        assert who_answers(world, "x_admin", "C1")[0] == 200
        assert who_answers(world, "x_admin", "C2")[0] == 403 and who_answers(world, "x_admin", "P")[0] == 403

    def test_the_granted_tenant_appears_in_their_list_marked_granted(self, world, audits):
        put(world, "platform", "C1", account(world, "x_admin"))
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth("x_admin")).json()["tenants"]
        assert [(t["relationship"], t["id"]) for t in r] == [("self", str(world.tenants["X"].id)), ("granted", str(world.tenants["C1"].id))]

    def test_the_response_says_who_what_where_and_by_whom(self, world, audits):
        r = put(world, "platform", "C1", account(world, "x_admin")).json()
        assert (r["tenant_id"], r["account_name"], r["home_tenant_id"], r["access"], r["granted_by"]) == (str(world.tenants["C1"].id), account(world, "x_admin"), str(world.tenants["X"].id), "view", "platform@pl.example")
        assert r["user_id"] == str(world.users["x_admin"].id) and r["created_at"]

    def test_it_is_idempotent_one_row_and_no_second_audit_event(self, world, audits):
        before = len(grants_of(world, "C1"))
        a, b = put(world, "platform", "C1", account(world, "x_admin")), put(world, "platform", "C1", account(world, "x_admin"))
        assert a.status_code == b.status_code == 200 and a.json()["created_at"] == b.json()["created_at"]
        assert len(grants_of(world, "C1")) == before + 1, "x_admin makes ONE more, however often it is asked"
        assert len(audits) == 1

    def test_the_account_name_is_matched_in_any_case(self, world, audits):
        assert put(world, "platform", "C1", account(world, "x_admin").upper()).status_code == 200

    def test_an_unknown_account_is_a_404(self, world, audits):
        r = put(world, "platform", "C1", "nobody-by-that-name")
        assert r.status_code == 404 and audits == []

    def test_an_account_that_already_belongs_to_the_tenant_is_refused_a_grant_is_for_outsiders(self, world, audits):
        r = put(world, "platform", "C1", account(world, "c1_admin"))
        assert r.status_code == 422 and "already belongs" in r.json()["detail"] and audits == []

    def test_a_deactivated_account_cannot_be_granted_anything(self, world, audits):
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.tenants["X"].id, email="gone@x.example", username="gone", account_name="gone-user", hashed_password="x", role="admin", is_active=False))
            s.commit()
        r = put(world, "platform", "C1", "gone-user")
        assert r.status_code == 422 and "deactivated" in r.json()["detail"] and audits == []

    def test_a_grant_to_an_account_in_another_tenant_leaves_that_accounts_own_tenant_unchanged(self, world, audits):
        put(world, "platform", "C1", account(world, "x_admin"))
        with Session(world.sync) as s:
            assert s.scalars(select(User.tenant_id).where(User.id == world.users["x_admin"].id)).one() == world.tenants["X"].id

    def test_a_lost_race_for_the_same_grant_is_the_already_granted_case_not_an_error(self, world, audits):
        """Two requests grant the same person at once. The first look-up for an existing grant finds none (the other had not committed); the insert then collides with the unique constraint; the answer must be the existing grant."""
        before = len(grants_of(world, "C1"))
        assert put(world, "platform", "C1", account(world, "x_admin")).status_code == 200  # the "other request", already committed

        class RacesAtCommit:
            def __init__(self, session):
                self.session, self.blind = session, True

            async def execute(self, stmt):
                if self.blind and "from tenant_access_grants" in str(stmt).lower():
                    self.blind = False  # the first look-up for an existing grant reports none
                    return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: None))
                return await self.session.execute(stmt)

            async def commit(self):
                raise IntegrityError("insert", {}, Exception("duplicate key"))

            async def rollback(self):
                await self.session.rollback()

            def __getattr__(self, name):
                return getattr(self.session, name)

        platform = SimpleNamespace(tenant_id=world.tenants["PL"].id, home_tenant_id=world.tenants["PL"].id, user_id=world.users["platform"].id, email="platform@pl.example", holds=lambda p: True)

        async def go():
            async with world.factory() as s:
                return await tn.grant_tenant_access(tenant_id=world.tenants["C1"].id, account_name=account(world, "x_admin"), current_user=platform, db=RacesAtCommit(s))

        out = asyncio.run(go())
        assert out.account_name == account(world, "x_admin") and out.access == "view"
        assert len(grants_of(world, "C1")) == before + 1, "still one grant per person"

    def test_the_grant_is_audited_in_the_TARGET_tenants_own_log(self, world, audits):
        put(world, "p_admin", "C2", account(world, "x_admin"))
        (event,) = audits
        assert event["tenant_id"] == world.tenants["C2"].id and event["action"] == "tenant:access_granted" and event["resource"] == "tenant_access"
        assert event["actor_id"] == world.users["p_admin"].id and event["actor_email"] == "p-admin@p.example" and event["resource_id"] == str(world.users["x_admin"].id)
        assert event["changes"] == {"account_name": account(world, "x_admin"), "home_tenant_id": str(world.tenants["X"].id), "access": "view"}


class TestWhoMayGrant:
    def test_someone_who_may_not_manage_the_tenant_gets_the_same_404_as_for_a_tenant_that_does_not_exist(self, world, audits):
        before = count_grants(world)
        stranger = put(world, "x_admin", "C1", account(world, "p_viewer"))
        ghost = world.client.put(f"/api/v1/tenants/{uuid.uuid4()}/access/{account(world, 'p_viewer')}", headers=world.auth("x_admin"))
        assert (stranger.status_code, stranger.json()) == (ghost.status_code, ghost.json()) == (404, {"detail": "Tenant not found"})
        assert count_grants(world) == before and audits == []

    @pytest.mark.parametrize("who,tenant", [("x_admin", "C1"), ("x_admin", "P"), ("c1_admin", "C2"), ("c1_admin", "P"), ("c1_admin", "X"), ("p_admin", "X"), ("p_admin", "PL")])
    def test_the_people_who_may_not_manage_a_tenant_cannot_grant_on_it(self, world, audits, who, tenant):
        before = count_grants(world)
        assert put(world, who, tenant, account(world, "p_viewer")).status_code == 404
        assert count_grants(world) == before and audits == []

    @pytest.mark.parametrize("who", ["p_viewer", "p_analyst", "p_service"])
    def test_without_users_write_the_request_is_refused_before_anything_else(self, world, audits, who):
        assert put(world, who, "P", account(world, "x_admin")).status_code == 403 and audits == []

    def test_a_role_that_can_read_users_but_not_write_them_can_neither_grant_nor_revoke_and_cannot_manage_the_list(self, world, audits):
        """soc_lead holds users:read but NOT users:write. Granting and revoking need write; seeing who has access is part of managing it, which also needs write (a 404, the same as for a stranger)."""
        assert put(world, "p_lead", "C1", account(world, "x_admin")).status_code == 403
        assert delete(world, "p_lead", "C1", account(world, "p_analyst")).status_code == 403
        assert world.client.get(f"/api/v1/tenants/{world.tenants['P'].id}/access", headers=world.auth("p_lead")).status_code == 404
        assert audits == [] and who_answers(world, "p_analyst", "C1")[0] == 200

    def test_a_child_tenants_admin_cannot_reach_up_to_grant_access_to_its_parent(self, world, audits):
        assert put(world, "c1_admin", "P", account(world, "x_admin")).status_code == 404

    def test_nobody_can_grant_while_viewing_another_tenant_the_view_is_read_only(self, world, audits):
        """p_admin is viewing C1 (granted). Even though they may manage C2's access from their home, a request sent from inside a view is a write and is refused."""
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C2'].id}/access/{account(world, 'x_admin')}", headers={**world.auth("p_admin"), V: str(world.tenants["C1"].id)})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only" and audits == []

    def test_an_api_key_cannot_use_the_view_header_but_acts_on_its_own_tenant_as_before(self, world, audits):
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'x_admin')}", headers={"Authorization": "Bearer " + world.api_key})
        assert r.status_code == 200, "the key belongs to P's admin: P is C1's parent"


class TestListingAccess:
    def list(self, world, who, tenant):
        return world.client.get(f"/api/v1/tenants/{world.tenants[tenant].id}/access", headers=world.auth(who))

    def test_it_lists_who_has_access_with_their_home_tenant(self, world):
        r = self.list(world, "c1_admin", "C1").json()
        P, X = str(world.tenants["P"].id), str(world.tenants["X"].id)
        assert {(g["account_name"], g["home_tenant_id"], g["access"]) for g in r} == {
            (account(world, "p_admin"), P, "view"), (account(world, "p_analyst"), P, "view"),
            (account(world, "tech_full"), X, "full"), (account(world, "tech_view"), X, "view"), (account(world, "tech_mixed_a"), X, "view"), (account(world, "tech_mixed_b"), X, "full"), (account(world, "admin_full"), X, "full"),
        }, "who, where they come from, and at which level"

    def test_only_that_tenants_grants_are_listed(self, world):
        assert {g["account_name"] for g in self.list(world, "p_admin", "C2").json()} == {account(world, "p_admin"), account(world, "tech_full")}
        assert self.list(world, "x_admin", "X").json() == []

    def test_the_listing_follows_the_same_who_may_manage_rule(self, world):
        assert self.list(world, "x_admin", "C1").status_code == 404 and self.list(world, "c1_admin", "C2").status_code == 404
        assert self.list(world, "platform", "C1").status_code == 200 and self.list(world, "p_admin", "C1").status_code == 200

    def test_it_needs_users_read(self, world):
        assert self.list(world, "p_service", "P").status_code == 403

    def test_the_unauthenticated_are_refused(self, world, monkeypatch):
        # Stated, not assumed: in DEVELOPMENT mode a request with no credentials is deliberately the demo user. Several other test files set ENVIRONMENT=development when they are imported, which puts the whole full-suite run in that mode.
        monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
        assert world.client.get(f"/api/v1/tenants/{world.tenants['C1'].id}/access").status_code in (401, 403)

    def test_in_development_mode_a_request_with_no_credentials_is_the_demo_user_who_still_cannot_manage_a_tenant_that_is_not_theirs(self, world, monkeypatch):
        """The documented development fallback does not widen this: the demo user is just another principal, so the management rule applies to it (the same 404 as for a stranger)."""
        monkeypatch.setattr(deps, "is_dev_mode", lambda: True)
        r = world.client.get(f"/api/v1/tenants/{world.tenants['C1'].id}/access")
        assert r.status_code == 404 and r.json() == {"detail": "Tenant not found"}


class TestRevokingAccess:
    def test_revoking_takes_effect_on_their_very_next_request(self, world, audits):
        assert who_answers(world, "p_analyst", "C1")[0] == 200
        r = delete(world, "c1_admin", "C1", account(world, "p_analyst"))
        assert r.status_code == 204 and r.content == b""
        assert who_answers(world, "p_analyst", "C1")[0] == 403

    def test_it_removes_that_grant_only(self, world, audits):
        delete(world, "platform", "C1", account(world, "p_analyst"))
        assert who_answers(world, "p_admin", "C1")[0] == 200 and who_answers(world, "p_admin", "C2")[0] == 200

    def test_revoking_what_does_not_exist_is_a_404_and_audits_nothing(self, world, audits):
        assert delete(world, "platform", "C2", account(world, "p_analyst")).status_code == 404
        assert delete(world, "platform", "C1", "nobody-by-that-name").status_code == 404 and audits == []

    def test_only_people_who_may_manage_the_tenant_can_revoke(self, world, audits):
        assert delete(world, "x_admin", "C1", account(world, "p_analyst")).status_code == 404
        assert who_answers(world, "p_analyst", "C1")[0] == 200 and audits == []

    def test_it_needs_users_write(self, world, audits):
        assert delete(world, "p_service", "P", account(world, "p_analyst")).status_code == 403

    def test_the_revocation_is_audited_in_the_target_tenants_own_log(self, world, audits):
        delete(world, "c1_admin", "C1", account(world, "p_analyst"))
        (event,) = audits
        assert event["tenant_id"] == world.tenants["C1"].id and event["action"] == "tenant:access_revoked"
        assert event["actor_id"] == world.users["c1_admin"].id and event["resource_id"] == str(world.users["p_analyst"].id)
        assert event["changes"] == {"account_name": account(world, "p_analyst"), "home_tenant_id": str(world.tenants["P"].id)}

    def test_a_revoked_person_can_be_granted_again(self, world, audits):
        delete(world, "platform", "C1", account(world, "p_analyst"))
        assert put(world, "platform", "C1", account(world, "p_analyst")).status_code == 200 and who_answers(world, "p_analyst", "C1")[0] == 200


class TestTheGrantsTableAndTheRule:
    SQL = " ".join((Path(__file__).resolve().parent.parent / "migrations" / "072_tenant_access_grants.sql").read_text().split())

    def test_the_migration_creates_what_the_model_declares(self):
        for column in TenantAccessGrant.__table__.columns:
            assert column.name in self.SQL, column.name

    def test_one_grant_per_person_and_tenant_and_it_goes_with_either(self):
        assert "UNIQUE (user_id, tenant_id)" in self.SQL
        assert "user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE" in self.SQL and "tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE" in self.SQL

    def test_the_grant_survives_its_granters_deletion_with_the_label_kept(self):
        assert "granted_by UUID REFERENCES users (id) ON DELETE SET NULL" in self.SQL and "granted_by_label TEXT NOT NULL" in self.SQL

    def test_only_view_access_exists_and_row_level_security_is_the_standard_policy_on_the_granted_tenant(self):
        assert "CHECK (access IN ('view'))" in self.SQL
        assert "ENABLE ROW LEVEL SECURITY" in self.SQL and "USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)" in self.SQL

    def test_the_blanket_children_rule_is_gone(self):
        import inspect

        assert not hasattr(view_as, "MSSP_READ_PERMISSION")
        assert "parent_tenant_id" not in inspect.getsource(view_as.may_view_tenant) and "parent_tenant_id" not in inspect.getsource(view_as.viewable_tenants)

    def test_the_grants_are_the_persons_own_never_another_persons(self, world):
        T = world.tenants
        for who, expected in (("p_admin", {T["C1"].id, T["C2"].id}), ("p_analyst", {T["C1"].id}), ("p_viewer", set()), ("platform", set())):
            u = world.users[who]
            principal = deps.CurrentUser(user_id=u.id, tenant_id=u.tenant_id, role=u.role, email=u.email)
            async def go(s, principal=principal):
                return await view_as.granted_tenant_ids(s, principal)

            async def run_it(go=go):
                async with world.factory() as s:
                    return await go(s)

            assert asyncio.run(run_it()) == expected, who


class TestCapabilities:
    """What the console is told a person may do, so it does not show controls they cannot use. The server still checks every action."""

    def test_the_capability_names_are_derived_from_real_permissions(self):
        from app.core.security import UI_CAPABILITIES, capabilities_for_role

        assert UI_CAPABILITIES == {"platform_admin": "platform:cross_tenant_query", "manage_users": "users:write"}
        assert capabilities_for_role("platform_admin") == ["manage_users", "platform_admin"]
        assert capabilities_for_role("no-such-role") == []

    @pytest.mark.parametrize("who,expected", [("platform", ["manage_users", "platform_admin"]), ("p_admin", ["manage_users"]), ("c1_admin", ["manage_users"]), ("p_lead", []), ("p_analyst", []), ("p_viewer", []), ("p_service", [])])
    def test_me_tells_the_console_what_each_kind_of_person_may_do(self, world, who, expected):
        r = world.client.get("/api/v1/auth/me", headers=world.auth(who))
        assert r.status_code == 200 and r.json()["capabilities"] == expected, who

    def test_every_built_in_role_gets_the_right_capabilities(self):
        from app.core.security import ROLE_PERMISSIONS, capabilities_for_role

        got = {role: capabilities_for_role(role) for role in ROLE_PERMISSIONS}
        assert got == {"platform_admin": ["manage_users", "platform_admin"], "admin": ["manage_users"], "tenant_admin": ["manage_users"], "soc_lead": [], "soc_analyst": [], "threat_hunter": [], "viewer": [], "api_service": []}

    def test_a_capability_is_exactly_the_permission_it_stands_for(self):
        """If a role holds the permission it has the capability, and never otherwise: nothing is granted by the name."""
        from app.core.security import ROLE_PERMISSIONS, UI_CAPABILITIES, capabilities_for_role, has_permission

        for role in ROLE_PERMISSIONS:
            for name, permission in UI_CAPABILITIES.items():
                assert (name in capabilities_for_role(role)) == has_permission(role, permission), (role, name)

    def test_saving_a_preference_does_not_make_the_console_lose_them(self, world):
        r = world.client.patch("/api/v1/auth/me/preferences", headers=world.auth("p_admin"), json={"preferences": {"theme": "dark"}})
        assert r.status_code == 200 and r.json()["capabilities"] == ["manage_users"]


class TestManageableTenants:
    """GET /tenants/manageable: the tenants whose access this caller may manage. The same rule as the grant routes, so the screen can only offer what the server will honour."""

    def listing(self, world, who):
        r = world.client.get("/api/v1/tenants/manageable", headers=world.auth(who))
        assert r.status_code == 200, r.text
        return [(t["relationship"], t["id"]) for t in r.json()["tenants"]]

    def test_a_platform_admin_may_manage_every_tenant_their_own_first(self, world):
        T = world.tenants
        got = self.listing(world, "platform")
        assert got[0] == ("self", str(T["PL"].id)) and {i for _, i in got} == {str(t.id) for t in T.values()} and len(got) == len(T)
        assert {r for r, _ in got[1:]} <= {"child", "other"}

    def test_an_msps_admin_manages_their_own_tenant_and_their_customers(self, world):
        T = world.tenants
        assert self.listing(world, "p_admin") == [("self", str(T["P"].id)), ("child", str(T["C1"].id)), ("child", str(T["C2"].id))]

    def test_a_customers_admin_manages_only_their_own_tenant_never_their_parent_or_a_sibling(self, world):
        T = world.tenants
        assert self.listing(world, "c1_admin") == [("self", str(T["C1"].id))] and self.listing(world, "x_admin") == [("self", str(T["X"].id))]

    @pytest.mark.parametrize("who", ["p_viewer", "p_analyst", "p_service", "p_lead"])
    def test_a_role_that_cannot_manage_access_is_offered_nothing(self, world, who):
        r = world.client.get("/api/v1/tenants/manageable", headers=world.auth(who))
        assert (r.status_code == 200 and r.json()["tenants"] == []) or r.status_code == 403

    def test_what_the_list_offers_is_exactly_what_the_server_lets_them_grant_on(self, world):
        """For every person and every tenant: it is in the list if and only if the server would accept a grant request for it (the manage check passes: not the 404)."""
        for who in ("platform", "p_admin", "c1_admin", "c2_admin", "x_admin"):
            offered = {i for _, i in self.listing(world, who)}
            for name, t in world.tenants.items():
                r = world.client.put(f"/api/v1/tenants/{t.id}/access/nobody-by-that-name", headers=world.auth(who))
                allowed = r.status_code != 404 or r.json().get("detail") != "Tenant not found"
                assert (str(t.id) in offered) == allowed, f"{who} -> {name}: offered={str(t.id) in offered} allowed={allowed} ({r.status_code} {r.text[:60]})"

    def test_the_answer_names_the_callers_home_tenant(self, world):
        r = world.client.get("/api/v1/tenants/manageable", headers=world.auth("p_admin"))
        assert r.json()["home_tenant_id"] == str(world.tenants["P"].id)

    def test_the_unauthenticated_are_refused(self, world, monkeypatch):
        monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
        assert world.client.get("/api/v1/tenants/manageable").status_code in (401, 403)

    def test_it_is_not_swallowed_by_a_tenant_id_route(self, world):
        assert world.client.get("/api/v1/tenants/manageable", headers=world.auth("platform")).status_code == 200


# ======================================================================================================================================================================
# FULL ACCESS: a grant can be `full` (read and write, as the person's own role allows), and a person can be granted ALL tenants. Migration 074.
# ======================================================================================================================================================================
ALL = ["P", "C1", "C2", "X", "PL"]
# who may WRITE in which tenant through the probe route (alerts:write), besides their own tenant: exactly the FULL grants, specific or all-tenants, the stronger of the two winning
FULL_IN = {"tech_full": {"C1"}, "tech_all_full": set(ALL), "tech_mixed_a": set(ALL), "tech_mixed_b": {"C1"}, "admin_full": {"C1"}, "platform_all_full": set(ALL)}
HOME = {"p_admin": "P", "p_analyst": "P", "c1_admin": "C1", "c2_admin": "C2", "x_admin": "X", "platform": "PL", "tech_full": "X", "tech_view": "X", "tech_all_full": "X", "tech_all_view": "X", "tech_mixed_a": "X", "tech_mixed_b": "X", "admin_full": "X", "platform_all_full": "PL"}


def write(world, who, tenant=None, path="/api/v1/probe/write", method="post"):
    headers = {**world.auth(who), **({V: str(world.tenants[tenant].id)} if tenant else {})}
    return world.client.request(method.upper(), path, headers=headers)


def handled(world):
    return [e for e in world.events if e[0] == "handler"]


class TestWritingWithFullAccess:
    def test_a_full_grant_lets_the_person_write_in_that_tenant_acting_as_themselves_not_as_the_tenant(self, world):
        r = write(world, "tech_full", "C1")
        T, u = world.tenants, world.users["tech_full"]
        assert r.status_code == 200 and r.json() == {"tenant_id": str(T["C1"].id), "home_tenant_id": str(T["X"].id), "access": "full"}
        assert r.headers[VIEWING_HEADER] == str(T["C1"].id) and r.headers["X-Viewing-Access"] == "full"
        assert world.events == [("audit", u.id, T["C1"].id, "full", "POST", "/api/v1/probe/write"), ("handler", "write", T["C1"].id, T["X"].id, "full")]

    def test_the_write_is_recorded_in_the_tenants_own_log_BEFORE_it_is_carried_out(self, world):
        write(world, "tech_full", "C1")
        assert [e[0] for e in world.events] == ["audit", "handler"]

    def test_if_the_record_cannot_be_written_the_write_is_not_performed(self, world):
        world.audit_state["fail"] = True
        with pytest.raises(RuntimeError, match="audit store down"):
            write(world, "tech_full", "C1")
        assert handled(world) == [], "an unrecorded write must not happen"

    def test_every_write_is_recorded_not_one_per_fifteen_minutes_like_a_view(self, world):
        for _ in range(3):
            write(world, "tech_full", "C1")
        assert [e[0] for e in world.events] == ["audit", "handler"] * 3

    def test_both_write_methods_are_allowed_and_recorded_with_their_method(self, world):
        write(world, "tech_full", "C1", method="post"), write(world, "tech_full", "C1", method="delete")
        assert [e[4] for e in world.events if e[0] == "audit"] == ["POST", "DELETE"]

    def test_with_view_access_a_write_is_refused_and_nothing_is_recorded_or_done(self, world):
        for who, tenant in (("tech_view", "C1"), ("tech_full", "C2"), ("tech_all_view", "C1"), ("tech_mixed_b", "C2"), ("platform", "C1"), ("p_admin", "C1")):
            r = write(world, who, tenant)
            assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only", (who, tenant)
        assert world.events == []

    def test_with_no_grant_it_is_forbidden_and_looks_the_same_as_a_tenant_that_does_not_exist(self, world):
        real, ghost = write(world, "x_admin", "C1"), world.client.post("/api/v1/probe/write", headers={**world.auth("x_admin"), V: str(uuid.uuid4())})
        assert (real.status_code, real.headers[ERROR_HEADER], real.json()) == (ghost.status_code, ghost.headers[ERROR_HEADER], ghost.json()) and real.status_code == 403 and real.headers[ERROR_HEADER] == "forbidden"
        assert world.events == []

    @pytest.mark.parametrize("method", ["post", "delete"])
    def test_for_every_person_and_every_tenant_a_write_is_allowed_exactly_where_they_hold_FULL_or_it_is_their_own(self, world, method):
        for who, home in HOME.items():
            for tenant in ALL:
                world.events.clear()
                r = write(world, who, tenant, method=method)
                allowed = tenant == home or tenant in FULL_IN.get(who, set())
                assert (r.status_code == 200) == allowed, f"{who} -> {tenant} {method}: {r.status_code} {r.text[:80]}"
                if allowed:
                    assert handled(world)[0][2] == world.tenants[tenant].id, "the write ran for that tenant"
                    assert (len(world.events) == 2) == (tenant != home), "the cross-tenant write was recorded first; the person's own tenant needs no such record"
                else:
                    assert r.headers[ERROR_HEADER] in ("forbidden", "read_only") and world.events == []

    def test_a_write_in_a_persons_own_tenant_is_unchanged_and_carries_no_acting_level(self, world):
        r = write(world, "tech_full")
        assert r.status_code == 200 and r.json()["access"] is None and r.json()["tenant_id"] == r.json()["home_tenant_id"] and [e[0] for e in world.events] == ["handler"]

    def test_the_stronger_of_a_specific_grant_and_an_all_tenants_grant_wins(self, world):
        assert write(world, "tech_mixed_a", "C1").status_code == 200, "view on C1 + everything full: full"
        assert write(world, "tech_mixed_b", "C1").status_code == 200, "full on C1 + everything view: full"
        assert write(world, "tech_mixed_b", "C2").status_code == 403, "...but only on C1"
        assert write(world, "tech_mixed_a", "C2").status_code == 200

    def test_an_all_tenants_grant_covers_a_tenant_created_later_and_a_specific_one_does_not(self, world):
        with Session(world.sync) as s:
            new = Tenant(id=uuid.uuid4(), name="Created Later", slug="later-" + uuid.uuid4().hex[:6])
            s.add(new)
            s.commit()
            new_id = new.id
        headers = lambda who: {**world.auth(who), V: str(new_id)}  # noqa: E731
        assert world.client.post("/api/v1/probe/write", headers=headers("tech_all_full")).status_code == 200
        assert world.client.post("/api/v1/probe/write", headers=headers("tech_full")).status_code == 403
        assert world.client.get("/api/v1/tenants/me/identity", headers=headers("tech_all_view")).status_code == 200

    def test_a_platform_admin_alone_still_reads_everything_but_writes_nowhere_else(self, world):
        assert world.client.get("/api/v1/tenants/me/identity", headers={**world.auth("platform"), V: str(world.tenants["C1"].id)}).status_code == 200
        assert write(world, "platform", "C1").status_code == 403
        assert write(world, "platform_all_full", "C1").status_code == 200, "an all-tenants FULL grant is what lets a platform admin write"

    def test_revoking_a_full_grant_takes_effect_on_the_very_next_request(self, world):
        assert write(world, "tech_full", "C1").status_code == 200
        with Session(world.sync) as s:
            s.query(TenantAccessGrant).filter_by(user_id=world.users["tech_full"].id, tenant_id=world.tenants["C1"].id).delete()
            s.commit()
        r = write(world, "tech_full", "C1")
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "forbidden"

    def test_downgrading_full_to_view_takes_effect_on_the_very_next_request(self, world):
        assert write(world, "tech_full", "C1").status_code == 200
        with Session(world.sync) as s:
            s.query(TenantAccessGrant).filter_by(user_id=world.users["tech_full"].id, tenant_id=world.tenants["C1"].id).update({"access": "view"})
            s.commit()
        r = write(world, "tech_full", "C1")
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"
        assert world.client.get("/api/v1/tenants/me/identity", headers={**world.auth("tech_full"), V: str(world.tenants["C1"].id)}).status_code == 200, "they can still read it"

    def test_removing_an_all_tenants_grant_takes_effect_on_the_very_next_request(self, world):
        assert write(world, "tech_all_full", "C2").status_code == 200
        with Session(world.sync) as s:
            s.query(AllTenantAccessGrant).filter_by(user_id=world.users["tech_all_full"].id).delete()
            s.commit()
        assert write(world, "tech_all_full", "C2").status_code == 403

    def test_the_principal_knows_it_is_acting_with_full_access_and_otherwise_does_not(self, world):
        helper = TestThePrincipalWhileViewing()
        acting = helper.principal(world, "tech_full", world.tenants["C1"].id, method="POST", path="/api/v1/probe/write")
        assert acting.acting_access == "full" and acting.viewing_other_tenant is True and acting.home_tenant_id == world.tenants["X"].id
        reading = helper.principal(world, "tech_full", world.tenants["C2"].id)
        assert reading.acting_access == "view"
        plain = helper.principal(world, "tech_full", None)
        assert plain.acting_access is None and plain.viewing_other_tenant is False

    def test_the_acting_context_is_left_on_the_request_for_the_audit_middleware(self, world):
        helper = TestThePrincipalWhileViewing()
        req = helper.request(world.tenants["C1"].id, method="POST", path="/api/v1/probe/write")
        creds = SimpleNamespace(credentials=world.auth("tech_full")["Authorization"].split(" ", 1)[1])

        async def go():
            async with world.factory() as s:
                return await deps.get_current_user(creds, s, req, SimpleNamespace(headers={}))

        asyncio.run(go())
        assert (req.state.acting_tenant_id, req.state.acting_home_tenant_id, req.state.acting_access) == (world.tenants["C1"].id, world.tenants["X"].id, "full")


class TestWhatFullAccessStillCannotDo:
    """Even with FULL access, identity and credential administration (users, roles, API keys, who has access, platform and MSSP administration) is refused: a stolen technician login must not be able to plant a hidden administrator or a long-lived key in every customer."""

    @pytest.mark.parametrize("who", ["tech_full", "admin_full", "tech_all_full", "platform_all_full"])
    def test_creating_a_user_in_another_tenant_is_refused_and_nothing_is_created_or_recorded(self, world, who):
        with Session(world.sync) as s:
            before = len(s.scalars(select(User.id)).all())
        r = world.client.post("/api/v1/tenants/me/users", headers={**world.auth(who), V: str(world.tenants["C1"].id)}, json={"account_name": "planted.admin", "password": "Str0ng-Passw0rd!", "role": "admin"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "not_allowed_here" and "another tenant" in r.json()["detail"]
        with Session(world.sync) as s:
            assert len(s.scalars(select(User.id)).all()) == before
        assert world.events == [], "refused before anything is recorded or done"

    def test_changing_a_user_in_another_tenant_is_refused_too_and_the_role_is_not_changed(self, world):
        """The route that exists is PATCH /tenants/me/users/{id}; the path rule for every method is covered by the matrix below."""
        target = world.users["c1_admin"].id
        r = world.client.patch(f"/api/v1/tenants/me/users/{target}", headers={**world.auth("admin_full"), V: str(world.tenants["C1"].id)}, json={"role": "viewer"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "not_allowed_here"
        with Session(world.sync) as s:
            assert s.get(User, target).role == "admin"
        assert world.events == []

    def test_nobody_can_change_who_has_access_while_working_in_another_tenant_not_even_to_themselves(self, world):
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'tech_view')}", headers={**world.auth("admin_full"), V: str(world.tenants["C1"].id)}, json={"access": "full"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "not_allowed_here"
        r = world.client.delete(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'tech_view')}", headers={**world.auth("admin_full"), V: str(world.tenants["C1"].id)})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "not_allowed_here"

    def test_with_view_access_the_same_requests_are_read_only_not_allowed_here(self, world):
        r = world.client.post("/api/v1/tenants/me/users", headers={**world.auth("tech_view"), V: str(world.tenants["C1"].id)}, json={"account_name": "x.y", "password": "Str0ng-Passw0rd!"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    @pytest.mark.parametrize("path", [
        "/api/v1/tenants/me/users", "/api/v1/tenants/me/users/abc", f"/api/v1/tenants/{uuid.uuid4()}/access", f"/api/v1/tenants/{uuid.uuid4()}/access/some.name", "/api/v1/api-keys", "/api/v1/api-keys/abc",
        "/api/v1/rbac/roles", "/api/v1/rbac", "/api/v1/platform/alert-email", "/api/v1/platform/all-tenant-access/x", "/api/v1/mssp/children", "/api/v1/mssp",
    ])
    def test_every_identity_credential_platform_and_mssp_route_is_blocked_for_a_write_with_full_access(self, world, method, path):
        user = SimpleNamespace(user_id=world.users["tech_all_full"].id, tenant_id=world.tenants["X"].id, holds=lambda p: False)

        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, user, str(world.tenants["C1"].id), method, path)

        with pytest.raises(HTTPException) as e:
            asyncio.run(go())
        assert e.value.status_code == 403 and e.value.headers[ERROR_HEADER] == "not_allowed_here"

    @pytest.mark.parametrize("method,path", [
        ("POST", "/api/v1/alerts/abc/claim"), ("POST", "/api/v1/cases"), ("PATCH", "/api/v1/cases/abc"), ("POST", "/api/v1/connectors"), ("PUT", "/api/v1/playbooks/abc"), ("POST", "/api/v1/investigations"),
        ("POST", "/api/v1/remediation/actions"), ("DELETE", "/api/v1/hunts/abc"),
        # lookalikes of a blocked prefix are NOT blocked: the match is on the whole path segment
        ("POST", "/api/v1/api-keys-report"), ("POST", "/api/v1/rbacx"), ("POST", "/api/v1/platformer"), ("POST", "/api/v1/mssp-reports"), ("POST", "/api/v1/tenants/me/usersettings"),
        # and reading the same places is not blocked at all
        ("GET", "/api/v1/tenants/me/users"), ("GET", "/api/v1/api-keys"), ("GET", "/api/v1/rbac/roles"), ("GET", "/api/v1/platform/alert-email"), ("GET", "/api/v1/mssp/children"),
    ])
    def test_everything_else_is_allowed_with_full_access_and_so_are_reads_of_the_blocked_places(self, world, method, path):
        user = SimpleNamespace(user_id=world.users["tech_all_full"].id, tenant_id=world.tenants["X"].id, holds=lambda p: False)

        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, user, str(world.tenants["C1"].id), method, path)

        result = asyncio.run(go())
        assert result.tenant_id == world.tenants["C1"].id and result.access == "full"

    def test_the_wildcard_role_cannot_use_users_write_while_working_in_another_tenant_but_can_at_home(self, world):
        assert write(world, "admin_full", None, path="/api/v1/probe/users-write").status_code == 200, "an admin holds users:write in their own tenant"
        r = write(world, "admin_full", "C1", path="/api/v1/probe/users-write")
        assert r.status_code == 403 and "Not available while working in another tenant: users:write" in r.json()["detail"]
        assert handled(world) == [handled(world)[0]], "only the at-home call ran"

    def test_a_platform_admin_with_full_access_to_a_tenant_loses_the_platform_permissions_there_only(self, world):
        assert write(world, "platform_all_full", None, path="/api/v1/probe/platform").status_code == 200
        r = write(world, "platform_all_full", "C1", path="/api/v1/probe/platform")
        assert r.status_code == 403 and "platform:cross_tenant_query" in r.json()["detail"]

    def test_the_denied_permissions_are_exactly_these(self):
        assert view_as.ACTING_DENIED_PERMISSIONS == frozenset({"users:write", "mssp:manage", "mssp:onboard", "platform:cross_tenant_query", "plugins:admin"})

    def test_an_api_key_still_cannot_work_in_another_tenant_at_all(self, world):
        r = world.client.post("/api/v1/probe/write", headers={"Authorization": "Bearer " + world.api_key, V: str(world.tenants["C1"].id)})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "session_only"

    def test_account_level_routes_still_ignore_the_header_whatever_the_access(self, world):
        r = world.client.get("/api/v1/auth/me", headers={**world.auth("tech_all_full"), V: str(world.tenants["C1"].id)})
        assert r.status_code == 200 and r.json()["tenant_id"] == str(world.tenants["X"].id)


class TestAccessLevelsAreReported:
    def levels(self, world, who):
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth(who))
        assert r.status_code == 200, r.text
        return [(t["relationship"], t["access"], t["id"]) for t in r.json()["tenants"]]

    def test_a_person_sees_their_own_tenant_as_full_and_each_grant_at_its_level(self, world):
        T = world.tenants
        assert self.levels(world, "tech_full") == [("self", "full", str(T["X"].id)), ("granted", "full", str(T["C1"].id)), ("granted", "view", str(T["C2"].id))]

    def test_an_all_tenants_grant_lists_every_other_tenant_at_its_level(self, world):
        T = world.tenants
        full = self.levels(world, "tech_all_full")
        assert full[0] == ("self", "full", str(T["X"].id)) and {i for _, _, i in full} == {str(t.id) for t in T.values()} and {a for _, a, _ in full[1:]} == {"full"} and {r for r, _, _ in full[1:]} == {"granted"}
        assert {a for _, a, _ in self.levels(world, "tech_all_view")[1:]} == {"view"}

    def test_a_platform_admin_sees_every_tenant_as_view_unless_they_also_hold_all_tenants_at_full(self, world):
        assert {a for _, a, _ in self.levels(world, "platform")[1:]} == {"view"} and {r for r, _, _ in self.levels(world, "platform")[1:]} == {"platform"}
        both = self.levels(world, "platform_all_full")
        assert {a for _, a, _ in both[1:]} == {"full"} and {r for r, _, _ in both[1:]} == {"platform"}

    def test_the_stronger_level_is_the_one_listed(self, world):
        T = world.tenants
        a = {i: acc for _, acc, i in self.levels(world, "tech_mixed_a")}
        b = {i: acc for _, acc, i in self.levels(world, "tech_mixed_b")}
        assert a[str(T["C1"].id)] == "full" and b[str(T["C1"].id)] == "full" and b[str(T["C2"].id)] == "view" and a[str(T["C2"].id)] == "full"

    def test_what_is_reported_is_exactly_what_the_server_does_for_every_person_and_tenant(self, world):
        """Listed at `full` if and only if a write there is accepted; listed at `view` if and only if a write is refused as read-only."""
        for who in HOME:
            listed = {i: a for _, a, i in self.levels(world, who)}
            for name in ALL:
                tid = str(world.tenants[name].id)
                r = write(world, who, name)
                if name == HOME[who]:
                    assert listed[tid] == "full" and r.status_code == 200
                elif r.status_code == 200:
                    assert listed.get(tid) == "full", (who, name)
                elif r.headers.get(ERROR_HEADER) == "read_only":
                    assert listed.get(tid) == "view", (who, name)
                else:
                    assert tid not in listed, (who, name)


class TestGrantingFullAccess:
    def test_the_level_defaults_to_view_so_a_request_with_no_body_is_read_only(self, world, audits):
        r = put(world, "platform", "C1", account(world, "x_admin"))
        assert r.status_code == 200 and r.json()["access"] == "view"

    def test_an_empty_body_is_read_only_too(self, world, audits):
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'x_admin')}", headers=world.auth("platform"), json={})
        assert r.status_code == 200 and r.json()["access"] == "view"

    def test_full_can_be_granted_and_the_person_can_then_write_at_once(self, world, audits):
        assert write(world, "x_admin", "C1").status_code == 403
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'x_admin')}", headers=world.auth("platform"), json={"access": "full"})
        assert r.status_code == 200 and r.json()["access"] == "full"
        assert write(world, "x_admin", "C1").status_code == 200

    @pytest.mark.parametrize("body", [{"access": "write"}, {"access": "admin"}, {"access": "FULL"}, {"access": ""}, {"access": None}, {"access": "full", "role": "admin"}, {"extra": 1}])
    def test_an_invalid_body_is_a_422_and_nothing_changes(self, world, audits, body):
        r = world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'x_admin')}", headers=world.auth("platform"), json=body)
        assert r.status_code == 422 and audits == []

    def test_changing_the_level_updates_the_one_grant_and_is_audited_with_before_and_after(self, world, audits):
        call = lambda level: world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'tech_view')}", headers=world.auth("platform"), json={"access": level})  # noqa: E731
        before = len(grants_of(world, "C1"))
        r = call("full")
        assert r.status_code == 200 and r.json()["access"] == "full" and len(grants_of(world, "C1")) == before
        (event,) = audits
        assert event["action"] == "tenant:access_changed" and event["tenant_id"] == world.tenants["C1"].id and event["changes"]["before"] == "view" and event["changes"]["after"] == "full"
        assert write(world, "tech_view", "C1").status_code == 200

    def test_downgrading_stops_the_writes_and_asking_for_the_same_level_again_audits_nothing(self, world, audits):
        call = lambda level, who="tech_full": world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, who)}", headers=world.auth("platform"), json={"access": level})  # noqa: E731
        assert call("full").status_code == 200 and audits == [], "already full: nothing to change, nothing to audit"
        assert call("view").status_code == 200 and [a["action"] for a in audits] == ["tenant:access_changed"]
        r = write(world, "tech_full", "C1")
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"

    def test_a_new_full_grant_is_audited_with_its_level_in_the_target_tenants_log(self, world, audits):
        world.client.put(f"/api/v1/tenants/{world.tenants['C2'].id}/access/{account(world, 'x_admin')}", headers=world.auth("p_admin"), json={"access": "full"})
        (event,) = audits
        assert event["action"] == "tenant:access_granted" and event["tenant_id"] == world.tenants["C2"].id and event["changes"]["access"] == "full"

    @pytest.mark.parametrize("who,tenant,expected", [("c1_admin", "C1", 200), ("p_admin", "C1", 200), ("p_admin", "C2", 200), ("platform", "X", 200), ("x_admin", "C1", 404), ("c1_admin", "C2", 404), ("c1_admin", "P", 404), ("p_viewer", "C1", 403), ("p_lead", "P", 403), ("tech_all_full", "C1", 403)])
    def test_the_same_people_who_may_grant_view_may_grant_full_and_nobody_else_including_a_technician_with_full_access(self, world, audits, who, tenant, expected):
        r = world.client.put(f"/api/v1/tenants/{world.tenants[tenant].id}/access/{account(world, 'x_admin' if tenant != 'X' else 'c1_admin')}", headers=world.auth(who), json={"access": "full"})
        assert r.status_code == expected, (who, tenant, r.status_code, r.text[:80])

    def test_a_viewable_entry_reports_the_level_after_a_change(self, world, audits):
        world.client.put(f"/api/v1/tenants/{world.tenants['C1'].id}/access/{account(world, 'tech_view')}", headers=world.auth("platform"), json={"access": "full"})
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth("tech_view")).json()["tenants"]
        assert {t["id"]: t["access"] for t in r}[str(world.tenants["C1"].id)] == "full"


@pytest.fixture
def all_audits(monkeypatch):
    calls: list[dict] = []

    async def record(**kw):
        calls.append(kw)

    monkeypatch.setattr(pta, "emit_audit", record)
    return calls


ALL_URL = "/api/v1/platform/all-tenant-access"


class TestGrantingAllTenants:
    """Only a platform administrator can hand out EVERY tenant."""

    @pytest.mark.parametrize("who", ["p_admin", "c1_admin", "x_admin", "p_viewer", "p_analyst", "p_lead", "p_service", "admin_full", "tech_all_full", "tech_full"])
    @pytest.mark.parametrize("method,path,body", [("get", "", None), ("put", "/some.account", {"access": "full"}), ("delete", "/some.account", None)])
    def test_nobody_but_a_platform_administrator_may_use_it_not_even_a_technician_who_already_has_everything(self, world, all_audits, who, method, path, body):
        r = world.client.request(method.upper(), ALL_URL + path, headers=world.auth(who), **({"json": body} if body is not None else {}))
        assert r.status_code == 403 and all_audits == [], (who, method)

    def test_the_unauthenticated_are_refused(self, world, monkeypatch):
        monkeypatch.setattr(deps, "is_dev_mode", lambda: False)
        assert world.client.get(ALL_URL).status_code in (401, 403)

    def test_a_platform_admin_grants_all_tenants_and_the_person_can_then_work_in_every_one(self, world, all_audits):
        assert write(world, "x_admin", "C1").status_code == 403
        r = world.client.put(f"{ALL_URL}/{account(world, 'x_admin')}", headers=world.auth("platform"), json={"access": "full"})
        assert r.status_code == 200 and r.json()["access"] == "full" and r.json()["account_name"] == account(world, "x_admin") and r.json()["granted_by"] == "platform@pl.example"
        assert all(write(world, "x_admin", t).status_code == 200 for t in ("P", "C1", "C2", "PL"))

    def test_the_level_must_be_stated_there_is_no_default(self, world, all_audits):
        for body in (None, {}, {"access": "write"}, {"access": None}, {"access": "full", "extra": 1}):
            r = world.client.put(f"{ALL_URL}/{account(world, 'x_admin')}", headers=world.auth("platform"), **({"json": body} if body is not None else {}))
            assert r.status_code == 422, body
        assert all_audits == []

    def test_changing_the_level_and_repeating_it(self, world, all_audits):
        put_all = lambda level: world.client.put(f"{ALL_URL}/{account(world, 'tech_all_view')}", headers=world.auth("platform"), json={"access": level})  # noqa: E731
        assert put_all("view").status_code == 200 and all_audits == [], "already view: nothing to change"
        assert put_all("full").status_code == 200 and [a["action"] for a in all_audits] == ["platform:all_tenant_access_changed"]
        assert all_audits[0]["changes"]["before"] == "view" and all_audits[0]["changes"]["after"] == "full"
        assert write(world, "tech_all_view", "C1").status_code == 200

    def test_it_is_audited_in_the_platform_administrators_own_tenant_log(self, world, all_audits):
        world.client.put(f"{ALL_URL}/{account(world, 'x_admin')}", headers=world.auth("platform"), json={"access": "view"})
        (event,) = all_audits
        assert event["action"] == "platform:all_tenant_access_granted" and event["tenant_id"] == world.tenants["PL"].id and event["actor_id"] == world.users["platform"].id
        assert event["changes"] == {"account_name": account(world, "x_admin"), "home_tenant_id": str(world.tenants["X"].id), "before": None, "after": "view"}

    def test_it_lists_who_has_every_tenant_and_at_which_level(self, world, all_audits):
        r = world.client.get(ALL_URL, headers=world.auth("platform")).json()
        assert {(g["account_name"], g["access"], g["home_tenant_id"]) for g in r} == {(account(world, who), level, str(world.tenants[HOME[who]].id)) for who, level in (("tech_all_full", "full"), ("tech_all_view", "view"), ("tech_mixed_a", "full"), ("tech_mixed_b", "view"), ("platform_all_full", "full"))}

    def test_revoking_ends_it_at_once_and_leaves_the_persons_specific_grants_alone(self, world, all_audits):
        assert write(world, "tech_mixed_a", "C2").status_code == 200
        r = world.client.delete(f"{ALL_URL}/{account(world, 'tech_mixed_a')}", headers=world.auth("platform"))
        assert r.status_code == 204 and [a["action"] for a in all_audits] == ["platform:all_tenant_access_revoked"] and all_audits[0]["changes"]["before"] == "full"
        assert write(world, "tech_mixed_a", "C2").status_code == 403
        assert world.client.get("/api/v1/tenants/me/identity", headers={**world.auth("tech_mixed_a"), V: str(world.tenants["C1"].id)}).status_code == 200, "their specific VIEW grant on C1 remains"

    def test_unknown_inactive_and_missing_grants(self, world, all_audits):
        assert world.client.put(f"{ALL_URL}/nobody-by-that-name", headers=world.auth("platform"), json={"access": "view"}).status_code == 404
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.tenants["X"].id, email="gone2@x.example", username="gone2", account_name="gone-two", hashed_password="x", role="admin", is_active=False))
            s.commit()
        r = world.client.put(f"{ALL_URL}/gone-two", headers=world.auth("platform"), json={"access": "view"})
        assert r.status_code == 422 and "deactivated" in r.json()["detail"]
        assert world.client.delete(f"{ALL_URL}/{account(world, 'x_admin')}", headers=world.auth("platform")).status_code == 404
        assert world.client.delete(f"{ALL_URL}/nobody-by-that-name", headers=world.auth("platform")).status_code == 404
        assert all_audits == []

    def test_it_cannot_be_used_from_inside_another_tenant_even_by_a_platform_administrator_with_full_access(self, world, all_audits):
        r = world.client.put(f"{ALL_URL}/{account(world, 'x_admin')}", headers={**world.auth("platform_all_full"), V: str(world.tenants["C1"].id)}, json={"access": "full"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "not_allowed_here" and all_audits == []
        r = world.client.put(f"{ALL_URL}/{account(world, 'x_admin')}", headers={**world.auth("platform"), V: str(world.tenants["C1"].id)}, json={"access": "full"})
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "read_only"


class TestTheAuditTrailForActingInAnotherTenant:
    def test_the_middleware_files_the_outcome_under_the_tenant_the_request_was_for_with_where_the_person_came_from(self):
        from app.middleware.audit_middleware import _acting_context

        C1, X = uuid.uuid4(), uuid.uuid4()
        req = SimpleNamespace(state=SimpleNamespace(acting_tenant_id=C1, acting_home_tenant_id=X, acting_access="full"))
        assert _acting_context(req) == (C1, {"acting_from_tenant_id": str(X), "access": "full"})

    @pytest.mark.parametrize("state", [SimpleNamespace(), None])
    def test_an_ordinary_request_is_filed_under_the_persons_own_tenant_as_before(self, state):
        from app.middleware.audit_middleware import _acting_context

        assert _acting_context(SimpleNamespace(state=state) if state is not None else SimpleNamespace()) is None

    def test_the_intent_record_names_who_from_where_with_which_role_method_and_path(self, monkeypatch):
        calls: list[dict] = []

        async def emit(**kw):
            calls.append(kw)

        class Db:
            committed = 0

            async def commit(self):
                self.committed += 1

        monkeypatch.setattr(view_as, "emit_audit", emit)
        C1, X, U = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        user = SimpleNamespace(user_id=U, tenant_id=X, email="tech@x.example", role="soc_analyst")
        req = SimpleNamespace(method="POST", url=SimpleNamespace(path="/api/v1/cases"))
        db = Db()
        asyncio.run(view_as.record_act_as(db, user, C1, "full", req))
        (c,) = calls
        assert (c["tenant_id"], c["actor_id"], c["actor_email"], c["action"], c["resource"], c["resource_id"]) == (C1, U, "tech@x.example", "tenant:acted", "tenant", str(C1))
        assert c["changes"] == {"acted_from_tenant_id": str(X), "role": "soc_analyst", "access": "full", "method": "POST", "path": "/api/v1/cases"} and db.committed == 1

    def test_if_the_intent_record_fails_the_error_is_not_swallowed(self, monkeypatch):
        async def emit(**kw):
            raise RuntimeError("audit down")

        monkeypatch.setattr(view_as, "emit_audit", emit)
        with pytest.raises(RuntimeError):
            asyncio.run(view_as.record_act_as(SimpleNamespace(commit=lambda: None), SimpleNamespace(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), email="a@b", role="r"), uuid.uuid4(), "full", SimpleNamespace(method="POST", url=SimpleNamespace(path="/x"))))


class TestMigration074AndTheModels:
    SQL = " ".join((Path(__file__).resolve().parent.parent / "migrations" / "074_full_access_and_all_tenant_grants.sql").read_text().split())

    def test_the_level_check_allows_view_and_full_only(self):
        assert "DROP CONSTRAINT IF EXISTS tenant_access_grants_access_check" in self.SQL and "CHECK (access IN ('view', 'full'))" in self.SQL

    def test_the_all_tenants_table_is_keyed_by_person_has_a_level_check_and_no_tenant_id_so_no_rls_is_owed(self):
        assert "user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE" in self.SQL and "access VARCHAR(16) NOT NULL CHECK (access IN ('view', 'full'))" in self.SQL
        assert "tenant_id" not in self.SQL.split("CREATE TABLE IF NOT EXISTS all_tenant_access_grants")[1]

    def test_the_migration_creates_what_the_model_declares(self):
        for column in AllTenantAccessGrant.__table__.columns:
            assert column.name in self.SQL, column.name

    def test_the_levels_are_defined_once(self):
        from app.models.tenant_access import ACCESS_FULL, ACCESS_LEVELS, ACCESS_VIEW

        assert ACCESS_LEVELS == (ACCESS_VIEW, ACCESS_FULL) == ("view", "full")

    def test_an_existing_installation_keeps_every_grant_as_view(self):
        assert "UPDATE" not in self.SQL.upper().replace("ON UPDATE", "") and "DELETE FROM" not in self.SQL.upper()


class TestTheAccessLevelRule:
    """access_level(user, tenant, grants): what a person may do in a tenant. The callers special-case the person's own tenant, so this pins the rule itself, branch by branch."""

    HOME, OTHER, THIRD = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    def person(self, platform=False):
        return SimpleNamespace(user_id=uuid.uuid4(), tenant_id=self.HOME, holds=lambda p: platform and p == "platform:cross_tenant_query")

    @pytest.mark.parametrize("platform,by_tenant,everywhere,tenant,expected", [
        (False, {}, None, "HOME", "full"),  # their own tenant: always full
        (False, {"OTHER": "view"}, "view", "HOME", "full"),  # grants do not demote it
        (False, {}, None, "OTHER", None),  # a stranger: nothing
        (False, {"THIRD": "full"}, None, "OTHER", None),  # a grant to a DIFFERENT tenant is nothing here
        (False, {"OTHER": "view"}, None, "OTHER", "view"),
        (False, {"OTHER": "full"}, None, "OTHER", "full"),
        (False, {}, "view", "OTHER", "view"),
        (False, {}, "full", "OTHER", "full"),
        (False, {"OTHER": "view"}, "full", "OTHER", "full"),  # the stronger wins, either way round
        (False, {"OTHER": "full"}, "view", "OTHER", "full"),
        (False, {"OTHER": "view"}, "view", "OTHER", "view"),
        (True, {}, None, "OTHER", "view"),  # the platform permission alone: read-only
        (True, {"OTHER": "full"}, None, "OTHER", "full"),
        (True, {}, "full", "OTHER", "full"),
        (True, {"OTHER": "view"}, "view", "OTHER", "view"),
    ])
    def test_the_level_for_each_combination(self, platform, by_tenant, everywhere, tenant, expected):
        ids = {"HOME": self.HOME, "OTHER": self.OTHER, "THIRD": self.THIRD}
        grants = view_as.Grants({ids[k]: v for k, v in by_tenant.items()}, everywhere)
        assert view_as.access_level(self.person(platform), ids[tenant], grants) == expected

    def test_stronger_picks_the_higher_level_and_treats_nothing_as_the_lowest(self):
        assert [view_as._stronger(a, b) for a, b in (("view", "full"), ("full", "view"), ("view", "view"), ("full", "full"), (None, "view"), ("view", None), (None, None))] == ["full", "full", "view", "full", "view", "view", None]

    def test_may_view_tenant_still_answers_the_yes_or_no_for_ids_and_for_levels(self):
        T = SimpleNamespace(id=self.OTHER)
        assert view_as.may_view_tenant(self.person(), T) is False
        assert view_as.may_view_tenant(self.person(), T, granted={self.OTHER}) is True
        assert view_as.may_view_tenant(self.person(), T, granted={self.OTHER: "full"}) is True
        assert view_as.may_view_tenant(self.person(), T, all_access="view") is True
        assert view_as.may_view_tenant(self.person(), SimpleNamespace(id=self.HOME)) is True


class TestTheRealAuditMiddlewareFilesUnderTheRightTenant:
    """Through the REAL middleware (a fake database session catches the row): the outcome of a request served for another tenant goes into THAT tenant's log, naming where the person came from; an ordinary request is still filed under the token's own tenant. Also proves that state set inside
    a route is visible to the middleware afterwards, which the whole design relies on."""

    def run(self, monkeypatch, acting):
        from fastapi import Request

        from app.middleware import audit_middleware as am

        added: list = []

        class FakeDb:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def add(self, event):
                added.append(event)

            async def commit(self):
                pass

        async def no_previous(db, tenant):
            return None

        monkeypatch.setattr(am, "AsyncSessionLocal", lambda: FakeDb())
        monkeypatch.setattr("app.services.audit._resolve_prev_hash", no_previous)
        home, other, person = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        app = FastAPI()
        app.add_middleware(am.AuditMiddleware)

        @app.post("/api/v1/things/{thing_id}")
        async def thing(request: Request, thing_id: str):
            if acting:
                request.state.acting_tenant_id, request.state.acting_home_tenant_id, request.state.acting_access = other, home, "full"
            return {"ok": True}

        token = create_access_token({"sub": str(person), "tenant_id": str(home), "role": "soc_analyst", "email": "tech@x.example"})
        r = TestClient(app).post(f"/api/v1/things/{uuid.uuid4()}", headers={"Authorization": "Bearer " + token})
        assert r.status_code == 200
        return added, home, other, person

    def test_a_request_served_for_another_tenant_is_filed_in_that_tenants_log_with_where_the_person_came_from(self, monkeypatch):
        added, home, other, person = self.run(monkeypatch, acting=True)
        (event,) = added
        assert event.tenant_id == other and event.actor_id == person and event.actor_email == "tech@x.example"
        assert event.metadata_["acting_from_tenant_id"] == str(home) and event.metadata_["access"] == "full" and event.metadata_["status_code"] == 200
        assert event.entry_hash is not None, "it is chained into that tenant's history"

    def test_an_ordinary_request_is_filed_under_the_token_tenant_as_before(self, monkeypatch):
        added, home, other, person = self.run(monkeypatch, acting=False)
        (event,) = added
        assert event.tenant_id == home and "acting_from_tenant_id" not in event.metadata_ and "access" not in event.metadata_
