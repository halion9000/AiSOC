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

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import tenants as tn
from app.core.security import create_access_token, hash_api_key
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.models.tenant_access import TenantAccessGrant
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
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__, TenantAccessGrant.__table__])
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
    }
    raw_key = "aisoc_" + uuid.uuid4().hex
    key = ApiKey(id=uuid.uuid4(), tenant_id=P.id, user_id=users["p_admin"].id, name="ci", key_prefix=raw_key[:12], hashed_key=hash_api_key(raw_key), scopes=["*"], is_active=True)
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([P, X, PL, C1, C2, *users.values(), key])
        s.commit()
        s.add_all([TenantAccessGrant(user_id=users[who].id, tenant_id=t.id, granted_by=users["platform"].id, granted_by_label="platform@pl.example") for who, t in (("p_admin", C1), ("p_admin", C2), ("p_analyst", C1))])
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
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(tn.router, prefix="/api/v1")

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    tenants = {"P": P, "C1": C1, "C2": C2, "X": X, "PL": PL}
    token = lambda u: create_access_token({"sub": str(u.id), "tenant_id": str(u.tenant_id), "role": u.role, "email": u.email})  # noqa: E731
    yield SimpleNamespace(client=TestClient(app), views=views, factory=factory, sync=sync, users=users, tenants=tenants, api_key=raw_key, auth=lambda who: {"Authorization": "Bearer " + token(users[who])})
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
        assert emails(get_users(world, "platform", view=world.tenants["X"].id)) == ["x-admin@x.example"]

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

        assert asyncio.run(go()) == world.tenants["C1"].id

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
        return SimpleNamespace(headers={V: str(view)} if view is not None else {}, method=method, url=SimpleNamespace(path=path))

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
        a, b = put(world, "platform", "C1", account(world, "x_admin")), put(world, "platform", "C1", account(world, "x_admin"))
        assert a.status_code == b.status_code == 200 and a.json()["created_at"] == b.json()["created_at"]
        assert len(grants_of(world, "C1")) == 3, "p_admin and p_analyst already had C1; x_admin makes three, however often it is asked"
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
        assert len(grants_of(world, "C1")) == 3, "p_admin, p_analyst and x_admin: still one grant per person"

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
        assert [(g["account_name"], g["home_tenant_id"], g["access"]) for g in r] == sorted([(account(world, "p_admin"), str(world.tenants["P"].id), "view"), (account(world, "p_analyst"), str(world.tenants["P"].id), "view")])

    def test_only_that_tenants_grants_are_listed(self, world):
        assert [g["account_name"] for g in self.list(world, "p_admin", "C2").json()] == [account(world, "p_admin")]
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
