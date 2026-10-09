"""Viewing another tenant ("view as"): read-only, for the people entitled to, and never silently ignored.

The console's tenant switcher sent the chosen tenant as `X-Tenant-Id`, which the API never read, so an MSSP operator who "switched" to a customer kept seeing their OWN data under the customer's name. The server now honours an explicit
`X-View-As-Tenant` header, for a tenant the caller may view, for reading only (app.services.view_as). A real SQLite database and the real routers (mounted under /api/v1, as in production, so the account-level path rule sees real paths). Row-level
security follows the viewed tenant because the principal's tenant_id does; SQLite has none, so that was checked on real Postgres as the non-superuser role (the live scenario in the commit message).
"""
import asyncio
import itertools
import logging
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
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
from app.services import view_as
from app.services.view_as import ERROR_HEADER, VIEW_AS_HEADER, VIEWING_HEADER

V = VIEW_AS_HEADER


def tenant(name, parent=None):
    return Tenant(id=uuid.uuid4(), name=name, slug=name.lower() + "-" + uuid.uuid4().hex[:6], parent_tenant_id=parent.id if parent else None, mssp_role="parent" if name == "P" else ("child" if parent else None))


def user(t, email, role):
    return User(id=uuid.uuid4(), tenant_id=t.id, email=email, username=email.split("@")[0], hashed_password="x", role=role)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """P is an MSSP parent with two children (C1, C2); X is unrelated; PL holds a platform admin. Users are minted tokens directly (no password hashing)."""
    path = tmp_path / "viewas.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    P, X, PL = tenant("P"), tenant("X"), tenant("PL")
    C1, C2 = tenant("C1", P), tenant("C2", P)
    users = {
        "p_admin": user(P, "p-admin@p.example", "admin"),
        "p_analyst": user(P, "p-analyst@p.example", "soc_analyst"),
        "p_viewer": user(P, "p-viewer@p.example", "viewer"),
        "p_service": user(P, "p-service@p.example", "api_service"),  # holds alerts:read but NOT mssp:read
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

    def test_an_mssp_operator_may_view_their_own_tenant_and_its_children_only(self, world):
        T = world.tenants
        assert self.listing(world, "p_admin") == [("self", str(T["P"].id)), ("child", str(T["C1"].id)), ("child", str(T["C2"].id))]

    def test_a_child_or_an_unrelated_tenant_may_view_only_itself(self, world):
        T = world.tenants
        for who, own in (("c1_admin", "C1"), ("c2_admin", "C2"), ("x_admin", "X")):
            assert self.listing(world, who) == [("self", str(T[own].id))]

    def test_a_platform_admin_may_view_every_tenant_their_own_first(self, world):
        T = world.tenants
        got = self.listing(world, "platform")
        assert got[0] == ("self", str(T["PL"].id)) and {i for _, i in got} == {str(t.id) for t in T.values()} and {r for r, _ in got[1:]} == {"platform"}
        assert len(got) == len({i for _, i in got}) == len(T), "every tenant exactly once: a set of ids would hide a repeated one"

    def test_a_role_without_the_mssp_read_permission_may_not_view_the_children_even_in_the_parent_tenant(self, world):
        assert self.listing(world, "p_service") == [("self", str(world.tenants["P"].id))]

    def test_a_tenant_is_always_viewable_by_its_own_people_whatever_their_permissions_and_another_is_not_without_a_reason(self, world):
        nobody = SimpleNamespace(tenant_id=world.tenants["P"].id, holds=lambda permission: False)
        assert view_as.may_view_tenant(nobody, world.tenants["P"]) is True
        assert view_as.may_view_tenant(nobody, world.tenants["C1"]) is False and view_as.may_view_tenant(nobody, world.tenants["X"]) is False

    def test_every_rule_is_relative_to_the_persons_home_never_to_the_tenant_being_viewed(self, world):
        """A principal that is already viewing C1 is still P's operator: it may view C2 (P's other child) and its list is P's. It must not reason from C1's position (where C2 would be a stranger)."""
        T = world.tenants
        viewing = deps.CurrentUser(user_id=world.users["p_admin"].id, tenant_id=T["C1"].id, role="admin", email="p-admin@p.example", home_tenant_id=T["P"].id)
        assert view_as.home_tenant_of(viewing) == T["P"].id
        assert view_as.may_view_tenant(viewing, T["C2"]) is True and view_as.may_view_tenant(viewing, T["P"]) is True and view_as.may_view_tenant(viewing, T["X"]) is False

        async def go():
            async with world.factory() as s:
                return await view_as.viewable_tenants(s, viewing), await tn.list_viewable_tenants(current_user=viewing, db=s), await view_as.resolve_view_as(s, viewing, str(T["P"].id), "GET")

        listing, response, naming_home = asyncio.run(go())
        assert [(rel, t.id) for t, rel in listing] == [("self", T["P"].id), ("child", T["C1"].id), ("child", T["C2"].id)]
        assert response.home_tenant_id == T["P"].id and naming_home is None, "naming the home tenant is 'no change', not a view"

    def test_the_answer_names_the_callers_home_tenant(self, world):
        r = world.client.get("/api/v1/tenants/viewable", headers=world.auth("p_admin"))
        assert r.json()["home_tenant_id"] == str(world.tenants["P"].id)

    def test_another_tenants_children_are_never_listed(self, world):
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
        assert emails(get_users(world, "p_admin")) == ["p-admin@p.example", "p-analyst@p.example", "p-service@p.example", "p-viewer@p.example"]

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

    @pytest.mark.parametrize("who,target", [("c1_admin", "P"), ("c1_admin", "C2"), ("c2_admin", "C1"), ("x_admin", "P"), ("x_admin", "C1"), ("p_service", "C1"), ("p_admin", "X"), ("p_admin", "PL")])
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

    def test_the_right_to_view_ends_with_the_relationship(self, world):
        c1 = world.tenants["C1"].id
        assert get_users(world, "p_admin", view=c1).status_code == 200
        with Session(world.sync) as s:
            s.get(Tenant, c1).parent_tenant_id = None
            s.commit()
        r = get_users(world, "p_admin", view=c1)
        assert r.status_code == 403 and r.headers[ERROR_HEADER] == "forbidden"

    def test_a_tenant_with_no_parent_is_not_viewable_by_a_caller_whose_tenant_id_merely_matches_nothing(self, world):
        """A NULL parent must never match: `parent_tenant_id = <caller's tenant>` is false, but a sloppy `==` on two Nones would be true."""
        X, x_admin = world.tenants["X"], "x_admin"
        assert X.parent_tenant_id is None and get_users(world, x_admin, view=world.tenants["PL"].id).status_code == 403


class TestViewingIsReadOnly:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get"])
    def test_reading_methods_are_allowed(self, world, method):
        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, SimpleNamespace(tenant_id=world.tenants["P"].id, holds=lambda p: p == "mssp:read"), str(world.tenants["C1"].id), method)

        assert asyncio.run(go()) == world.tenants["C1"].id

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post", "Delete", "TRACE", "CONNECT"])
    def test_every_other_method_is_refused(self, world, method):
        async def go():
            async with world.factory() as s:
                return await view_as.resolve_view_as(s, SimpleNamespace(tenant_id=world.tenants["P"].id, holds=lambda p: p == "mssp:read"), str(world.tenants["C1"].id), method)

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
