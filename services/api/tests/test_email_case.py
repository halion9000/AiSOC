"""An email address is one account, whatever its letter case.

`users.email` was UNIQUE only case-sensitively, so `Alice@x.com` and `alice@x.com` could both exist. Login matched the exact text, and the check that stops one organisation claiming another's address could be bypassed by changing a letter's case.
Addresses are now compared by `normalize_email`, found through `find_user_by_email` (compares lower(email), so a LEGACY mixed-case account still signs in), and stored lower-cased on creation; migration 070 adds a unique index on lower(email).
A real SQLite database and the real router. The index and the migration's duplicate handling were checked on real Postgres (see the commit message).
"""
import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import tenants as tn
from app.core.emails import normalize_email
from app.core.security import get_password_hash
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.services.user_lookup import find_user_by_email

PASSWORD = "correct horse battery staple"
HASH = get_password_hash(PASSWORD)
APP = Path(__file__).resolve().parent.parent / "app"


@pytest.fixture
def world(tmp_path):
    """Tenant A holds a lower-case account, a LEGACY mixed-case account and an inactive one; tenant B holds a legacy mixed-case account."""
    path = tmp_path / "case.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    ta, tb = (Tenant(id=uuid.uuid4(), name=n, slug=n.lower() + "-" + uuid.uuid4().hex[:6]) for n in ("A", "B"))
    base = datetime(2026, 1, 1, tzinfo=UTC)

    def user(tenant, email, active=True, age=0):
        return User(id=uuid.uuid4(), tenant_id=tenant.id, email=email, username=email.split("@")[0], hashed_password=HASH, role="admin", is_active=active, created_at=base + timedelta(days=age))

    users = {
        "alice": user(ta, "alice@a.example"),
        "legacy": user(ta, "Legacy.User@A.example"),  # stored in mixed case, from before addresses were lower-cased
        "dormant": user(ta, "dormant@a.example", active=False),
        "bob": user(tb, "Bob@B.example"),
    }
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([ta, tb, *users.values()])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    yield SimpleNamespace(client=TestClient(app), sync=sync, factory=factory, ta=ta, tb=tb, users=users)
    sync.dispose()


def run(world, fn):
    async def go():
        async with world.factory() as s:
            return await fn(s)

    return asyncio.run(go())


def login(world, email, password=PASSWORD):
    return world.client.post("/api/v1/auth/login", json={"email": email, "password": password})


def stored(world, address):
    with Session(world.sync) as s:
        return s.scalars(select(User.email).where(func.lower(User.email) == address.lower())).all()


class TestNormalize:
    @pytest.mark.parametrize("raw,want", [("Alice@X.com", "alice@x.com"), ("  alice@x.com ", "alice@x.com"), ("ALICE@X.COM", "alice@x.com"), ("alice@x.com", "alice@x.com"), ("A.B+tag@X.Org", "a.b+tag@x.org"), ("\talice@x.com\n", "alice@x.com")])
    def test_trimmed_and_lower_cased(self, raw, want):
        assert normalize_email(raw) == want

    def test_it_is_idempotent(self):
        assert normalize_email(normalize_email("  MiXeD@Case.COM ")) == "mixed@case.com"


class TestFindUserByEmail:
    @pytest.mark.parametrize("typed", ["alice@a.example", "ALICE@A.EXAMPLE", "Alice@a.example", "  alice@a.example  "])
    def test_any_case_finds_the_account(self, world, typed):
        assert run(world, lambda s: find_user_by_email(s, typed)).id == world.users["alice"].id

    @pytest.mark.parametrize("typed", ["legacy.user@a.example", "LEGACY.USER@A.EXAMPLE", "Legacy.User@A.example"])
    def test_a_legacy_mixed_case_account_is_found_by_any_case(self, world, typed):
        assert run(world, lambda s: find_user_by_email(s, typed)).id == world.users["legacy"].id

    def test_an_unknown_address_is_none(self, world):
        assert run(world, lambda s: find_user_by_email(s, "nobody@nowhere.example")) is None

    def test_active_only_skips_an_inactive_account(self, world):
        assert run(world, lambda s: find_user_by_email(s, "DORMANT@a.example")).id == world.users["dormant"].id
        assert run(world, lambda s: find_user_by_email(s, "DORMANT@a.example", active_only=True)) is None

    def test_a_tenant_can_be_required(self, world):
        assert run(world, lambda s: find_user_by_email(s, "bob@b.example", tenant_id=world.tb.id)).id == world.users["bob"].id
        assert run(world, lambda s: find_user_by_email(s, "bob@b.example", tenant_id=world.ta.id)) is None

    def test_a_deployment_that_already_holds_a_case_pair_gets_a_deterministic_answer_never_an_error(self, world):
        """Two accounts differing only in case (what this change prevents from now on) must not turn sign-in into a 500: an exact-case match wins, otherwise the oldest."""
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, email="Twin@a.example", username="twin1", hashed_password=HASH, role="admin", is_active=True, created_at=datetime(2026, 2, 1, tzinfo=UTC)))
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, email="twin@a.example", username="twin2", hashed_password=HASH, role="admin", is_active=True, created_at=datetime(2026, 3, 1, tzinfo=UTC)))
            s.commit()
        assert run(world, lambda s: find_user_by_email(s, "twin@a.example")).email == "twin@a.example"  # exact case wins, though it is the newer
        assert run(world, lambda s: find_user_by_email(s, "Twin@a.example")).email == "Twin@a.example"
        assert run(world, lambda s: find_user_by_email(s, "TWIN@a.example")).email == "Twin@a.example"  # neither matches exactly: the oldest

    def test_with_a_case_pair_the_active_one_is_chosen_when_asked_for_active(self, world):
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, email="Pair@a.example", username="pair1", hashed_password=HASH, role="admin", is_active=False, created_at=datetime(2026, 2, 1, tzinfo=UTC)))
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, email="pair@a.example", username="pair2", hashed_password=HASH, role="admin", is_active=True, created_at=datetime(2026, 3, 1, tzinfo=UTC)))
            s.commit()
        assert run(world, lambda s: find_user_by_email(s, "Pair@a.example", active_only=True)).email == "pair@a.example"


class TestSignIn:
    @pytest.mark.parametrize("typed", ["alice@a.example", "ALICE@A.EXAMPLE", "Alice@a.example"])
    def test_any_case_signs_in(self, world, typed):
        assert login(world, typed).status_code == 200

    @pytest.mark.parametrize("typed", ["legacy.user@a.example", "LEGACY.USER@A.EXAMPLE", "Legacy.User@A.example"])
    def test_a_legacy_mixed_case_account_still_signs_in_under_any_case(self, world, typed):
        assert login(world, typed).status_code == 200

    def test_a_wrong_password_is_still_refused_whatever_the_case(self, world):
        assert [login(world, e, "wrong").status_code for e in ("alice@a.example", "ALICE@a.example")] == [401, 401]

    def test_an_inactive_account_is_still_refused_under_any_case(self, world):
        assert [login(world, e).status_code for e in ("dormant@a.example", "DORMANT@A.EXAMPLE")] == [401, 401]

    def test_the_failure_count_is_shared_across_cases_so_the_lock_cannot_be_dodged_by_changing_a_letter(self, world):
        for email in ("alice@a.example", "ALICE@a.example", "Alice@a.example", "aLICE@a.example", "alice@A.example"):
            assert login(world, email, "wrong").status_code == 401
        assert login(world, "alice@a.example").status_code == 429


class TestCreatingAUser:
    def create(self, world, tenant, email):
        body = tn.CreateUserRequest(email=email, username=email.split("@")[0], password="Str0ng-Passw0rd!", role="soc_analyst")
        who = SimpleNamespace(tenant_id=tenant.id, user_id=uuid.uuid4(), can_grant_role=lambda role: True)
        return run(world, lambda s: tn.create_user(request=body, current_user=who, db=s))

    def test_the_address_is_stored_lower_cased_and_returned_that_way(self, world):
        out = self.create(world, world.ta, "New.Person@A.Example")
        assert out.email == "new.person@a.example" and stored(world, "new.person@a.example") == ["new.person@a.example"]

    def test_the_new_account_signs_in_under_any_case(self, world):
        self.create(world, world.ta, "Mixed@A.Example")
        assert [login(world, e, "Str0ng-Passw0rd!").status_code for e in ("mixed@a.example", "MIXED@A.EXAMPLE")] == [200, 200]

    @pytest.mark.parametrize("variant", ["ALICE@a.example", "Alice@A.Example", "alice@a.example"])
    def test_a_case_variant_of_an_address_in_the_callers_own_tenant_is_a_conflict(self, world, variant):
        with pytest.raises(HTTPException) as e:
            self.create(world, world.ta, variant)
        assert e.value.status_code == 409 and e.value.detail == "A user with this email already exists in your organization."
        assert stored(world, "alice@a.example") == ["alice@a.example"], "and no second account was made"

    @pytest.mark.parametrize("variant", ["bob@b.example", "BOB@B.EXAMPLE", "Bob@b.example"])
    def test_a_case_variant_of_ANOTHER_tenants_legacy_address_is_refused_without_saying_it_is_registered(self, world, variant):
        """The bypass: changing a letter's case used to get past the check that keeps one organisation from claiming another's address."""
        with pytest.raises(HTTPException) as e:
            self.create(world, world.ta, variant)
        assert e.value.status_code == 409 and e.value.detail == "This email address cannot be used. Choose a different one."
        assert stored(world, "bob@b.example") == ["Bob@B.example"]

    def test_a_case_variant_of_the_callers_own_legacy_mixed_case_account_is_a_conflict(self, world):
        with pytest.raises(HTTPException) as e:
            self.create(world, world.ta, "legacy.user@a.example")
        assert e.value.status_code == 409 and "in your organization" in e.value.detail

    def test_two_creations_differing_only_in_case_make_one_account(self, world):
        self.create(world, world.ta, "Once@A.Example")
        with pytest.raises(HTTPException):
            self.create(world, world.ta, "ONCE@a.example")
        assert stored(world, "once@a.example") == ["once@a.example"]


class TestNoCodeComparesTheAddressByExactCase:
    def test_nothing_outside_the_lookup_helper_compares_User_email_directly(self):
        """A bare `User.email == x` is exact-case: it misses a legacy account and cannot see that an address is taken. Use find_user_by_email, or func.lower(User.email) == normalize_email(x)."""
        offenders = []
        for p in APP.rglob("*.py"):
            if p.name == "user_lookup.py":
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if re.search(r"\bUser\.email\s*(==|!=|\.in_\(|\.ilike\()", line) and not line.lstrip().startswith("#"):
                    offenders.append(f"{p.relative_to(APP)}:{n}: {line.strip()[:90]}")
        assert offenders == []

    def test_every_place_that_creates_a_user_stores_a_normalised_address(self):
        """The addresses these pass must be lower-case: normalize_email(...), the bootstrap's already-normalised `email`, or a constant (checked below)."""
        expected = {
            "api/v1/endpoints/tenants.py": "email = normalize_email(request.email) if request.email else None",
            "services/tenant_provision/provisioner.py": "email=normalize_email(entry.email)",
            "scripts/bootstrap_production.py": "email = email.strip().lower()",
            "scripts/seed_demo.py": "email=DEMO_USER_EMAIL",
        }
        for rel, needle in expected.items():
            assert needle in (APP / rel).read_text(encoding="utf-8"), f"{rel} no longer stores a normalised address ({needle})"

    def test_the_address_constants_that_are_stored_as_they_are_are_lower_case(self):
        from app.scripts import bootstrap_production, seed_demo

        for value in (seed_demo.DEMO_USER_EMAIL, bootstrap_production.SEEDED_ADMIN_EMAIL):
            assert value == normalize_email(value)

    def test_the_sign_in_paths_use_the_helper(self):
        # sign-in and passkey sign-in go through find_user_by_login (an account name, or an email); it uses find_user_by_email for an email
        for rel in ("api/v1/endpoints/auth.py", "api/v1/endpoints/passkeys.py"):
            assert "find_user_by_login(" in (APP / rel).read_text(encoding="utf-8"), rel
        for rel in ("scripts/bootstrap_production.py", "services/tenant_provision/provisioner.py"):
            assert "find_user_by_email(" in (APP / rel).read_text(encoding="utf-8"), rel
        assert "find_user_by_email(" in (APP / "services/user_lookup.py").read_text(encoding="utf-8")

    def test_the_failed_sign_in_lock_counts_by_the_same_rule(self):
        from app.services import login_throttle

        assert login_throttle.email_key("  Alice@X.com ") == normalize_email("  Alice@X.com ")


class TestTheMigration:
    SQL = " ".join((Path(__file__).resolve().parent.parent / "migrations" / "070_users_email_lower_unique.sql").read_text().split())

    def test_it_builds_a_unique_index_on_lower_email(self):
        assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email))" in self.SQL

    def test_it_refuses_to_guess_when_case_duplicates_exist_and_says_how_to_fix_them(self):
        assert "HAVING count(*) > 1" in self.SQL and "RAISE WARNING" in self.SQL and "was NOT created" in self.SQL
        assert "array_agg(email)" in self.SQL and "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower" in self.SQL.split("RAISE WARNING")[1]

    def test_it_does_not_rewrite_existing_rows(self):
        assert "UPDATE users" not in self.SQL and "DELETE FROM users" not in self.SQL
