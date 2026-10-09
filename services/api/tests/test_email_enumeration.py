"""Nobody can use the API to find out which email addresses are registered.

LOGIN. `user is None or not verify_password(...)` skipped the password hash for an unknown email, so over HTTP an unknown email answered in about 6 ms and a registered one in about 285 ms (no overlap): anyone, with no account, could list
which addresses (admins included) are registered. Login now does the same work either way, against a real hash made the way every stored one is. Wall-clock time makes a flaky test, so these assert the cause (the expensive check runs exactly
once on EVERY path, against the right hash) and that the answers are identical; the timing itself was measured over HTTP, interleaved, before and after (see the commit message).

USER CREATION. Email addresses are unique across ALL tenants (login is by email alone), so creating a user whose address belongs to another organisation must be refused, but the refusal no longer says the address is registered: that is said only
for the caller's own tenant, whose users the caller can list anyway. The attempt is logged so probing can be seen. (A refusal still differs from a success, so a tenant admin can still learn something about a few addresses: removing that needs
per-tenant uniqueness or an invitation flow.)
"""
import asyncio
import hashlib
import logging
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import bcrypt
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import tenants as tn
from app.core import security
from app.core.security import get_password_hash, verify_password, verify_password_or_equalise
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User

PASSWORD = "correct horse battery staple"
GENERIC = "Incorrect email or password"


@pytest.fixture
def world(tmp_path):
    """A real database with two tenants: A has an active and an inactive user, B has one. And an app exposing the real auth router."""
    path = tmp_path / "enum.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    ta, tb = (Tenant(id=uuid.uuid4(), name=n, slug=n.lower() + "-" + uuid.uuid4().hex[:6]) for n in ("A", "B"))
    def user(tenant, email, active=True, role="admin"):
        return User(id=uuid.uuid4(), tenant_id=tenant.id, email=email, username=email.split("@")[0], hashed_password=get_password_hash(PASSWORD), role=role, is_active=active)
    alice, dormant, bob = user(ta, "alice@a.example"), user(ta, "dormant@a.example", active=False), user(tb, "bob@b.example")
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([ta, tb, alice, dormant, bob])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    app = FastAPI()
    app.include_router(auth.router)

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    yield SimpleNamespace(client=TestClient(app), factory=factory, ta=ta, tb=tb, alice=alice, dormant=dormant, bob=bob)
    sync.dispose()


def attempt(world, email, password=PASSWORD):
    return world.client.post("/auth/login", json={"email": email, "password": password})


@pytest.fixture
def hash_checks(monkeypatch):
    """Every call to the expensive bcrypt check, with the hash it was made against."""
    calls: list[bytes] = []
    real = bcrypt.checkpw

    def counting(password, hashed):
        calls.append(hashed)
        return real(password, hashed)

    monkeypatch.setattr(security.bcrypt, "checkpw", counting)
    return calls


class TestLoginDoesTheSameWorkWhoeverIsAsked:
    @pytest.mark.parametrize("email,password", [
        ("alice@a.example", "wrong"),  # registered, wrong password
        ("alice@a.example", PASSWORD),  # registered, right password
        ("nobody@nowhere.example", "wrong"),  # not registered
        ("nobody@nowhere.example", PASSWORD),  # not registered, a password that works elsewhere
        ("dormant@a.example", PASSWORD),  # registered but inactive, right password
        ("dormant@a.example", "wrong"),  # registered but inactive
    ])
    def test_the_expensive_hash_check_runs_exactly_once_on_every_path(self, world, hash_checks, email, password):
        attempt(world, email, password)
        assert len(hash_checks) == 1

    def test_an_unknown_email_is_checked_against_a_real_bcrypt_hash_of_the_same_cost_as_a_stored_one(self, world, hash_checks):
        attempt(world, "nobody@nowhere.example")
        attempt(world, "alice@a.example", "wrong")
        unknown, known = hash_checks
        cost = lambda h: int(re.match(rb"\$2[aby]\$(\d\d)\$", h).group(1))  # noqa: E731
        assert cost(unknown) == cost(known) and unknown != known

    def test_an_inactive_account_is_checked_like_an_unknown_one_not_skipped(self, world, hash_checks):
        attempt(world, "dormant@a.example")
        assert hash_checks == [security._TIMING_EQUALISER_HASH.encode()]

    @pytest.mark.parametrize("email,password", [("alice@a.example", "wrong"), ("nobody@nowhere.example", "wrong"), ("dormant@a.example", PASSWORD), ("dormant@a.example", "wrong"), ("nobody@nowhere.example", PASSWORD)])
    def test_every_refusal_is_the_same_response(self, world, email, password):
        r = attempt(world, email, password)
        assert (r.status_code, r.json(), r.headers.get("www-authenticate")) == (401, {"detail": GENERIC}, "Bearer")

    def test_a_correct_login_still_works_and_only_for_an_active_account(self, world):
        assert attempt(world, "alice@a.example").status_code == 200
        assert attempt(world, "bob@b.example").status_code == 200
        assert attempt(world, "dormant@a.example").status_code == 401

    def test_the_login_handler_uses_the_equalising_check_and_never_the_bare_one(self):
        import inspect

        src = inspect.getsource(auth.login)
        assert "verify_password_or_equalise(" in src and "verify_password(" not in src.replace("verify_password_or_equalise(", ""), "login must not skip the hash for an unknown email"

    def test_no_code_outside_the_security_module_checks_a_password_with_the_bare_function(self):
        """A new credential check that calls verify_password directly would bring the timing difference back (or skip the work for an unknown account). Use verify_password_or_equalise."""
        root = Path(__file__).resolve().parent.parent / "app"
        offenders = [str(p.relative_to(root)) for p in root.rglob("*.py") if p.name != "security.py" and re.search(r"(?<![\w.])verify_password\(", p.read_text(encoding="utf-8", errors="replace"))]
        assert offenders == [], f"call verify_password_or_equalise instead: {offenders}"


class TestTheEqualisingCheck:
    def test_the_right_password_against_a_real_hash_matches_and_a_wrong_one_does_not(self):
        h = get_password_hash(PASSWORD)
        assert verify_password_or_equalise(PASSWORD, h) is True and verify_password_or_equalise("wrong", h) is False

    def test_no_account_is_always_false_even_for_a_password_that_would_match_the_stand_in_hash(self, monkeypatch):
        monkeypatch.setattr(security, "verify_password", lambda plain, hashed: True)  # the worst case: the stand-in "matches"
        assert verify_password_or_equalise("anything", None) is False

    def test_no_account_does_the_real_work_against_the_stand_in(self, monkeypatch):
        seen = []
        monkeypatch.setattr(security, "verify_password", lambda plain, hashed: seen.append(hashed) or False)
        verify_password_or_equalise("x", None)
        verify_password_or_equalise("x", "$2b$12$real")
        assert seen == [security._TIMING_EQUALISER_HASH, "$2b$12$real"]

    @pytest.mark.parametrize("guess", ["", "password", "dummy", "x", "not-a-real-password", "admin", PASSWORD])
    def test_the_stand_in_is_not_the_hash_of_anything_guessable(self, guess):
        assert verify_password(guess, security._TIMING_EQUALISER_HASH) is False

    def test_the_stand_in_is_a_well_formed_bcrypt_hash_made_like_every_stored_one(self):
        h = security._TIMING_EQUALISER_HASH
        assert re.fullmatch(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", h) and h[:7] == get_password_hash("x")[:7]

    def test_a_malformed_stored_hash_is_a_refusal_not_an_error(self):
        assert verify_password_or_equalise("x", "not a bcrypt hash") is False

    def test_a_password_longer_than_bcrypt_reads_is_handled_like_get_password_hash_does(self):
        long = "p" * 100
        assert verify_password_or_equalise(long, get_password_hash(long)) is True


def principal(tenant, user_id=None):
    return SimpleNamespace(tenant_id=tenant.id, user_id=user_id or uuid.uuid4(), can_grant_role=lambda role: True)


def create(world, tenant, email, caller=None):
    body = tn.CreateUserRequest(email=email, username=email.split("@")[0], password="Str0ng-Passw0rd!", role="soc_analyst")

    async def go():
        async with world.factory() as s:
            return await tn.create_user(request=body, current_user=caller or principal(tenant), db=s)

    return asyncio.run(go())


class TestCreatingAUserDoesNotRevealWhoIsRegisteredElsewhere:
    def test_an_address_of_the_callers_own_tenant_is_reported_as_such(self, world):
        with pytest.raises(HTTPException) as e:
            create(world, world.ta, "alice@a.example")
        assert e.value.status_code == 409 and e.value.detail == "A user with this email already exists in your organization."

    def test_an_address_of_another_tenant_is_refused_without_saying_it_is_registered(self, world):
        with pytest.raises(HTTPException) as e:
            create(world, world.ta, "bob@b.example")
        assert e.value.status_code == 409 and e.value.detail == "This email address cannot be used. Choose a different one."
        for word in ("exist", "regist", "tenant", "organi", "another", "taken", "already"):
            assert word not in e.value.detail.lower(), word

    def test_an_inactive_user_of_another_tenant_still_blocks_the_address_the_same_way(self, world):
        with pytest.raises(HTTPException) as e:
            create(world, world.tb, "dormant@a.example")
        assert e.value.status_code == 409 and "already" not in e.value.detail

    def test_a_clash_is_found_whatever_the_tenant_so_the_unique_constraint_is_never_what_decides(self, world):
        for owner, other, email in ((world.ta, world.tb, "alice@a.example"), (world.tb, world.ta, "bob@b.example")):
            with pytest.raises(HTTPException) as e:
                create(world, other, email)
            assert e.value.status_code == 409 and "cannot be used" in e.value.detail

    def test_a_new_address_is_created_in_the_callers_tenant(self, world):
        out = create(world, world.ta, "new@a.example")
        assert out.email == "new@a.example" and str(out.tenant_id) == str(world.ta.id) and not hasattr(out, "hashed_password")
        with pytest.raises(HTTPException) as e:
            create(world, world.ta, "new@a.example")
        assert "in your organization" in e.value.detail

    def test_the_attempt_on_another_tenants_address_is_logged_with_who_made_it_and_never_the_address(self, world, caplog):
        caller = principal(world.ta)
        with caplog.at_level(logging.WARNING, logger=tn.logger.name):
            with pytest.raises(HTTPException):
                create(world, world.ta, "bob@b.example", caller=caller)
        (rec,) = [r for r in caplog.records if r.name == tn.logger.name]
        assert rec.levelno == logging.WARNING
        assert (rec.acting_tenant, rec.acting_user) == (str(world.ta.id), str(caller.user_id))
        assert rec.email_sha256 == hashlib.sha256(b"bob@b.example").hexdigest()[:16]
        assert "bob@b.example" not in rec.getMessage() and "bob@b.example" not in str(vars(rec))

    def test_nothing_is_logged_for_a_clash_in_the_callers_own_tenant_or_a_success(self, world, caplog):
        with caplog.at_level(logging.WARNING, logger=tn.logger.name):
            with pytest.raises(HTTPException):
                create(world, world.ta, "alice@a.example")
            create(world, world.ta, "fresh@a.example")
        assert [r for r in caplog.records if r.name == tn.logger.name] == []

    def test_the_log_call_uses_no_reserved_record_attribute(self):
        """`extra` may not use a key the logging module owns ('created', 'name', 'message', ...): the call would raise KeyError after the user was committed (that was an earlier bug in this codebase)."""
        reserved = set(vars(logging.LogRecord("n", 20, "p", 1, "m", (), None))) | {"message", "asctime"}
        for key in ("acting_tenant", "acting_user", "email_sha256"):
            assert key not in reserved
