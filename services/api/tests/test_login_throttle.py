"""Guessing a password is no longer free.

/auth/login had no rate limit and no lockout: a password could be guessed as fast as the server answered, for as long as the attacker liked. Failed sign-ins are now counted (app.services.login_throttle, migration 069), and too many for one
address, or from one client address, in the window refuse further attempts (429, Retry-After) until the window passes, even with the right password.

The lock must NOT bring the email enumeration back (fixed in the previous change): a made-up address locks exactly like a real one, and every locked case gets the same answer. A real SQLite database and the real router; time is moved by
inserting failures with older timestamps. The same properties were also checked over HTTP against real Postgres, as the superuser and as the non-superuser role (see the commit message).
"""
import asyncio
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import bcrypt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from app.api.v1.endpoints import auth
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.scripts import login_lockout
from app.services import login_throttle

PASSWORD = "correct horse battery staple"
GENERIC = "Incorrect account name or password"
HASH = get_password_hash(PASSWORD)  # one real hash, shared (hashing is slow)


@pytest.fixture(autouse=True)
def _email_sign_in_is_on_for_these_tests(monkeypatch):
    """These tests are about an identifier that is an EMAIL ADDRESS (the lock keyed by what was typed; the case of an address; not revealing which addresses exist). Email sign-in is OFF by default since people sign in with their account name, so they say so here.
    The account-name equivalents live in test_account_names.py and the default-off behaviour in TestEmailSignInIsOffByDefault."""
    from settings_support import patch_login_allow_email

    patch_login_allow_email(monkeypatch, True)


@pytest.fixture
def world(tmp_path):
    path = tmp_path / "throttle.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    t = Tenant(id=uuid.uuid4(), name="T", slug="t-" + uuid.uuid4().hex[:6])
    def user(email, active=True):
        return User(id=uuid.uuid4(), tenant_id=t.id, email=email, username=email.split("@")[0], hashed_password=HASH, role="admin", is_active=active)
    with Session(sync, expire_on_commit=False) as s:
        s.add_all([t, user("alice@a.example"), user("bob@a.example"), user("dormant@a.example", active=False)])
        s.commit()
    factory = async_sessionmaker(create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool), expire_on_commit=False)
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")

    async def session():
        async with factory() as s:
            yield s

    app.dependency_overrides[deps.get_db] = session
    yield SimpleNamespace(client=TestClient(app), sync=sync, factory=factory)
    sync.dispose()


def attempt(world, email, password="wrong", **headers):
    return world.client.post("/api/v1/auth/login", json={"email": email, "password": password}, headers=headers)


def failures(world, **where):
    with Session(world.sync) as s:
        q = select(func.count()).select_from(LoginFailure)
        for k, v in where.items():
            q = q.where(getattr(LoginFailure, k) == v)
        return s.scalar(q)


def seed(world, email=None, ip="testclient", minutes_ago=0.0, n=1):
    """Failures that happened `minutes_ago` minutes ago (the way to move time)."""
    with Session(world.sync) as s:
        for _ in range(n):
            s.add(LoginFailure(email_key=email, client_ip=ip, created_at=datetime.now(UTC) - timedelta(minutes=minutes_ago)))
        s.commit()


@pytest.fixture
def hash_checks(monkeypatch):
    calls = []
    real = bcrypt.checkpw

    def counting(password, hashed):
        calls.append(hashed)
        return real(password, hashed)

    monkeypatch.setattr(security.bcrypt, "checkpw", counting)
    return calls


def retry_minutes(r):
    return int(re.search(r"about (\d+) minute", r.json()["detail"]).group(1))


class TestTheLock:
    def test_the_fifth_wrong_attempt_is_still_a_401_and_the_sixth_is_refused(self, world):
        assert [attempt(world, "alice@a.example").status_code for _ in range(5)] == [401] * 5
        r = attempt(world, "alice@a.example")
        assert r.status_code == 429 and r.json()["detail"].startswith("Too many failed sign-in attempts. Try again in about ")

    def test_while_locked_even_the_correct_password_is_refused(self, world):
        for _ in range(5):
            attempt(world, "alice@a.example")
        r = attempt(world, "alice@a.example", PASSWORD)
        assert r.status_code == 429 and "access_token" not in r.text

    def test_the_refusal_says_when_to_come_back(self, world):
        for _ in range(5):
            attempt(world, "alice@a.example")
        r = attempt(world, "alice@a.example")
        seconds = int(r.headers["Retry-After"])
        assert 1 <= seconds <= 15 * 60 and retry_minutes(r) == -(-seconds // 60)

    def test_one_address_locking_does_not_lock_another(self, world):
        for _ in range(5):
            attempt(world, "alice@a.example")
        assert attempt(world, "alice@a.example").status_code == 429
        assert attempt(world, "bob@a.example", PASSWORD).status_code == 200

    def test_a_correct_login_under_the_limit_works(self, world):
        for _ in range(4):
            attempt(world, "alice@a.example")
        assert attempt(world, "alice@a.example", PASSWORD).status_code == 200

    def test_a_success_clears_the_addresses_count_so_it_starts_again(self, world):
        for _ in range(4):
            attempt(world, "alice@a.example")
        assert attempt(world, "alice@a.example", PASSWORD).status_code == 200
        assert failures(world, email_key="alice@a.example") == 0
        assert [attempt(world, "alice@a.example").status_code for _ in range(4)] == [401] * 4

    def test_the_address_is_counted_however_it_is_cased(self, world):
        for email in ("alice@a.example", "ALICE@a.example", "Alice@a.example", "alice@a.example", "aLiCe@a.example"):
            attempt(world, email)
        assert failures(world, email_key="alice@a.example") == 5
        assert attempt(world, "alice@A.EXAMPLE", PASSWORD).status_code == 429

    def test_a_failure_is_stored_even_though_the_request_raises(self, world):
        """get_db rolls back on an exception; the count is committed first, or it would never exist."""
        attempt(world, "alice@a.example")
        assert failures(world) == 1

    def test_a_refused_attempt_adds_nothing_so_hammering_cannot_extend_the_lock_for_ever(self, world):
        for _ in range(5):
            attempt(world, "alice@a.example")
        before = failures(world)
        for _ in range(10):
            assert attempt(world, "alice@a.example").status_code == 429
        assert failures(world) == before

    def test_a_refused_attempt_does_none_of_the_expensive_hashing(self, world, hash_checks):
        for _ in range(5):
            attempt(world, "alice@a.example")
        hash_checks.clear()
        attempt(world, "alice@a.example", PASSWORD)
        assert hash_checks == []


class TestTheLockEnds:
    def test_old_failures_do_not_count(self, world):
        seed(world, "alice@a.example", minutes_ago=16, n=5)
        assert attempt(world, "alice@a.example", PASSWORD).status_code == 200

    def test_failures_inside_the_window_still_lock(self, world):
        seed(world, "alice@a.example", minutes_ago=14, n=5)
        r = attempt(world, "alice@a.example", PASSWORD)
        assert r.status_code == 429 and retry_minutes(r) == 1 and 1 <= int(r.headers["Retry-After"]) <= 60

    def test_the_wait_is_until_the_oldest_of_the_latest_five_leaves_not_the_newest(self, world):
        seed(world, "alice@a.example", minutes_ago=14)  # the oldest of the latest five: leaves in about a minute
        seed(world, "alice@a.example", minutes_ago=2, n=4)
        r = attempt(world, "alice@a.example", PASSWORD)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) <= 70

    def test_an_older_sixth_failure_does_not_lengthen_the_wait(self, world):
        seed(world, "alice@a.example", minutes_ago=14.5)  # oldest of all: not among the latest five
        seed(world, "alice@a.example", minutes_ago=3, n=5)
        r = attempt(world, "alice@a.example", PASSWORD)
        assert 11 * 60 <= int(r.headers["Retry-After"]) <= 12 * 60 + 5

    def test_old_rows_are_purged_as_new_failures_arrive(self, world):
        seed(world, "gone@a.example", minutes_ago=30, n=3)
        attempt(world, "alice@a.example")
        assert failures(world, email_key="gone@a.example") == 0 and failures(world, email_key="alice@a.example") == 1

    def test_the_limits_and_the_window_are_settings(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 2)
        attempt(world, "alice@a.example"), attempt(world, "alice@a.example")
        assert attempt(world, "alice@a.example").status_code == 429
        monkeypatch.setattr(settings, "LOGIN_FAILURE_WINDOW_MINUTES", 1)
        seed(world, "bob@a.example", minutes_ago=2, n=5)
        assert attempt(world, "bob@a.example", PASSWORD).status_code == 200

    @pytest.mark.parametrize("name", ["LOGIN_MAX_FAILURES_PER_ACCOUNT", "LOGIN_MAX_FAILURES_PER_IP", "LOGIN_FAILURE_WINDOW_MINUTES"])
    def test_a_limit_below_one_is_refused_so_nobody_can_configure_the_lock_into_locking_everyone_or_nobody(self, name):
        meta = type(settings).model_fields[name].metadata
        assert any(getattr(m, "ge", None) == 1 for m in meta), meta

    def test_the_defaults(self):
        assert (settings.LOGIN_MAX_FAILURES_PER_ACCOUNT, settings.LOGIN_MAX_FAILURES_PER_IP, settings.LOGIN_FAILURE_WINDOW_MINUTES) == (5, 20, 15)


class TestItDoesNotBringTheEnumerationBack:
    """A distinguishing lock would let anyone find out which addresses are registered by watching which ones lock."""

    CASES = ["alice@a.example", "nobody@nowhere.example", "dormant@a.example"]  # registered, made up, registered but inactive

    @pytest.mark.parametrize("email", CASES)
    def test_every_kind_of_address_locks_after_the_same_number_of_attempts(self, world, email):
        assert [attempt(world, email).status_code for _ in range(5)] == [401] * 5
        assert attempt(world, email).status_code == 429

    def test_the_locked_answer_is_the_same_for_a_real_a_made_up_and_an_inactive_address(self, world):
        seen = []
        for email in self.CASES:
            for _ in range(5):
                attempt(world, email)
            r = attempt(world, email, PASSWORD)
            seen.append((r.status_code, r.json()["detail"], r.headers["Retry-After"][:1] if int(r.headers["Retry-After"]) > 99 else r.headers["Retry-After"], tuple(sorted(r.json()))))
        assert len({s[:2] + s[3:] for s in seen}) == 1, seen
        minutes = {int(re.search(r"(\d+) minute", s[1]).group(1)) for s in seen}
        assert minutes == {15}

    def test_the_unlocked_refusals_are_still_the_one_generic_401(self, world):
        r = [attempt(world, e) for e in self.CASES]
        assert {(x.status_code, x.json()["detail"]) for x in r} == {(401, GENERIC)}

    def test_the_lock_text_names_no_reason(self, world):
        for _ in range(5):
            attempt(world, "alice@a.example")
        detail = attempt(world, "alice@a.example").json()["detail"].lower()
        for word in ("account", "password", "user", "exist", "regist", "ip", "address", "client", "locked"):
            assert word not in detail, word

    def test_a_made_up_address_is_recorded_like_a_real_one(self, world):
        attempt(world, "nobody@nowhere.example")
        assert failures(world, email_key="nobody@nowhere.example") == 1


class TestTheClientAddress:
    """One client cannot try many addresses."""

    def test_many_failures_from_one_client_lock_that_client_whatever_address_it_tries(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
        for i in range(3):
            assert attempt(world, f"made-up-{i}@nowhere.example").status_code == 401
        r = attempt(world, "bob@a.example", PASSWORD)  # a fresh address with the right password
        assert r.status_code == 429 and r.json()["detail"].startswith("Too many failed sign-in attempts.")

    def test_a_forged_x_forwarded_for_does_not_dodge_it_without_trusted_proxies(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
        for i in range(3):
            attempt(world, f"made-up-{i}@nowhere.example", **{"X-Forwarded-For": f"198.51.100.{i}"})
        assert attempt(world, "bob@a.example", PASSWORD, **{"X-Forwarded-For": "203.0.113.99"}).status_code == 429

    def test_the_client_count_is_by_client_address_so_another_client_is_unaffected(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
        seed(world, "x@x.example", ip="203.0.113.7", n=3)  # some other client has failed a lot
        assert attempt(world, "bob@a.example", PASSWORD).status_code == 200

    def test_a_success_clears_the_addresss_count_but_not_the_clients(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 4)
        attempt(world, "alice@a.example")
        attempt(world, "other@nowhere.example")
        assert attempt(world, "alice@a.example", PASSWORD).status_code == 200
        assert failures(world, email_key="alice@a.example") == 0
        assert failures(world, client_ip="testclient") == 1, "the other address's failure from this client stays"

    def test_both_limits_apply_and_the_longer_wait_is_the_one_reported(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
        seed(world, "q@q.example", ip="testclient", minutes_ago=14, n=3)  # the client lock: about a minute left
        seed(world, "alice@a.example", ip="203.0.113.7", minutes_ago=2, n=5)  # the address lock: about thirteen
        r = attempt(world, "alice@a.example", PASSWORD)
        assert r.status_code == 429 and 12 * 60 <= int(r.headers["Retry-After"]) <= 13 * 60 + 5


class TestTheService:
    @pytest.mark.parametrize("seconds,minutes", [(-30, 1), (0, 1), (0.2, 1), (1, 1), (59, 1), (60, 1), (61, 2), (900, 15), (899.2, 15)])
    def test_the_wait_is_rounded_up_and_never_zero(self, seconds, minutes):
        e = login_throttle.too_many_attempts(timedelta(seconds=seconds))
        assert e.status_code == 429 and f"about {minutes} minute" in e.detail
        assert int(e.headers["Retry-After"]) >= 1

    def test_one_minute_is_singular_and_more_are_plural(self):
        assert login_throttle.too_many_attempts(timedelta(seconds=30)).detail.endswith("about 1 minute.")
        assert login_throttle.too_many_attempts(timedelta(minutes=5)).detail.endswith("about 5 minutes.")

    @pytest.mark.parametrize("raw,key", [("Alice@X.com", "alice@x.com"), ("  alice@x.com ", "alice@x.com"), ("ALICE@X.COM", "alice@x.com")])
    def test_the_key_is_trimmed_and_lower_cased(self, raw, key):
        assert login_throttle.email_key(raw) == key

    def test_without_a_client_address_only_the_address_is_limited(self, world):
        async def go():
            async with world.factory() as s:
                for _ in range(20):
                    await login_throttle.record_failure(s, f"m{_}@x.example", None)
                await login_throttle.ensure_not_locked(s, "fresh@x.example", None)  # must not raise

        asyncio.run(go())

    def test_a_store_that_cannot_be_read_is_an_error_not_an_open_door(self, world, monkeypatch):
        async def broken(*a, **kw):
            raise RuntimeError("store down")

        monkeypatch.setattr(login_throttle, "ensure_not_locked", broken)
        with pytest.raises(RuntimeError):
            attempt(world, "alice@a.example", PASSWORD)


class TestLogging:
    def test_reaching_the_limit_is_logged_once_with_a_hash_never_the_address(self, world, caplog):
        with caplog.at_level(logging.WARNING, logger=login_throttle.logger.name):
            for _ in range(5):
                attempt(world, "alice@a.example")
        (rec,) = [r for r in caplog.records if r.name == login_throttle.logger.name]
        import hashlib

        assert rec.email_sha256 == hashlib.sha256(b"alice@a.example").hexdigest()[:16] and rec.failures_limit == 5
        assert "alice@a.example" not in rec.getMessage() and "alice@a.example" not in str(vars(rec))

    def test_nothing_is_logged_before_the_limit_or_for_a_refused_attempt(self, world, caplog):
        with caplog.at_level(logging.WARNING, logger=login_throttle.logger.name):
            for _ in range(4):
                attempt(world, "alice@a.example")
        assert [r for r in caplog.records if r.name == login_throttle.logger.name] == []

    def test_the_log_call_uses_no_reserved_record_attribute(self):
        reserved = set(vars(logging.LogRecord("n", 20, "p", 1, "m", (), None))) | {"message", "asctime"}
        assert not ({"email_sha256", "client_ip", "failures_limit"} & reserved)


class TestTheOperatorsTool:
    def run(self, world, action, now=None, **kw):
        return asyncio.run(login_lockout.run(action, session_factory=world.factory, now=now, **kw))

    def test_list_shows_who_is_locked_and_for_how_long_and_nobody_else(self, world):
        seed(world, "alice@a.example", minutes_ago=2, n=5)
        seed(world, "bob@a.example", minutes_ago=2, n=4)  # under the limit
        seed(world, "old@a.example", minutes_ago=30, n=9)  # outside the window
        out = self.run(world, "list")
        assert [a["address"] for a in out["locked_addresses"]] == ["alice@a.example"]
        assert out["locked_addresses"][0]["recent_failures"] == 5 and 12 * 60 <= out["locked_addresses"][0]["seconds_left"] <= 13 * 60 + 5
        assert out["locked_clients"] == [] and out["window_minutes"] == 15

    def test_list_shows_a_locked_client(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
        seed(world, "a@x.example", ip="203.0.113.7", n=3)
        out = self.run(world, "list")
        assert [c["client_ip"] for c in out["locked_clients"]] == ["203.0.113.7"]

    def test_the_tool_takes_the_limits_from_the_service_so_it_cannot_disagree_with_login(self, world, monkeypatch):
        """Another test reloads the config module, which gives `app.core.config.settings` a new identity: a tool that imported `settings` itself then saw the DEFAULT limit while login (and this test) used the patched one."""
        import inspect

        assert "app.core.config" not in inspect.getsource(login_lockout) and "settings" not in inspect.getsource(login_lockout.run)
        monkeypatch.setattr(login_throttle, "limits", lambda: (2, 2))
        seed(world, "a@x.example", ip="203.0.113.7", n=2)
        out = self.run(world, "list")
        assert [a["address"] for a in out["locked_addresses"]] == ["a@x.example"] and [c["client_ip"] for c in out["locked_clients"]] == ["203.0.113.7"]

    def test_limits_reports_the_settings_in_force(self, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 7)
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 9)
        assert login_throttle.limits() == (7, 9)

    def test_clear_by_address_lifts_that_lock_only(self, world):
        seed(world, "alice@a.example", n=5)
        seed(world, "bob@a.example", n=5)
        assert self.run(world, "clear", email="Alice@A.example") == {"ok": True, "cleared_failures": 5}
        assert attempt(world, "alice@a.example", PASSWORD).status_code == 200
        assert failures(world, email_key="bob@a.example") == 5

    def test_clear_by_client_lifts_that_client_only(self, world):
        seed(world, "a@x.example", ip="203.0.113.7", n=3)
        seed(world, "b@x.example", ip="198.51.100.1", n=2)
        assert self.run(world, "clear", ip="203.0.113.7")["cleared_failures"] == 3
        assert failures(world, client_ip="198.51.100.1") == 2

    def test_clear_all(self, world):
        seed(world, "a@x.example", n=3)
        seed(world, "b@x.example", ip="1.2.3.4", n=2)
        assert self.run(world, "clear", all_failures=True)["cleared_failures"] == 5 and failures(world) == 0

    @pytest.mark.parametrize("kw", [{}, {"email": "a@x.example", "ip": "1.2.3.4"}, {"email": "a@x.example", "all_failures": True}])
    def test_clear_needs_exactly_one_target_and_deletes_nothing_otherwise(self, world, kw):
        seed(world, "a@x.example", n=3)
        with pytest.raises(login_lockout.LoginLockoutError):
            self.run(world, "clear", **kw)
        assert failures(world) == 3

    def test_an_unknown_action_is_an_error(self, world):
        with pytest.raises(login_lockout.LoginLockoutError):
            self.run(world, "frobnicate")

    def test_the_command_line_reports_a_usage_error_as_json_with_exit_2(self, capsys, monkeypatch):
        async def refuse(*a, **kw):
            raise login_lockout.LoginLockoutError("give exactly one of --email, --ip, --all")

        monkeypatch.setattr(login_lockout, "run", refuse)
        assert login_lockout.main(["clear"]) == 2
        assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "give exactly one of --email, --ip, --all"}


class TestTheTableAndTheModelAgree:
    def test_the_migration_creates_what_the_model_declares(self):
        from pathlib import Path

        sql = " ".join((Path(__file__).resolve().parent.parent / "migrations" / "069_login_failures.sql").read_text().split())
        for column in LoginFailure.__table__.columns:
            assert column.name in sql, column.name
        assert "CREATE TABLE IF NOT EXISTS login_failures" in sql and "ROW LEVEL SECURITY" not in sql.replace("no row-level security", "").replace("row-level security", "")
        assert "(email_key, created_at DESC)" in sql and "(client_ip, created_at DESC)" in sql
