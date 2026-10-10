"""A person signs in with an ACCOUNT NAME, not an email address.

Login was by email, unique platform-wide, but nothing verifies that an address is real or sends mail to it, so it only ever behaved as a label while carrying the cost of an identifier. An account name is 3-32 lower-case letters, digits, '.', '_', '-'
(no '@', so a string with one is always an email), unique across the platform and compared case-insensitively; email becomes optional contact information. Existing clients keep working (the JSON key `email` is still accepted at sign-in, and creating a user without
a name derives one), and existing people can still sign in with their email while LOGIN_ALLOW_EMAIL is on. A real SQLite database and the real router, with the unique index created as production has it; migration 071 and its backfill were checked on real Postgres.
"""
import asyncio
import random
import re
import string
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, text, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1 import deps
from settings_support import patch_login_allow_email

from app.api.v1.endpoints import auth
from app.api.v1.endpoints import tenants as tn
from app.core import account_names as an
from app.core.config import settings
from app.core.security import decode_token, get_password_hash, hash_api_key
from app.db.database import Base
from app.models.login_failure import LoginFailure
from app.models.tenant import ApiKey, Tenant, User
from app.services import account_names as svc
from app.services.user_lookup import find_user_by_account_name, find_user_by_login

PASSWORD = "correct horse battery staple"
HASH = get_password_hash(PASSWORD)
APP = Path(__file__).resolve().parent.parent / "app"


@pytest.fixture
def world(tmp_path):
    """Tenant A: 'alice' (with an email), 'nomail' (NO email), 'dormant' (inactive). Tenant B: 'bob' (with an email)."""
    path = tmp_path / "names.db"
    sync = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync, tables=[Tenant.__table__, User.__table__, ApiKey.__table__, LoginFailure.__table__])
    with sync.begin() as c:
        c.execute(text("CREATE UNIQUE INDEX ux_users_account_name_lower ON users (lower(account_name))"))  # as migration 071 does
    ta, tb = (Tenant(id=uuid.uuid4(), name=n, slug=n.lower() + "-" + uuid.uuid4().hex[:6]) for n in ("A", "B"))

    def user(tenant, name, email=None, active=True):
        return User(id=uuid.uuid4(), tenant_id=tenant.id, account_name=name, email=email, username=name, hashed_password=HASH, role="admin", is_active=active)

    users = {"alice": user(ta, "alice", "alice@a.example"), "nomail": user(ta, "nomail"), "dormant": user(ta, "dormant", "dormant@a.example", active=False), "bob": user(tb, "bob", "bob@b.example")}
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


def sign_in(world, identifier, password=PASSWORD, key="email"):
    return world.client.post("/api/v1/auth/login", json={key: identifier, "password": password})


def names(world):
    with Session(world.sync) as s:
        return sorted(s.scalars(select(User.account_name)).all())


class TestTheRules:
    @pytest.mark.parametrize("name", ["abc", "a.b", "a_b", "a-b", "a1b", "hal.liveoak", "user-2", "x" * 32, "0ab", "ab9", "a..b", "a--b", "a.-_b"])
    def test_valid_names(self, name):
        assert an.is_valid_account_name(name) and an.validate_account_name(name) == name

    @pytest.mark.parametrize("name", ["", "a", "ab", "x" * 33, "ab@cd", "a b c", "-abc", "abc-", ".abc", "abc.", "_abc", "abc_", "Abc", "ABC", "caf\u00e9", "a/b", "a\\b", "ab\n", "\ttab", "name!", "emoji\U0001f600ok", "a\u200bbc"])
    def test_invalid_names(self, name):
        assert not an.is_valid_account_name(name)

    def test_validate_trims_and_lower_cases_first(self):
        assert an.validate_account_name("  Hal.LiveOak  ") == "hal.liveoak"

    @pytest.mark.parametrize("bad", ["", "ab", "has space", "x" * 40, "a@b.com", "-lead", "trail-", "UNI\u00c7ODE"])
    def test_validate_refuses_with_the_rule_in_words(self, bad):
        with pytest.raises(an.InvalidAccountName) as e:
            an.validate_account_name(bad)
        assert "3 to 32" in str(e.value) and "letters, digits" in str(e.value)

    def test_the_length_limits_are_what_the_database_enforces(self):
        assert (an.MIN_LENGTH, an.MAX_LENGTH) == (3, 32) and an.is_valid_account_name("x" * 32) and not an.is_valid_account_name("x" * 33)

    @pytest.mark.parametrize("identifier,is_email", [("a@b.com", True), ("alice", False), ("@", True), ("hal.liveoak", False), ("a@b", True), ("", False)])
    def test_an_at_sign_marks_an_email_and_a_name_can_never_have_one(self, identifier, is_email):
        assert an.looks_like_email(identifier) is is_email
        if is_email:
            assert not an.is_valid_account_name(identifier)

    @pytest.mark.parametrize("source,want", [("Alice.Smith@Example.com", "alice.smith"), ("John Smith", "john-smith"), ("  Zed  ", "zed"), ("a@b.com", "user"), ("__", "user"), ("", "user"), ("!!!", "user"), ("x.y+tag@z.com", "x.y-tag"), ("Caf\u00e9 Owner", "caf-owner"), ("under_score", "under_score")])
    def test_suggestions(self, source, want):
        assert an.suggest_account_name(source) == want

    def test_a_suggestion_is_always_valid_whatever_it_is_made_from(self):
        rng = random.Random(7)
        alphabet = string.printable + "\u00e9\u00fc\u4e2d\U0001f600"
        for _ in range(3000):
            source = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
            assert an.is_valid_account_name(an.suggest_account_name(source)), repr(source)

    def test_a_long_source_is_cut_to_the_limit_and_still_valid(self):
        s = an.suggest_account_name("a" * 100)
        assert len(s) == 32 and an.is_valid_account_name(s)

    @pytest.mark.parametrize("base", ["alice", "a" * 32, "ab-", "x" * 31 + "-", "abc"])
    def test_a_suffix_keeps_the_name_valid_within_the_limit(self, base):
        base = an.suggest_account_name(base)
        for n in (2, 9, 10, 99, 100, 12345):
            out = an.with_suffix(base, n)
            assert an.is_valid_account_name(out) and len(out) <= 32 and out.endswith(f"-{n}")


class TestFreeNames:
    def test_a_free_name_is_the_suggestion_itself(self, world):
        assert run(world, lambda s: svc.unique_account_name(s, "Carol.Jones@x.com")) == "carol.jones"

    def test_a_taken_name_gets_a_number(self, world):
        assert run(world, lambda s: svc.unique_account_name(s, "alice@elsewhere.com")) == "alice-2"

    def test_the_numbers_keep_counting(self, world):
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, account_name="alice-2", username="x", hashed_password=HASH, role="admin"))
            s.commit()
        assert run(world, lambda s: svc.unique_account_name(s, "alice")) == "alice-3"

    def test_taken_is_case_insensitive_and_platform_wide(self, world):
        assert run(world, lambda s: svc.account_name_taken(s, "ALICE")) and run(world, lambda s: svc.account_name_taken(s, "  Bob "))
        assert not run(world, lambda s: svc.account_name_taken(s, "carol"))

    def test_a_long_taken_name_still_fits(self, world):
        long = "l" * 32
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, account_name=long, username="x", hashed_password=HASH, role="admin"))
            s.commit()
        out = run(world, lambda s: svc.unique_account_name(s, long))
        assert out != long and len(out) <= 32 and an.is_valid_account_name(out)


class TestFindingAPerson:
    @pytest.mark.parametrize("typed", ["alice", "ALICE", "Alice", "  alice  "])
    def test_by_name_in_any_case(self, world, typed):
        assert run(world, lambda s: find_user_by_account_name(s, typed)).id == world.users["alice"].id

    def test_an_unknown_name_is_none(self, world):
        assert run(world, lambda s: find_user_by_account_name(s, "nobody")) is None

    def test_active_only_skips_an_inactive_account(self, world):
        assert run(world, lambda s: find_user_by_account_name(s, "dormant")).id == world.users["dormant"].id
        assert run(world, lambda s: find_user_by_account_name(s, "dormant", active_only=True)) is None

    def test_a_login_identifier_without_an_at_is_a_name_and_with_one_an_email_when_email_sign_in_is_on(self, world, monkeypatch):
        patch_login_allow_email(monkeypatch, True)  # off by default
        assert run(world, lambda s: find_user_by_login(s, "bob")).id == world.users["bob"].id
        assert run(world, lambda s: find_user_by_login(s, "BOB@B.example")).id == world.users["bob"].id

    def test_an_email_identifier_is_refused_when_email_sign_in_is_off_but_a_name_still_works(self, world, monkeypatch):
        patch_login_allow_email(monkeypatch, False)
        assert run(world, lambda s: find_user_by_login(s, "bob@b.example")) is None
        assert run(world, lambda s: find_user_by_login(s, "bob")).id == world.users["bob"].id

    def test_an_email_is_never_looked_up_as_a_name(self, world):
        """'bob@b.example' is not a name, so it can never match the account whose name is 'bob'."""
        assert run(world, lambda s: find_user_by_account_name(s, "bob@b.example")) is None

    def test_a_person_with_no_email_is_found_by_name(self, world):
        assert run(world, lambda s: find_user_by_login(s, "nomail")).id == world.users["nomail"].id


class TestSigningIn:
    @pytest.mark.parametrize("typed", ["alice", "ALICE", "Alice"])
    def test_by_account_name_in_any_case(self, world, typed):
        assert sign_in(world, typed).status_code == 200

    def test_by_email_while_email_sign_in_is_on(self, world, monkeypatch):
        patch_login_allow_email(monkeypatch, True)  # off by default
        assert sign_in(world, "alice@a.example").status_code == 200 and sign_in(world, "ALICE@A.EXAMPLE").status_code == 200

    def test_by_email_is_refused_when_it_is_off_and_the_name_still_works(self, world, monkeypatch):
        patch_login_allow_email(monkeypatch, False)
        assert sign_in(world, "alice@a.example").status_code == 401 and sign_in(world, "alice").status_code == 200

    def test_a_person_with_no_email_signs_in_by_name(self, world):
        assert sign_in(world, "nomail").status_code == 200

    @pytest.mark.parametrize("key", ["email", "account_name", "username", "identifier"])
    def test_every_accepted_json_key(self, world, key):
        assert sign_in(world, "alice", key=key).status_code == 200

    def test_a_request_with_none_of_the_keys_is_a_validation_error(self, world):
        assert world.client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 422

    def test_an_empty_identifier_is_a_validation_error(self, world):
        assert sign_in(world, "").status_code == 422

    def test_a_wrong_password_and_an_inactive_and_an_unknown_name_are_the_same_401(self, world):
        seen = {(sign_in(world, n, p).status_code, sign_in(world, n, p).json()["detail"]) for n, p in (("alice", "wrong"), ("dormant", PASSWORD), ("nobody", PASSWORD))}
        assert seen == {(401, "Incorrect account name or password")}

    def test_the_token_carries_the_account_name_and_a_label_for_who(self, world):
        claims = decode_token(sign_in(world, "alice").json()["access_token"])
        assert claims["account_name"] == "alice" and claims["email"] == "alice@a.example"

    def test_with_no_email_the_label_is_the_account_name_so_audit_and_the_rest_still_have_one(self, world):
        claims = decode_token(sign_in(world, "nomail").json()["access_token"])
        assert claims["account_name"] == "nomail" and claims["email"] == "nomail"

    def test_the_refresh_token_carries_them_too(self, world):
        tokens = sign_in(world, "nomail").json()
        claims = decode_token(world.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()["access_token"])
        assert claims["account_name"] == "nomail" and claims["email"] == "nomail"

    def test_me_reports_the_account_name_and_no_email(self, world):
        token = sign_in(world, "nomail").json()["access_token"]
        me = world.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
        assert me["account_name"] == "nomail" and me["email"] is None

    def test_the_failed_sign_in_lock_counts_a_name_in_any_case_together(self, world):
        for typed in ("alice", "ALICE", "Alice", "aLiCe", "alice "):
            assert sign_in(world, typed, "wrong").status_code == 401
        assert sign_in(world, "alice").status_code == 429

    def test_a_made_up_name_locks_like_a_real_one(self, world):
        assert [sign_in(world, "nobody-here", "wrong").status_code for _ in range(5)] == [401] * 5
        assert sign_in(world, "nobody-here").status_code == 429


class TestThePrincipalLabel:
    """Everything that records "who did this" (audit, rule tuning, view-as) reads `current_user.email` as a label. An account with no email must still have one: its account name."""

    def principal(self, world, monkeypatch, token_for):
        async def not_revoked(jti):
            return False

        monkeypatch.setattr(deps, "is_revoked", not_revoked)
        creds = SimpleNamespace(credentials=sign_in(world, token_for).json()["access_token"])
        return run(world, lambda s: deps.get_current_user(creds, s))

    def test_a_person_with_an_email_is_labelled_by_it(self, world, monkeypatch):
        assert self.principal(world, monkeypatch, "alice").email == "alice@a.example"

    def test_a_person_with_no_email_is_labelled_by_their_account_name(self, world, monkeypatch):
        assert self.principal(world, monkeypatch, "nomail").email == "nomail"

    def test_an_api_key_acting_as_a_person_with_no_email_is_labelled_the_same_way(self, world):
        raw = "aisoc_" + uuid.uuid4().hex
        with Session(world.sync) as s:
            s.add(ApiKey(id=uuid.uuid4(), tenant_id=world.ta.id, user_id=world.users["nomail"].id, name="ci", key_prefix=raw[:12], hashed_key=hash_api_key(raw), scopes=["*"], is_active=True))
            s.commit()
        creds = SimpleNamespace(credentials=raw)
        assert run(world, lambda s: deps.get_current_user(creds, s)).email == "nomail"

    def test_the_audit_service_receives_that_label(self, world, monkeypatch):
        """audit.emit_audit(actor_email=current_user.email): for a person with no email that is their account name, never None or the literal 'None'."""
        user = self.principal(world, monkeypatch, "nomail")
        assert user.email and user.email != "None"


class TestPasskeys:
    def test_sign_in_looks_the_person_up_by_what_they_typed_and_labels_the_credential_with_the_account_name(self):
        src = (APP / "api/v1/endpoints/passkeys.py").read_text(encoding="utf-8")
        assert "find_user_by_login(db, body.identifier, active_only=True)" in src
        assert "user_name=user_row.account_name" in src and "user_display_name=user_row.username or user_row.account_name" in src
        assert '"account_name": user_row.account_name' in src and '"email": user_row.email or user_row.account_name' in src

    @pytest.mark.parametrize("key", ["email", "account_name", "username", "identifier"])
    def test_the_begin_request_accepts_every_key_and_the_old_email_one_still_means_the_same(self, key):
        from app.api.v1.endpoints import passkeys

        assert passkeys.AuthenticateBeginRequest(**{key: "alice"}).identifier == "alice"

    def test_the_begin_request_may_be_empty_for_a_discoverable_credential(self):
        from app.api.v1.endpoints import passkeys

        assert passkeys.AuthenticateBeginRequest().identifier is None


class TestCreatingAUser:
    def create(self, world, tenant=None, **fields):
        fields.setdefault("password", "Str0ng-Passw0rd!")
        body = tn.CreateUserRequest(**fields)
        who = SimpleNamespace(tenant_id=(tenant or world.ta).id, user_id=uuid.uuid4(), can_grant_role=lambda role: True)
        return run(world, lambda s: tn.create_user(request=body, current_user=who, db=s))

    def test_a_chosen_name_with_no_email(self, world):
        out = self.create(world, account_name="Carol.Jones", username="Carol Jones")
        assert out.account_name == "carol.jones" and out.email is None and out.username == "Carol Jones"
        assert sign_in(world, "CAROL.JONES", "Str0ng-Passw0rd!").status_code == 200

    def test_the_display_name_defaults_to_the_account_name(self, world):
        assert self.create(world, account_name="carol").username == "carol"

    def test_an_optional_email_is_still_accepted_and_stored_lower_cased(self, world):
        out = self.create(world, account_name="carol", email="Carol@A.Example")
        assert out.email == "carol@a.example"
        assert sign_in(world, "carol@a.example", "Str0ng-Passw0rd!").status_code == 401, "an email is contact information: it does not sign anyone in by default"
        assert sign_in(world, "carol", "Str0ng-Passw0rd!").status_code == 200

    @pytest.mark.parametrize("bad", ["ab", "has space", "x" * 40, "a@b.com", "-lead", "UNI\u00c7"])
    def test_an_invalid_name_is_a_422_with_the_rule(self, world, bad):
        with pytest.raises(HTTPException) as e:
            self.create(world, account_name=bad)
        assert e.value.status_code == 422 and "3 to 32" in e.value.detail
        assert "carol" not in names(world)

    @pytest.mark.parametrize("variant", ["alice", "ALICE", " Alice "])
    def test_a_name_taken_in_the_callers_own_tenant_is_a_409(self, world, variant):
        with pytest.raises(HTTPException) as e:
            self.create(world, account_name=variant)
        assert e.value.status_code == 409 and e.value.detail == "That account name is already taken. Choose another."

    def test_a_name_taken_in_ANOTHER_tenant_is_a_409_too_names_are_platform_wide(self, world):
        with pytest.raises(HTTPException) as e:
            self.create(world, world.tb, account_name="alice")
        assert e.value.status_code == 409 and "already taken" in e.value.detail
        assert names(world).count("alice") == 1

    def test_without_a_name_one_is_made_from_the_username(self, world):
        out = self.create(world, username="Dave Brown", email="dave@a.example")
        assert out.account_name == "dave-brown" and out.username == "Dave Brown"

    def test_without_a_name_or_username_one_is_made_from_the_email(self, world):
        assert self.create(world, email="Erin.Fox@A.example").account_name == "erin.fox"

    def test_a_made_name_that_is_taken_gets_a_number_instead_of_an_error(self, world):
        a, b = self.create(world, username="alice", email="a1@a.example"), self.create(world, username="alice", email="a2@a.example")
        assert (a.account_name, b.account_name) == ("alice-2", "alice-3")

    def test_an_older_client_that_sends_email_username_password_still_works(self, world):
        out = self.create(world, email="old.client@a.example", username="oldclient", role="soc_analyst")
        assert out.account_name == "oldclient" and out.email == "old.client@a.example"

    def test_nothing_to_make_a_name_from_is_a_validation_error(self):
        with pytest.raises(ValidationError):
            tn.CreateUserRequest(password="Str0ng-Passw0rd!")

    def test_the_email_conflict_rules_still_apply_when_an_account_name_is_given(self, world):
        with pytest.raises(HTTPException) as e:
            self.create(world, account_name="carol", email="alice@a.example")
        assert e.value.status_code == 409 and "in your organization" in e.value.detail
        with pytest.raises(HTTPException) as e:
            self.create(world, world.tb, account_name="carol", email="ALICE@a.example")
        assert e.value.status_code == 409 and e.value.detail == "This email address cannot be used. Choose a different one."
        assert "carol" not in names(world)

    def test_two_creations_racing_for_the_same_name_are_decided_by_the_database_not_a_500(self, world):
        class RacesAtCommit:
            def __init__(self, s):
                self.s, self.rolled = s, False

            async def commit(self):
                raise IntegrityError("insert", {}, Exception("duplicate key"))

            async def rollback(self):
                self.rolled = True

            def __getattr__(self, name):
                return getattr(self.s, name)

        body = tn.CreateUserRequest(account_name="racer", password="Str0ng-Passw0rd!")
        who = SimpleNamespace(tenant_id=world.ta.id, user_id=uuid.uuid4(), can_grant_role=lambda role: True)
        holder = {}

        async def go(s):
            holder["db"] = RacesAtCommit(s)
            return await tn.create_user(request=body, current_user=who, db=holder["db"])

        with pytest.raises(HTTPException) as e:
            run(world, go)
        assert e.value.status_code == 409 and "just taken" in e.value.detail and holder["db"].rolled

    def test_the_database_itself_refuses_a_duplicate_name_in_another_case(self, world):
        with pytest.raises(IntegrityError):
            with Session(world.sync) as s:
                s.add(User(id=uuid.uuid4(), tenant_id=world.tb.id, account_name="ALICE", username="x", hashed_password=HASH, role="admin"))
                s.commit()


class TestTheModel:
    def test_a_user_created_without_a_name_gets_one_made_from_the_username(self, world):
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, username="Zed Quill", email="zq@a.example", hashed_password=HASH, role="admin"))
            s.commit()
        assert "zed-quill" in names(world)

    def test_the_email_is_optional(self, world):
        assert User.__table__.c.email.nullable and not User.__table__.c.account_name.nullable

    def test_two_accounts_with_no_email_can_coexist(self, world):
        assert names(world).count("nomail") == 1
        with Session(world.sync) as s:
            s.add(User(id=uuid.uuid4(), tenant_id=world.ta.id, account_name="nomail-two", username="x", hashed_password=HASH, role="admin"))
            s.commit()
        assert {"nomail", "nomail-two"} <= set(names(world))


class TestEveryCreationPathSetsAName:
    def test_each_place_that_creates_a_user_names_it_explicitly(self):
        """A name made by the model's fallback could collide: code that creates accounts for real must choose one, and make it unique."""
        expected = {
            "api/v1/endpoints/tenants.py": "account_name=name,",
            "services/tenant_provision/provisioner.py": "account_name=await unique_account_name(db, entry.email)",
            "scripts/bootstrap_production.py": "account_name=chosen_name,",
            "scripts/seed_demo.py": 'account_name="demo",',
        }
        for rel, needle in expected.items():
            assert needle in (APP / rel).read_text(encoding="utf-8"), f"{rel} no longer names the account it creates ({needle})"

    def test_the_demo_name_is_a_valid_account_name(self):
        assert an.is_valid_account_name("demo")

    def test_no_new_place_constructs_a_user_without_being_listed_here(self):
        """Every `User(` construction in app/ must be one of the four above (a fifth must be added to the list, with its name set explicitly)."""
        found = []
        for p in APP.rglob("*.py"):
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if re.search(r"(?<![\w.])User\(\s*$", line) or re.search(r"(?<![\w.])User\(id=|(?<![\w.])User\(tenant_id=", line):
                    found.append(str(p.relative_to(APP)))
        assert sorted(set(found)) == ["api/v1/endpoints/tenants.py", "scripts/bootstrap_production.py", "scripts/seed_demo.py", "services/tenant_provision/provisioner.py"]

    def test_bootstrap_takes_a_validated_optional_name(self):
        src = (APP / "scripts/bootstrap_production.py").read_text(encoding="utf-8")
        assert "--admin-name" in src and "validate_account_name(admin_name)" in src and "unique_account_name(session, email)" in src

    def test_the_default_for_email_sign_in_is_off_people_sign_in_with_their_account_name(self):
        assert settings.LOGIN_ALLOW_EMAIL is False


class TestTheMigration:
    SQL = " ".join((Path(__file__).resolve().parent.parent / "migrations" / "071_users_account_name.sql").read_text().split())

    def test_it_adds_the_column_makes_it_required_and_makes_the_email_optional(self):
        assert "ADD COLUMN IF NOT EXISTS account_name VARCHAR(32)" in self.SQL
        assert "ALTER COLUMN account_name SET NOT NULL" in self.SQL and "ALTER COLUMN email DROP NOT NULL" in self.SQL

    def test_it_enforces_the_shape_and_the_uniqueness_in_the_database(self):
        assert "CHECK (account_name ~ '^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$')" in self.SQL
        assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_account_name_lower ON users (lower(account_name))" in self.SQL

    def test_the_shape_in_sql_is_the_shape_in_python(self):
        assert "'" + an.ACCOUNT_NAME_PATTERN + "'" in self.SQL

    def test_the_backfill_is_oldest_first_and_only_touches_users_without_a_name_so_it_is_repeatable(self):
        assert "WHERE account_name IS NULL ORDER BY created_at, id" in self.SQL

    def test_it_never_rewrites_or_deletes_anything_else(self):
        assert "DELETE FROM users" not in self.SQL and "UPDATE users SET email" not in self.SQL and "UPDATE users SET username" not in self.SQL


class TestEmailSignInIsOffByDefault:
    """People sign in with their ACCOUNT NAME. An email offered while email sign-in is off must be answered exactly like a wrong password: no way to learn that the address belongs to a real account."""

    def test_an_email_with_the_right_password_is_refused_exactly_like_a_wrong_password(self, world):
        right = sign_in(world, "alice@a.example")
        wrong = sign_in(world, "alice@a.example", "not the password")
        unknown = sign_in(world, "nobody@a.example")
        assert right.status_code == wrong.status_code == unknown.status_code == 401
        assert right.json() == wrong.json() == unknown.json()
        for header in ("www-authenticate", "retry-after", "x-ratelimit-remaining"):
            assert right.headers.get(header) == wrong.headers.get(header) == unknown.headers.get(header), header

    def test_it_costs_the_same_as_a_real_check_so_timing_does_not_give_it_away(self, world, monkeypatch):
        """The equaliser (a hash check against a throwaway hash) runs for an email that is not accepted, just as for an unknown account name."""
        calls: list[tuple] = []
        real = auth.verify_password_or_equalise

        def spy(plain, hashed):
            calls.append((plain, hashed is None))
            return real(plain, hashed)

        monkeypatch.setattr(auth, "verify_password_or_equalise", spy)
        sign_in(world, "alice@a.example")
        sign_in(world, "no-such-name")
        assert calls == [(PASSWORD, True), (PASSWORD, True)], "no real hash was consulted for the email, exactly as for an unknown name"

    def test_failed_attempts_with_an_email_still_count_toward_the_lock(self, world, monkeypatch):
        monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ACCOUNT", 2)
        assert [sign_in(world, "alice@a.example").status_code for _ in range(2)] == [401, 401]
        locked = sign_in(world, "alice@a.example")
        assert locked.status_code == 429 and "try again" in locked.json()["detail"].lower()
        assert sign_in(world, "alice").status_code == 200, "the person's account name is a different identifier and is not locked"

    def test_the_same_email_signs_in_when_the_option_is_switched_on(self, world, monkeypatch):
        patch_login_allow_email(monkeypatch, True)
        assert sign_in(world, "alice@a.example").status_code == 200


def test_no_test_patches_the_email_sign_in_setting_through_its_own_copy_of_the_settings_object():
    """That passes alone and fails in the full run (see tests/settings_support.py). Use patch_login_allow_email. (This file is not scanned: it only mentions the pattern here.)"""
    from pathlib import Path

    pattern = 'setattr(settings, "LOGIN_ALLOW_EMAIL"'
    offenders = [f"{path.name}:{n}" for path in sorted(Path(__file__).parent.glob("test_*.py")) if path.name != Path(__file__).name for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if pattern in line]
    assert offenders == [], offenders
    assert pattern in (Path(__file__).parent / "test_account_names.py").read_text(encoding="utf-8"), "the guard's own pattern is still the real one"
