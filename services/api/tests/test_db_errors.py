"""A database constraint violation is the caller's to correct (4xx), never a bare 500; a genuine server fault stays a 500.

Found by sending ordinary create requests to the real API on real Postgres: threat-intel feeds and IOCs, posture findings, identity nodes and report templates answered HTTP 500 when the body carried a value their CHECK constraint refuses. Classification was checked against the REAL asyncpg errors
(check 23514, foreign key 23503, not-null 23502, unique 23505 are IntegrityErrors; "value too long" is a plain DBAPIError with SQLSTATE 22001, NOT a DataError, which is why the class-22 case is recognised by SQLSTATE).
"""
import httpx
import pytest
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError, OperationalError, ProgrammingError

from app.core import db_errors as de


class Driver(Exception):
    """What asyncpg raises: carries sqlstate, and for constraint errors the constraint's name."""

    def __init__(self, sqlstate, constraint=None):
        super().__init__(f"driver error {sqlstate}")
        self.sqlstate, self.constraint_name = sqlstate, constraint


class Adapter(Exception):
    """SQLAlchemy's asyncpg adapter wraps the driver error as __cause__."""

    def __init__(self, driver):
        super().__init__("adapter")
        self.__cause__ = driver


SECRET_SQL = "INSERT INTO threat_intel_feeds (name, feed_type) VALUES ($1, $2)"
SECRET_VALUE = "s3cret-value"


def err(kind, sqlstate, constraint=None):
    return kind(SECRET_SQL, {"name": SECRET_VALUE}, Adapter(Driver(sqlstate, constraint)))


class TestClassify:
    @pytest.mark.parametrize("state,expected", [
        ("23505", (409, "That already exists")),
        ("23503", (422, "A value refers to something that does not exist")),
        ("23502", (422, "A required value is missing")),
        ("23514", (422, "A value is not allowed")),
        ("23P01", (422, "A value is not allowed")),  # exclusion violation: any other integrity error
    ])
    def test_integrity_errors(self, state, expected):
        assert de.classify(err(IntegrityError, state)) == expected

    def test_an_integrity_error_with_no_sqlstate_at_all_is_still_a_client_error(self):
        assert de.classify(IntegrityError("s", {}, Exception("x"))) == (422, "A value is not allowed")

    def test_a_DataError_is_a_client_error(self):
        assert de.classify(err(DataError, "22P02")) == (422, "A value is invalid or too long")

    @pytest.mark.parametrize("state", ["22001", "22003", "22007", "22P02"])
    def test_a_plain_DBAPIError_in_class_22_is_a_client_error(self, state):
        """asyncpg reports 'value too long' like this (SQLSTATE 22001), not as DataError."""
        assert de.classify(err(DBAPIError, state)) == (422, "A value is invalid or too long")

    @pytest.mark.parametrize("kind,state", [
        (ProgrammingError, "42P01"),  # undefined table: a bug of ours
        (ProgrammingError, "42703"),  # undefined column
        (OperationalError, "08006"),  # connection failure
        (OperationalError, "57P03"),  # cannot connect now
        (DBAPIError, "40001"),  # serialization failure
        (DBAPIError, "53300"),  # too many connections
        (DBAPIError, None),
    ])
    def test_everything_else_is_the_servers_fault_and_is_not_classified(self, kind, state):
        assert de.classify(err(kind, state) if state else kind("s", {}, Exception("x"))) is None

    def test_the_sqlstate_is_found_through_the_adapter_or_directly(self):
        assert de.sqlstate_of(err(IntegrityError, "23505")) == "23505"

        class Direct(Exception):
            sqlstate = "23514"

        assert de.sqlstate_of(IntegrityError("s", {}, Direct())) == "23514"

        class Legacy(Exception):
            pgcode = "23503"

        assert de.sqlstate_of(IntegrityError("s", {}, Legacy())) == "23503"


def make_app(exc_factory, *, cors=False):
    app = FastAPI()
    de.register_db_error_handlers(app)

    @app.post("/boom")
    async def boom():
        raise exc_factory()

    if cors:
        app.add_middleware(CORSMiddleware, allow_origins=["https://ui.example"], allow_methods=["*"], allow_headers=["*"])
    return app


async def post(app, **kw):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=kw.pop("raise_app_exceptions", False))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        return await c.post("/boom", **kw)


@pytest.mark.asyncio
class TestTheHandler:
    @pytest.mark.parametrize("kind,state,status,detail", [
        (IntegrityError, "23505", 409, "That already exists"),
        (IntegrityError, "23514", 422, "A value is not allowed"),
        (IntegrityError, "23503", 422, "A value refers to something that does not exist"),
        (IntegrityError, "23502", 422, "A required value is missing"),
        (DBAPIError, "22001", 422, "A value is invalid or too long"),
        (DataError, "22P02", 422, "A value is invalid or too long"),
    ])
    async def test_the_client_gets_the_status_and_a_fixed_sentence(self, kind, state, status, detail):
        r = await post(make_app(lambda: err(kind, state, "threat_intel_feeds_feed_type_check")))
        assert r.status_code == status and r.json() == {"detail": detail}

    async def test_the_client_never_sees_the_sql_the_values_or_the_constraint_name(self):
        r = await post(make_app(lambda: err(IntegrityError, "23514", "threat_intel_feeds_feed_type_check")))
        for leaked in (SECRET_SQL, "INSERT", SECRET_VALUE, "threat_intel_feeds", "feed_type_check", "constraint", "Driver"):
            assert leaked not in r.text

    @pytest.mark.parametrize("kind,state", [(ProgrammingError, "42P01"), (OperationalError, "08006"), (DBAPIError, "53300")])
    async def test_a_server_fault_is_still_a_500(self, kind, state):
        r = await post(make_app(lambda: err(kind, state)))
        assert r.status_code == 500

    async def test_a_server_fault_still_propagates_to_whoever_would_have_seen_it(self):
        with pytest.raises(ProgrammingError):
            await post(make_app(lambda: err(ProgrammingError, "42P01")), raise_app_exceptions=True)

    async def test_an_unrelated_exception_is_not_touched(self):
        with pytest.raises(RuntimeError):
            await post(make_app(lambda: RuntimeError("bug")), raise_app_exceptions=True)

    async def test_operators_get_the_sqlstate_and_constraint_in_the_log_but_only_for_client_errors(self):
        with structlog.testing.capture_logs() as logs:
            await post(make_app(lambda: err(IntegrityError, "23505", "tenants_slug_key")))
            await post(make_app(lambda: err(ProgrammingError, "42P01")))
        events = [x for x in logs if x["event"] == "db.constraint_violation"]
        assert len(events) == 1 and events[0]["sqlstate"] == "23505" and events[0]["constraint"] == "tenants_slug_key" and events[0]["status"] == 409 and events[0]["path"] == "/boom"

    async def test_a_handled_error_carries_the_CORS_headers_an_unhandled_500_does_not(self):
        """Why a 500 looked to the browser like a CORS failure: it is produced outside the CORS middleware."""
        origin = {"Origin": "https://ui.example"}
        handled = await post(make_app(lambda: err(IntegrityError, "23514"), cors=True), headers=origin)
        unhandled = await post(make_app(lambda: RuntimeError("bug"), cors=True), headers=origin)
        assert handled.status_code == 422 and handled.headers.get("access-control-allow-origin") == "https://ui.example"
        assert unhandled.status_code == 500 and "access-control-allow-origin" not in unhandled.headers


class TestRegistration:
    def test_the_real_application_has_the_handlers(self):
        from app.main import app

        for kind in (IntegrityError, DataError, DBAPIError):
            assert app.exception_handlers[kind] is de.constraint_violation_handler

    def test_an_error_a_handler_catches_itself_is_unaffected(self):
        """saved_views, saved_hunts, waitlist and alerts catch IntegrityError in the handler and answer with their own message; the app-level handler only sees what escapes."""
        import re
        from pathlib import Path

        ep = Path(__file__).resolve().parent.parent / "app" / "api" / "v1" / "endpoints"
        owners = {p.name for p in ep.glob("*.py") if re.search(r"except [^\n]*IntegrityError", p.read_text(encoding="utf-8", errors="replace"))}
        assert {"saved_views.py", "saved_hunts.py", "waitlist.py", "alerts.py"} <= owners
