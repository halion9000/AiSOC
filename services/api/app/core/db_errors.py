"""Database constraint violations are the CLIENT's problem, not a server error.

An unhandled sqlalchemy IntegrityError / DataError used to escape as an HTTP 500 with no explanation. Found by sending ordinary create requests to the real API on real Postgres: threat-intel feeds and IOCs, posture findings, identity nodes and report templates all
answered 500 when the body carried a value their CHECK constraint refuses (an unknown feed_type, say). That is a request the caller can correct, so it is a 4xx, and a 500 also looks to a browser like a CORS failure because it is produced outside the CORS middleware.

 * unique violation (23505)                       -> 409  "That already exists"
 * foreign key (23503)                            -> 422  "A value refers to something that does not exist"
 * not-null (23502)                               -> 422  "A required value is missing"
 * check (23514) and other integrity violations   -> 422  "A value is not allowed"
 * data exception (SQLSTATE class 22: too long, bad format, out of range...)  -> 422  "A value is invalid or too long"
   NOTE the asyncpg driver reports "value too long" as a plain DBAPIError, NOT a DataError, so the class-22 case is recognised by its SQLSTATE. Every OTHER DBAPIError (a dropped connection, a SQL bug, a missing table) is
   re-raised untouched and stays the 500 it always was: those are the server's fault.

The client gets a fixed sentence: never the SQL, the bound values, or the constraint's name (those tell an attacker about the schema). Operators get the sqlstate and constraint name in the log. Handlers that already catch IntegrityError themselves keep doing so.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError

logger = structlog.get_logger(__name__)

CONFLICT = (409, "That already exists")
BY_SQLSTATE: dict[str, tuple[int, str]] = {
    "23505": CONFLICT,
    "23503": (422, "A value refers to something that does not exist"),
    "23502": (422, "A required value is missing"),
    "23514": (422, "A value is not allowed"),
}
OTHER_INTEGRITY = (422, "A value is not allowed")
DATA_ERROR = (422, "A value is invalid or too long")


def _driver_error(exc: Exception) -> Any:
    """The asyncpg exception under SQLAlchemy's adapter (which wraps it as __cause__)."""
    orig = getattr(exc, "orig", None)
    return getattr(orig, "__cause__", None) or orig


def sqlstate_of(exc: Exception) -> str | None:
    d = _driver_error(exc)
    return getattr(d, "sqlstate", None) or getattr(d, "pgcode", None) or getattr(getattr(exc, "orig", None), "sqlstate", None) or getattr(getattr(exc, "orig", None), "pgcode", None)


def classify(exc: Exception) -> tuple[int, str] | None:
    """The (status, sentence) for a client-caused database error, or None when the server is at fault and the exception must be left alone."""
    state = sqlstate_of(exc) or ""
    if isinstance(exc, IntegrityError):
        return BY_SQLSTATE.get(state, OTHER_INTEGRITY)
    if isinstance(exc, DataError) or state.startswith("22"):
        return DATA_ERROR
    if state.startswith("23"):
        return BY_SQLSTATE.get(state, OTHER_INTEGRITY)
    return None


async def constraint_violation_handler(request: Request, exc: Exception) -> JSONResponse:
    verdict = classify(exc)
    if verdict is None:
        raise exc  # not the client's doing: behave exactly as if no handler were registered (a 500, logged with its traceback)
    status, detail = verdict
    logger.info("db.constraint_violation", path=request.url.path, method=request.method, sqlstate=sqlstate_of(exc), constraint=getattr(_driver_error(exc), "constraint_name", None), status=status)
    return JSONResponse(status_code=status, content={"detail": detail})


def register_db_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(IntegrityError, constraint_violation_handler)
    app.add_exception_handler(DataError, constraint_violation_handler)
    app.add_exception_handler(DBAPIError, constraint_violation_handler)  # most specific class wins, so the two above still apply to their own
