"""Does the database match what the ORM models expect? (read-only: it only queries information_schema)

    python -m app.scripts.schema_drift                # report
    python -m app.scripts.schema_drift --json
    python -m app.scripts.schema_drift --strict       # exit 1 if any ORM table or column is missing, or a column's type is incompatible

WHY. The ORM and the migrations are two descriptions of one schema and nothing forces them to agree. A column the ORM expects but the database lacks, or a type that disagrees (`IdentityNode.is_active` was mapped as a String for a boolean column, so EVERY insert failed), is a crash
waiting for the first request that touches it, and no unit test notices because the suite runs on SQLite. The comparison against a real migrated Postgres found that one; the models and migrations otherwise agree (63 of 63 tables, every column).

It does not compare constraints or indexes, and a NOT NULL the database does not enforce is reported as information only (legacy rows can then hold NULL where a response model requires a value).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

# SQLAlchemy type -> the information_schema.data_type values that can hold it. Checked by exact class first, then by isinstance (so subclasses are covered).
FAMILY: dict[type, set[str]] = {
    sa.Boolean: {"boolean"},
    sa.SmallInteger: {"smallint", "integer"},
    sa.BigInteger: {"bigint", "integer"},
    sa.Integer: {"integer", "bigint", "smallint"},
    sa.Float: {"double precision", "real", "numeric"},
    sa.Numeric: {"numeric", "double precision", "real"},
    sa.DateTime: {"timestamp with time zone", "timestamp without time zone"},
    sa.Date: {"date"},
    sa.Time: {"time without time zone", "time with time zone"},
    sa.Text: {"text", "character varying", "character"},
    sa.String: {"character varying", "text", "character"},
    sa.LargeBinary: {"bytea"},
    sa.Enum: {"USER-DEFINED", "character varying", "text"},  # a native Postgres enum reports USER-DEFINED
    sa.JSON: {"jsonb", "json"},
    pg.JSONB: {"jsonb", "json"},
    pg.UUID: {"uuid"},
    sa.Uuid: {"uuid"},
    sa.ARRAY: {"ARRAY"},
    pg.ARRAY: {"ARRAY"},
    pg.INET: {"inet"},
}


def compatible_types(col_type: Any) -> set[str] | None:
    """The database types that can hold this column type, or None if the type is not one this tool knows (those are not judged)."""
    for klass, ok in FAMILY.items():
        if type(col_type) is klass:
            return ok
    for klass, ok in FAMILY.items():
        if isinstance(col_type, klass):
            return ok
    return None


@dataclass
class Drift:
    orm_tables: int = 0
    missing_tables: list[str] = field(default_factory=list)
    missing_columns: list[tuple[str, str]] = field(default_factory=list)
    type_mismatches: list[tuple[str, str, str, str]] = field(default_factory=list)  # table, column, ORM type, database type
    not_null_not_enforced: list[tuple[str, str]] = field(default_factory=list)

    @property
    def defects(self) -> int:
        return len(self.missing_tables) + len(self.missing_columns) + len(self.type_mismatches)


def compare(metadata: sa.MetaData, db: dict[str, dict[str, dict[str, str]]]) -> Drift:
    """`db` is {table: {column: {"data_type": ..., "is_nullable": "YES"|"NO"}}}."""
    out = Drift(orm_tables=len(metadata.tables))
    for name, table in sorted(metadata.tables.items()):
        if name not in db:
            out.missing_tables.append(name)
            continue
        for col in table.columns:
            d = db[name].get(col.name)
            if d is None:
                out.missing_columns.append((name, col.name))
                continue
            ok = compatible_types(col.type)
            if ok is not None and d["data_type"] not in ok:
                out.type_mismatches.append((name, col.name, type(col.type).__name__, d["data_type"]))
            if not col.nullable and d["is_nullable"] == "YES" and col.default is None and col.server_default is None and not col.primary_key:
                out.not_null_not_enforced.append((name, col.name))
    return out


def render(d: Drift) -> str:
    out = [f"{d.orm_tables} ORM tables; {d.orm_tables - len(d.missing_tables)} exist in the database; {d.defects} defect(s)."]
    if d.missing_tables:
        out += ["", "ORM tables the database does not have:"] + [f"  {t}" for t in d.missing_tables]
    if d.missing_columns:
        out += ["", "ORM columns the database does not have:"] + [f"  {t}.{c}" for t, c in d.missing_columns]
    if d.type_mismatches:
        out += ["", "Type mismatches (the ORM will send values the column cannot hold):"] + [f"  {t}.{c}: ORM {o}, database {db_}" for t, c, o, db_ in d.type_mismatches]
    if d.not_null_not_enforced:
        out += ["", f"Information: {len(d.not_null_not_enforced)} column(s) the ORM treats as required but the database lets be NULL (legacy rows can break a response model that requires them):"]
        out += [f"  {t}.{c}" for t, c in d.not_null_not_enforced]
    return "\n".join(out)


def exit_code(d: Drift, *, strict: bool) -> int:
    return 1 if strict and d.defects else 0


async def collect(conn: Any) -> dict[str, dict[str, dict[str, str]]]:
    rows = await conn.fetch("SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'public'")
    db: dict[str, dict[str, dict[str, str]]] = {}
    for r in rows:
        db.setdefault(r["table_name"], {})[r["column_name"]] = {"data_type": r["data_type"], "is_nullable": r["is_nullable"]}
    return db


async def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare the ORM models with the database (read-only).")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any ORM table or column is missing or a type is incompatible")
    args = ap.parse_args(argv)
    import app.models  # noqa: F401, PLC0415  (registers every model on Base.metadata)
    from app.core.config import settings  # noqa: PLC0415
    from app.db.database import Base  # noqa: PLC0415
    from app.scripts.run_migrations import _connect  # noqa: PLC0415

    conn = await _connect(str(settings.DATABASE_URL))  # the service's own connection, not the migration one
    try:
        db = await collect(conn)
    finally:
        await conn.close()
    drift = compare(Base.metadata, db)
    print(json.dumps({**asdict(drift), "defects": drift.defects}, indent=2) if args.json else render(drift))
    return exit_code(drift, strict=args.strict)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
