"""Fold each archived client tenant ("<name> (archived)") into its live twin ("<name>"), then delete the archived tenant.

An archived client is a leftover: it was renamed instead of deleted because it still owned a few records (alerts that were never worked, AI triage runs and their events, memory notes). This
moves those records to the live client and removes the empty shell. Nothing is thrown away except what is a pure duplicate (the detection-rule copies every client gets, and computed metrics).

    python -m app.scripts.merge_archived_clients                 # dry run: prints the plan, changes nothing
    python -m app.scripts.merge_archived_clients --apply         # does it, one client per transaction
    python -m app.scripts.merge_archived_clients --apply --backup-dir /tmp --only "Hahn Agency"

Safety:
- Every row it is about to move is first written to a JSON file (``--backup-dir``); with ``--apply`` nothing is changed if that file cannot be written.
- A client is refused, and left alone, when it owns anything this script does not know how to move, or has no live twin, or has records the database would reject on the move (the reason is printed).
- investigation_events are tamper-proof (a trigger refuses any change). They are re-homed by switching that one trigger off and back on INSIDE the same transaction, changing only the owner column;
  a failure rolls everything back, trigger included. Afterwards the trigger's state is checked on a fresh connection.
- Needs a database role that owns the tables (the API's own connection does).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

ARCHIVED_SUFFIX = " (archived)"
EVENTS_TRIGGER = "trg_inv_events_immutable"

# (table, column) pairs that carry the tenant and are moved to the live client as they are. Order matters only for readability: ids do not change, so no foreign key is disturbed.
MOVE: tuple[tuple[str, str], ...] = (
    ("alerts", "tenant_id"),
    ("aisoc_institutional_memory", "tenant_id"),
    ("investigation_runs", "tenant_id"),
    ("investigation_events", "tenant_id"),
    ("aisoc_run_costs", "tenant_id"),
)
# Computed or duplicated data that is simply dropped with the archived tenant.
DROP: tuple[tuple[str, str], ...] = (("mssp_tenant_metrics", "tenant_id"),)
RULES = ("detection_rules", "tenant_id")
ALIASES = ("client_aliases", "child_tenant_id")
HANDLED = {*MOVE, *DROP, RULES, ALIASES}
# Where a client tenant is the PARENT of rows that belong to the MSSP, not to the client: those stay.
_IDENT = re.compile(r"^[a-z_][a-z0-9_.]*$")

_FK_SQL = text(
    """
    SELECT c.conrelid::regclass::text AS tbl, a.attname AS col
    FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
    WHERE c.contype = 'f' AND c.confrelid = 'tenants'::regclass AND array_length(c.conkey, 1) = 1
    ORDER BY 1, 2
    """
)


_TENANT_COLUMN_SQL = text(
    """
    SELECT c.table_name AS tbl, c.column_name AS col, c.data_type AS kind FROM information_schema.columns c
    JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
    WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id'
    """
)
# Some tables keep the tenant as text rather than uuid; their values must be written as text. Filled in from the catalogue by ``references``.
TEXT_COLUMNS: set[tuple[str, str]] = set()


def value_for(table: str, column: str, tenant_id: uuid.UUID) -> uuid.UUID | str:
    return str(tenant_id) if (table, column) in TEXT_COLUMNS else tenant_id


async def references(conn: AsyncConnection) -> list[tuple[str, str]]:
    """Every (table, column) that can belong to a tenant: those with a foreign key to tenants.id AND every table with a tenant_id column (some have none), from the database's own
    catalogue, so a table added later is noticed instead of being silently left behind."""
    columns = (await conn.execute(_TENANT_COLUMN_SQL)).all()
    TEXT_COLUMNS.clear()
    TEXT_COLUMNS.update((r.tbl, r.col) for r in columns if r.kind != "uuid")
    pairs = {(r.tbl, r.col) for r in (await conn.execute(_FK_SQL)).all()} | {(r.tbl, r.col) for r in columns}
    for tbl, col in pairs:
        if not (_IDENT.match(tbl) and _IDENT.match(col)):
            raise RuntimeError(f"unexpected identifier {tbl}.{col}")
    return sorted(pairs)


async def owned(conn: AsyncConnection, tenant_id: uuid.UUID, refs: list[tuple[str, str]]) -> dict[tuple[str, str], int]:
    """How many rows of each referencing table belong to ``tenant_id`` (only those with any). Compared as text so uuid and text columns are treated alike."""
    out: dict[tuple[str, str], int] = {}
    for tbl, col in refs:
        n = (await conn.execute(text(f"SELECT count(*) FROM {tbl} WHERE CAST({col} AS text) = :t"), {"t": str(tenant_id)})).scalar_one()  # noqa: S608 - names come from the catalogue, checked above
        if n:
            out[(tbl, col)] = int(n)
    return out


async def archived_clients(conn: AsyncConnection, only: str | None) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            text(
                """
                SELECT a.id, a.name, a.parent_tenant_id, l.id AS live_id, l.name AS live_name
                FROM tenants a
                LEFT JOIN tenants l ON l.parent_tenant_id = a.parent_tenant_id AND l.name = left(a.name, length(a.name) - :n)
                WHERE a.name LIKE :pat AND a.parent_tenant_id IS NOT NULL
                ORDER BY a.name
                """
            ),
            {"n": len(ARCHIVED_SUFFIX), "pat": "%" + ARCHIVED_SUFFIX},
        )
    ).all()
    found = [dict(r._mapping) for r in rows]
    return [r for r in found if only is None or r["name"] in (only, only + ARCHIVED_SUFFIX)]


async def plan_for(conn: AsyncConnection, client: dict[str, Any], refs: list[tuple[str, str]]) -> dict[str, Any]:
    """What would happen to one archived client: counts to move and drop, and the reasons it is refused (empty list when it can be merged)."""
    problems: list[str] = []
    live_id = client["live_id"]
    if live_id is None:
        problems.append("there is no live client with the same name (without the archived suffix)")
    counts = await owned(conn, client["id"], refs)
    unknown = {k: n for k, n in counts.items() if k not in HANDLED}
    for (tbl, col), n in unknown.items():
        problems.append(f"it owns {n} row(s) in {tbl}.{col}, which this script does not move")
    rules = {"move": 0, "duplicate": 0}
    if RULES in counts and live_id is not None:
        dup = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM detection_rules s WHERE s.tenant_id = :s AND EXISTS (SELECT 1 FROM detection_rules l WHERE l.tenant_id = :l AND l.name = s.name)"
                ),
                {"s": client["id"], "l": live_id},
            )
        ).scalar_one()
        rules = {"duplicate": int(dup), "move": counts[RULES] - int(dup)}
    if live_id is not None:
        clash = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM alerts s JOIN alerts l ON l.tenant_id = :l AND l.idempotency_key = s.idempotency_key "
                    "WHERE s.tenant_id = :s AND s.idempotency_key IS NOT NULL"
                ),
                {"s": client["id"], "l": live_id},
            )
        ).scalar_one()
        if clash:
            problems.append(f"{clash} alert(s) share an idempotency key with the live client's alerts")
    return {
        "client": client["name"],
        "id": str(client["id"]),
        "live": client["live_name"],
        "live_id": str(live_id) if live_id else None,
        "move": {t: counts[(t, c)] for t, c in MOVE if (t, c) in counts},
        "drop": {t: counts[(t, c)] for t, c in DROP if (t, c) in counts},
        "rules": rules,
        "aliases": counts.get(ALIASES, 0),
        "problems": problems,
    }


async def backup(conn: AsyncConnection, client: dict[str, Any], directory: Path) -> Path:
    """Write every row that is about to move (and the duplicate rules) to a JSON file. Returns its path; raises if it cannot be written."""
    payload: dict[str, Any] = {
        "archived_client": client["name"],
        "archived_id": str(client["id"]),
        "live_client": client["live_name"],
        "taken_at": datetime.now(UTC).isoformat(),
        "tables": {},
    }
    for tbl, col in (*MOVE, *DROP, RULES):
        rows = (
            await conn.execute(text(f"SELECT row_to_json(t) AS j FROM {tbl} t WHERE CAST({col} AS text) = :t"), {"t": str(client["id"])})
        ).all()  # noqa: S608 - constants
        if rows:
            payload["tables"][tbl] = [r.j for r in rows]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"archived-client-{re.sub(r'[^A-Za-z0-9]+', '-', client['name']).strip('-')}-{datetime.now(UTC):%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    if path.stat().st_size == 0:
        raise RuntimeError(f"the backup file {path} is empty")
    return path


async def merge_one(conn: AsyncConnection, client: dict[str, Any], plan: dict[str, Any], refs: list[tuple[str, str]]) -> None:
    """Move one client's records and delete the empty tenant. The caller wraps this in a transaction; any exception rolls everything back, the trigger switch included."""
    src, live = client["id"], client["live_id"]
    await conn.execute(text("SELECT set_config('lock_timeout', '10s', true), set_config('statement_timeout', '60s', true)"))
    await conn.execute(text(f"ALTER TABLE investigation_events DISABLE TRIGGER {EVENTS_TRIGGER}"))
    try:
        for tbl, col in MOVE:
            await conn.execute(
                text(f"UPDATE {tbl} SET {col} = :l WHERE CAST({col} AS text) = :s"), {"l": value_for(tbl, col, live), "s": str(src)}
            )  # noqa: S608 - constants
    finally:
        await conn.execute(text(f"ALTER TABLE investigation_events ENABLE TRIGGER {EVENTS_TRIGGER}"))
    # Rules the live client does not already have are moved; the duplicates go with the tenant.
    await conn.execute(
        text(
            "UPDATE detection_rules s SET tenant_id = :l WHERE s.tenant_id = :s AND NOT EXISTS (SELECT 1 FROM detection_rules x WHERE x.tenant_id = :l AND x.name = s.name)"
        ),
        {"l": live, "s": src},
    )
    await conn.execute(text("UPDATE client_aliases SET child_tenant_id = :l WHERE child_tenant_id = :s"), {"l": live, "s": src})
    await conn.execute(text("DELETE FROM detection_rules WHERE tenant_id = :s"), {"s": src})
    for tbl, col in DROP:
        await conn.execute(text(f"DELETE FROM {tbl} WHERE CAST({col} AS text) = :s"), {"s": str(src)})  # noqa: S608 - constants
    left = await owned(conn, src, refs)
    if left:
        raise RuntimeError(f"rows still belong to the archived client after the move: {left}")
    # The audit log is hash-chained and tamper-proof, so this script does not write to it: the printed report and the backup file are the record of what was done.
    await conn.execute(text("DELETE FROM tenants WHERE id = :s"), {"s": src})


async def trigger_enabled(conn: AsyncConnection) -> bool:
    return (
        await conn.execute(text("SELECT count(*) FROM pg_trigger WHERE tgname = :n AND tgenabled = 'O'"), {"n": EVENTS_TRIGGER})
    ).scalar_one() == 1


async def run(url: str | None, apply: bool, backup_dir: Path, only: str | None) -> int:
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    if url is None:
        from app.db.database import engine as shared  # noqa: PLC0415

        engine = shared
    else:
        engine = create_async_engine(url)
    failures = 0
    async with engine.connect() as conn:
        refs = await references(conn)
        clients = await archived_clients(conn, only)
        print(f"{len(clients)} archived client(s) found. {'APPLYING' if apply else 'DRY RUN: nothing is changed'}.\n")
        for client in clients:
            plan = await plan_for(conn, client, refs)
            moved = ", ".join(f"{n} {t}" for t, n in plan["move"].items()) or "nothing to move"
            print(
                f"- {plan['client']} -> {plan['live'] or '(no live twin)'}: {moved}; rules: {plan['rules']['duplicate']} duplicate dropped, {plan['rules']['move']} moved"
            )
            if plan["problems"]:
                failures += 1
                for p in plan["problems"]:
                    print(f"    REFUSED: {p}")
                continue
            if not apply:
                continue
            try:
                path = await backup(conn, client, backup_dir)
                await conn.rollback()  # end the read transaction before the write one
                async with conn.begin():
                    await merge_one(conn, client, plan, refs)
                print(f"    merged and deleted; backup: {path}")
            except Exception as exc:  # noqa: BLE001 - report and carry on with the next client
                failures += 1
                await conn.rollback()
                print(f"    FAILED, rolled back, left as it was: {' '.join(str(exc).split())[:300]}")
        if apply and not await trigger_enabled(conn):
            print(
                "\nWARNING: the investigation_events immutability trigger is not enabled. Run: ALTER TABLE investigation_events ENABLE TRIGGER trg_inv_events_immutable;"
            )
            failures += 1
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="make the changes (default is a dry run)")
    parser.add_argument("--backup-dir", type=Path, default=Path("backups"), help="where the JSON backup of each client's rows is written")
    parser.add_argument("--only", help="just this client, by name")
    parser.add_argument("--database-url", help="override the API's own database connection (for testing)")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.database_url, args.apply, args.backup_dir, args.only))


if __name__ == "__main__":
    sys.exit(main())
