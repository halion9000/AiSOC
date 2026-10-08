"""Report whether row-level security (RLS) actually protects this database, and where it does not.

READ-ONLY: it only queries the catalog (pg_roles, pg_class, pg_policies, information_schema). It changes nothing and reads no tenant data.

    python -m app.scripts.rls_audit                  # human-readable report
    python -m app.scripts.rls_audit --json           # machine-readable
    python -m app.scripts.rls_audit --strict         # exit 1 if any policy is DEFECTIVE (see below)
    python -m app.scripts.rls_audit --require-enforced   # also exit 1 if the connected role bypasses RLS

It answers four questions:
  1. Does RLS apply to the role this connection uses at all? (A PostgreSQL superuser, or a role with BYPASSRLS, ignores every policy. The default compose connects as the bootstrap superuser.)
  2. Of the tenant-scoped tables (those with a tenant_id column), how many have RLS enabled?
  3. Is any table's RLS on with NO policy (default-deny for a non-owner role)?
  4. Is any policy DEFECTIVE: it reads a setting nothing sets, or it raises an error when no tenant context has been set?

Policy kinds:
  standard                a tenant context restricts to that tenant; NO context admits the row (the endpoints filter by tenant themselves). The shape used by almost every table.
  strict_context          works only if the code sets a tenant context first; with none, the table looks empty and writes are refused. Fine for code that always sets one, a bug for code that does not.
  raises_without_context  calls current_setting('app.current_tenant_id') WITHOUT the missing-ok flag: EVERY query raises until something has set it on that connection. A defect.
  wrong_setting           reads a setting other than app.current_tenant_id, which nothing sets. A defect.
  other                   anything else (review by hand).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

STANDARD_SETTING = "app.current_tenant_id"
# The tables RLS deliberately does not cover (migration 002: authentication would be circular).
INTENTIONALLY_UNCOVERED = frozenset({"users", "tenants", "aisoc_schema_migrations"})
DEFECTS = ("raises_without_context", "wrong_setting")
_SETTING = re.compile(r"current_setting\('([^']+)'::text(?:,\s*(true|false))?\)")


def classify_policy(qual: str | None) -> str:
    """Name the shape of a policy's USING expression (see the module docstring)."""
    q = qual or ""
    if "current_tenant_id()" in q:
        return "standard" if "IS NULL" in q else "strict_context"
    m = _SETTING.search(q)
    if m:
        name, missing_ok = m.group(1), m.group(2) == "true"
        if name != STANDARD_SETTING:
            return "wrong_setting"
        return "strict_context" if missing_ok else "raises_without_context"
    return "other"


@dataclass
class Report:
    role: str = ""
    superuser: bool = False
    bypassrls: bool = False
    tables: int = 0
    tenant_scoped: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)  # tenant-scoped, RLS off, not intentionally excluded
    excluded: list[str] = field(default_factory=list)  # tenant-scoped, RLS off, deliberately
    no_policy: list[str] = field(default_factory=list)  # RLS on, zero policies
    policies: dict[str, list[dict[str, str]]] = field(default_factory=dict)  # kind -> [{table, policy, using}]

    @property
    def bypasses_rls(self) -> bool:
        return self.superuser or self.bypassrls

    @property
    def defects(self) -> list[dict[str, str]]:
        return [p for kind in DEFECTS for p in self.policies.get(kind, [])] + [{"table": t, "policy": "(none)", "using": "RLS enabled but no policy: invisible and unwritable for a non-owner role"} for t in self.no_policy]


def build_report(*, role: tuple[str, bool, bool], tables: list[str], tenant_tables: set[str], rls_enabled: set[str], policies: list[dict[str, Any]]) -> Report:
    r = Report(role=role[0], superuser=role[1], bypassrls=role[2], tables=len(tables))
    r.tenant_scoped = sorted(t for t in tables if t in tenant_tables)
    r.covered = [t for t in r.tenant_scoped if t in rls_enabled]
    off = [t for t in r.tenant_scoped if t not in rls_enabled]
    r.excluded = [t for t in off if t in INTENTIONALLY_UNCOVERED]
    r.uncovered = [t for t in off if t not in INTENTIONALLY_UNCOVERED]
    with_policy = {p["tablename"] for p in policies}
    r.no_policy = sorted(t for t in tables if t in rls_enabled and t not in with_policy)
    for p in policies:
        kind = classify_policy(p.get("qual") or p.get("with_check"))
        r.policies.setdefault(kind, []).append({"table": p["tablename"], "policy": p["policyname"], "using": (p.get("qual") or p.get("with_check") or "")[:110]})
    return r


def render(r: Report) -> str:
    out = [f"Connected as role '{r.role}': superuser={r.superuser} bypassrls={r.bypassrls}"]
    out.append("  RLS is BYPASSED for this role: tenant isolation rests entirely on the application's own tenant filters." if r.bypasses_rls else "  RLS is ENFORCED for this role.")
    total = len(r.tenant_scoped)
    pct = round(100 * len(r.covered) / total) if total else 0
    out += ["", f"{r.tables} tables; {total} are tenant-scoped (have a tenant_id column); RLS is enabled on {len(r.covered)} of them ({pct}%)."]
    if r.uncovered:
        out.append(f"{len(r.uncovered)} tenant-scoped tables have NO RLS (isolation there is application filters only, whatever the role):")
        out += [f"  {', '.join(r.uncovered[i:i + 4])}" for i in range(0, len(r.uncovered), 4)]
    if r.excluded:
        out.append(f"(deliberately excluded: {', '.join(r.excluded)})")
    counts = ", ".join(f"{k}={len(v)}" for k, v in sorted(r.policies.items()))
    out += ["", f"Policies by shape: {counts or 'none'}"]
    for kind in ("raises_without_context", "wrong_setting", "other", "strict_context"):
        for p in r.policies.get(kind, []):
            tag = "DEFECT" if kind in DEFECTS else "note  "
            out.append(f"  {tag} {kind}: {p['table']}.{p['policy']}: {p['using']}")
    for t in r.no_policy:
        out.append(f"  DEFECT no_policy: {t}: RLS enabled but no policy")
    out += ["", f"{len(r.defects)} defect(s)."]
    return "\n".join(out)


async def collect(conn: Any) -> Report:
    me = await conn.fetchrow("SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
    tables = [x["relname"] for x in await conn.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1")]
    tenant_tables = {x["table_name"] for x in await conn.fetch("SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'tenant_id'")}
    rls = {x["relname"] for x in await conn.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity")}
    pols = [dict(x) for x in await conn.fetch("SELECT tablename, policyname, qual, with_check FROM pg_policies WHERE schemaname = 'public'")]
    return build_report(role=(me["name"], me["rolsuper"], me["rolbypassrls"]), tables=tables, tenant_tables=tenant_tables, rls_enabled=rls, policies=pols)


def exit_code(r: Report, *, strict: bool, require_enforced: bool) -> int:
    return 1 if (strict and r.defects) or (require_enforced and r.bypasses_rls) else 0


async def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Report where row-level security does and does not protect this database (read-only).")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any policy is defective")
    ap.add_argument("--require-enforced", action="store_true", help="exit 1 if the connected role bypasses RLS")
    args = ap.parse_args(argv)
    from app.scripts.run_migrations import _connect  # noqa: PLC0415  (the same DATABASE_URL handling as the migration runner)

    conn = await _connect()
    try:
        report = await collect(conn)
    finally:
        await conn.close()
    print(json.dumps({**asdict(report), "bypasses_rls": report.bypasses_rls, "defects": report.defects}, indent=2) if args.json else render(report))
    return exit_code(report, strict=args.strict, require_enforced=args.require_enforced)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
