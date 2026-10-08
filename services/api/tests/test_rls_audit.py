"""The RLS audit tool classifies policies correctly and reports honestly. The policy strings below are the REAL ones Postgres reported from the fully migrated schema (pg_policies.qual), not strings invented to fit.

Background: the audit found that RLS is bypassed entirely in the default deployment (every service connects as the bootstrap superuser), covers only 38 of 79 tenant-scoped tables, and that eight tables had policies that
read a setting nothing sets or that raise an error when no tenant context is set (fixed by migrations 060 and 061). The tool exists so an operator can see the same picture for their OWN database.
"""
import asyncio
import json
import re
from pathlib import Path

import pytest

from app.scripts import rls_audit as ra

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"

STANDARD = "((tenant_id = current_tenant_id()) OR (current_tenant_id() IS NULL))"
HUNT_HYPOTHESES = "((tenant_id = current_tenant_id()) OR (tenant_id IS NULL) OR (current_tenant_id() IS NULL))"
EASM_RAISES = "(tenant_id = (current_setting('app.current_tenant_id'::text))::uuid)"
COMPLIANCE_STRICT = "(tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)"
SHIFTS_COALESCE = "(tenant_id = COALESCE((current_setting('app.current_tenant_id'::text, true))::uuid, '00000000-0000-0000-0000-000000000000'::uuid))"
SLA_007 = "(tenant_id = (current_setting('app.tenant_id'::text, true))::uuid)"
RETENTION_049 = "(tenant_id = (current_setting('app.current_tenant'::text, true))::uuid)"
STRICT_FN = "(tenant_id = current_tenant_id())"


class TestClassification:
    @pytest.mark.parametrize(
        "qual,kind",
        [
            (STANDARD, "standard"),
            (HUNT_HYPOTHESES, "standard"),
            (EASM_RAISES, "raises_without_context"),
            (COMPLIANCE_STRICT, "strict_context"),
            (SHIFTS_COALESCE, "strict_context"),
            (STRICT_FN, "strict_context"),
            (SLA_007, "wrong_setting"),
            (RETENTION_049, "wrong_setting"),
            (None, "other"),
            ("", "other"),
            ("true", "other"),
        ],
    )
    def test_the_real_policy_shapes(self, qual, kind):
        assert ra.classify_policy(qual) == kind

    def test_only_a_missing_ok_flag_separates_a_strict_policy_from_one_that_raises(self):
        assert ra.classify_policy("(x = (current_setting('app.current_tenant_id'::text, true))::uuid)") == "strict_context"
        assert ra.classify_policy("(x = (current_setting('app.current_tenant_id'::text))::uuid)") == "raises_without_context"

    def test_defects_are_exactly_the_two_kinds_that_cannot_work(self):
        assert set(ra.DEFECTS) == {"raises_without_context", "wrong_setting"}


def policies(*rows):
    return [{"tablename": t, "policyname": f"{t}_p", "qual": q, "with_check": None} for t, q in rows]


def report(**over):
    base = dict(
        role=("aisoc", True, False),
        tables=["a", "b", "c", "d", "users", "plain"],
        tenant_tables={"a", "b", "c", "d", "users"},
        rls_enabled={"a", "b", "c"},
        policies=policies(("a", STANDARD), ("b", STANDARD), ("c", STANDARD)),
    )
    base.update(over)
    return ra.build_report(**base)


class TestReport:
    def test_coverage_counts_only_tenant_scoped_tables(self):
        r = report()
        assert r.tables == 6 and r.tenant_scoped == ["a", "b", "c", "d", "users"] and r.covered == ["a", "b", "c"]

    def test_a_table_with_rls_that_is_not_tenant_scoped_does_not_inflate_coverage(self):
        """Coverage is "of the tenant-scoped tables, how many have RLS": a global table that happens to have RLS enabled must not count toward it."""
        r = report(rls_enabled={"a", "b", "c", "plain"}, policies=policies(("a", STANDARD), ("b", STANDARD), ("c", STANDARD), ("plain", STANDARD)))
        assert r.covered == ["a", "b", "c"] and "plain" not in r.tenant_scoped and "(60%)" in ra.render(r)

    def test_an_uncovered_table_is_listed_but_a_deliberately_excluded_one_is_separate(self):
        r = report()
        assert r.uncovered == ["d"] and r.excluded == ["users"]

    def test_a_table_with_rls_on_and_no_policy_is_a_defect(self):
        r = report(rls_enabled={"a", "b", "c", "d"}, policies=policies(("a", STANDARD), ("b", STANDARD), ("c", STANDARD)))
        assert r.no_policy == ["d"] and any(d["table"] == "d" and "no policy" in d["using"] for d in r.defects)

    def test_defective_policies_are_collected(self):
        r = report(policies=policies(("a", STANDARD), ("b", EASM_RAISES), ("c", SLA_007)))
        assert {(d["table"], d["policy"]) for d in r.defects} == {("b", "b_p"), ("c", "c_p")}

    def test_strict_policies_are_noted_not_defects(self):
        r = report(policies=policies(("a", STANDARD), ("b", SHIFTS_COALESCE), ("c", COMPLIANCE_STRICT)))
        assert r.defects == [] and len(r.policies["strict_context"]) == 2

    def test_a_superuser_and_a_bypassrls_role_both_bypass_rls_and_an_ordinary_role_does_not(self):
        assert report(role=("aisoc", True, False)).bypasses_rls and report(role=("svc", False, True)).bypasses_rls
        assert not report(role=("aisoc_app", False, False)).bypasses_rls

    def test_a_policy_that_only_has_a_with_check_is_still_classified(self):
        r = report(policies=[{"tablename": "a", "policyname": "ins", "qual": None, "with_check": EASM_RAISES}])
        assert r.policies["raises_without_context"][0]["table"] == "a"


class TestRendering:
    def test_a_bypassed_role_is_called_out_plainly(self):
        text = ra.render(report(role=("aisoc", True, False)))
        assert "RLS is BYPASSED" in text and "application's own tenant filters" in text and "ENFORCED" not in text

    def test_an_enforced_role_says_so(self):
        text = ra.render(report(role=("aisoc_app", False, False)))
        assert "RLS is ENFORCED" in text and "BYPASSED" not in text

    def test_it_states_the_coverage_percentage_and_lists_the_gaps(self):
        text = ra.render(report())
        assert "RLS is enabled on 3 of them (60%)" in text and "1 tenant-scoped tables have NO RLS" in text and "d" in text and "(deliberately excluded: users)" in text

    def test_defects_are_labelled_and_counted(self):
        text = ra.render(report(policies=policies(("a", STANDARD), ("b", EASM_RAISES), ("c", SLA_007))))
        assert "DEFECT raises_without_context: b.b_p" in text and "DEFECT wrong_setting: c.c_p" in text and text.rstrip().endswith("2 defect(s).")

    def test_no_defects_says_so(self):
        assert ra.render(report()).rstrip().endswith("0 defect(s).")

    def test_an_empty_schema_does_not_divide_by_zero(self):
        assert "0 are tenant-scoped" in ra.render(ra.build_report(role=("x", False, False), tables=[], tenant_tables=set(), rls_enabled=set(), policies=[]))


class TestExitCodes:
    @pytest.mark.parametrize(
        "strict,require,defective,bypassed,expected",
        [
            (False, False, True, True, 0),  # a plain report never fails
            (True, False, True, False, 1),
            (True, False, False, True, 0),  # bypassed is not a policy defect
            (False, True, False, True, 1),
            (False, True, False, False, 0),
            (True, True, False, False, 0),
            (True, True, True, True, 1),
        ],
    )
    def test_matrix(self, strict, require, defective, bypassed, expected):
        r = report(role=("r", bypassed, False), policies=policies(("a", EASM_RAISES if defective else STANDARD), ("b", STANDARD), ("c", STANDARD)))
        assert ra.exit_code(r, strict=strict, require_enforced=require) == expected


class FakeConn:
    def __init__(self, role=("aisoc", True, False), app_role_exists=True, can_truncate=False, tables=("a", "b")):
        self.role, self.sql, self.params = role, [], []
        self.app_role_exists, self.can_truncate, self.tables = app_role_exists, can_truncate, tables

    async def fetchval(self, sql, *params):
        self.sql.append(sql)
        self.params.append(params)
        if "FROM pg_roles" in sql:
            return 1 if self.app_role_exists else None
        if "has_table_privilege" in sql:
            return self.can_truncate
        raise AssertionError(f"unexpected fetchval: {sql}")

    async def fetchrow(self, sql):
        self.sql.append(sql)
        return {"name": self.role[0], "rolsuper": self.role[1], "rolbypassrls": self.role[2]}

    async def fetch(self, sql):
        self.sql.append(sql)
        if "FROM pg_policies" in sql:
            return [{"tablename": "a", "policyname": "p", "qual": STANDARD, "with_check": None}]
        if "information_schema.columns" in sql:
            return [{"table_name": "a"}, {"table_name": "b"}]
        if "relrowsecurity" in sql:
            return [{"relname": "a"}]
        return [{"relname": t} for t in self.tables]

    async def close(self):
        pass


class TestCollectAndMain:
    def test_collect_reads_only_the_catalog_and_never_writes(self):
        conn = FakeConn()
        asyncio.run(ra.collect(conn))
        assert len(conn.sql) == 6  # role, tables, tenant columns, rls, policies, does aisoc_app exist (no audit_log table here, so the TRUNCATE question is not asked)
        for sql in conn.sql:
            s = " ".join(sql.split()).upper()
            assert s.startswith("SELECT") and not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT)\b", s)
            assert not any(t in sql.lower() for t in ("from alerts", "from aisoc_cases", "from users"))  # no tenant data is read, only the catalog

    def test_collect_builds_the_report(self):
        r = asyncio.run(ra.collect(FakeConn()))
        assert r.role == "aisoc" and r.covered == ["a"] and r.uncovered == ["b"]
        assert r.app_role == {"exists": True, "can_truncate_audit_log": None}  # the fake schema has no audit_log table, so it is not asked

    def run_main(self, monkeypatch, capsys, args, conn):
        import app.scripts.run_migrations as rm

        async def connect():
            return conn

        monkeypatch.setattr(rm, "_connect", connect)
        code = asyncio.run(ra.main(args))
        return code, capsys.readouterr().out

    def test_the_default_output_is_the_text_report(self, monkeypatch, capsys):
        code, out = self.run_main(monkeypatch, capsys, [], FakeConn())
        assert code == 0 and "Connected as role 'aisoc'" in out

    def test_json_output_is_valid_and_carries_the_key_facts(self, monkeypatch, capsys):
        code, out = self.run_main(monkeypatch, capsys, ["--json"], FakeConn())
        data = json.loads(out)
        assert code == 0 and data["bypasses_rls"] is True and data["role"] == "aisoc" and data["defects"] == [] and data["covered"] == ["a"]

    def test_require_enforced_fails_for_a_superuser_and_passes_for_aisoc_app(self, monkeypatch, capsys):
        assert self.run_main(monkeypatch, capsys, ["--require-enforced"], FakeConn(("aisoc", True, False)))[0] == 1
        assert self.run_main(monkeypatch, capsys, ["--require-enforced"], FakeConn(("aisoc_app", False, False)))[0] == 0


class TestMigrationsDoNotReintroduceDefectiveShapes:
    """From 062 on, a policy must use the standard current_tenant_id(). Eight earlier tables got a shape that cannot work for the plain session (fixed by 060 and 061); this stops it happening again."""

    def test_new_migrations_use_the_standard_helper(self):
        offenders = []
        for f in sorted(MIGRATIONS.glob("*.sql")):
            if int(f.name.split("_")[0]) < 62:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            if re.search(r"CREATE POLICY[^;]*current_setting\(", text, re.S | re.I):
                offenders.append(f.name)
        assert offenders == [], f"policies must use current_tenant_id(), not current_setting(): {offenders}"

    def test_060_and_061_use_the_standard_shape_for_every_policy_they_create(self):
        for name in ("060_unify_rls_setting_name.sql", "061_unify_rls_plain_session_tables.sql"):
            text = (MIGRATIONS / name).read_text(encoding="utf-8", errors="replace")
            created = re.findall(r"CREATE POLICY (\w+) ON (\w+)\s+USING \((.*?)\);", text, re.S)
            assert len(created) == 4, name
            assert all(ra.classify_policy(" ".join(q.split())) == "standard" for _, _, q in created), name


class TestTheAppRoleChecks:
    """`aisoc_app` (migration 002) was granted ALL on every table, which includes TRUNCATE: TRUNCATE ignores RLS and row triggers, so it could erase the append-only audit_log (verified on a real database; fixed by 062)."""

    def test_the_truncate_question_is_asked_only_when_the_role_and_the_table_exist(self):
        asked = lambda conn: any("has_table_privilege" in q for q in conn.sql)  # noqa: E731
        with_log = FakeConn(tables=("a", "audit_log"))
        asyncio.run(ra.collect(with_log))
        assert asked(with_log)
        no_role, no_table = FakeConn(tables=("a", "audit_log"), app_role_exists=False), FakeConn()
        asyncio.run(ra.collect(no_role))
        asyncio.run(ra.collect(no_table))
        assert not asked(no_role) and not asked(no_table)

    def test_the_role_name_is_a_bound_parameter_and_the_queries_only_read(self):
        conn = FakeConn(tables=("audit_log",))
        asyncio.run(ra.collect(conn))
        assert ("aisoc_app",) in conn.params and all(" ".join(q.split()).upper().startswith("SELECT") for q in conn.sql)

    def test_a_role_that_can_truncate_the_audit_log_is_a_defect(self):
        r = asyncio.run(ra.collect(FakeConn(tables=("audit_log",), can_truncate=True)))
        assert r.app_role == {"exists": True, "can_truncate_audit_log": True}
        assert any(d["table"] == "audit_log" and "TRUNCATE" in d["using"] and "062" in d["using"] for d in r.defects)
        assert ra.exit_code(r, strict=True, require_enforced=False) == 1

    def test_a_role_that_cannot_is_not(self):
        r = asyncio.run(ra.collect(FakeConn(tables=("audit_log",), can_truncate=False)))
        assert r.defects == [] and "can TRUNCATE audit_log: no" in ra.render(r)

    def test_an_unknown_answer_is_reported_as_unknown_not_as_safe(self):
        assert "can TRUNCATE audit_log: unknown" in ra.render(asyncio.run(ra.collect(FakeConn())))

    def test_the_truncate_defect_is_named_in_the_rendered_report(self):
        text = ra.render(asyncio.run(ra.collect(FakeConn(tables=("audit_log",), can_truncate=True))))
        assert "can TRUNCATE audit_log: YES (DEFECT: apply migration 062)" in text and "1 defect(s)." in text


class TestCredentialSubstitution:
    def test_only_the_credentials_change(self):
        out = ra.with_credentials("postgresql://aisoc:s3cret@db.internal:5433/aisoc?sslmode=require", "aisoc_app", "changeme")
        assert out == "postgresql://aisoc_app:changeme@db.internal:5433/aisoc?sslmode=require" and "s3cret" not in out

    def test_special_characters_are_percent_encoded(self):
        assert ra.with_credentials("postgresql://u:p@h/db", "aisoc_app", "a@b/c:d#e?f").split("@")[0] == "postgresql://aisoc_app:a%40b%2Fc%3Ad%23e%3Ff"

    def test_a_dsn_without_credentials_gets_them(self):
        assert ra.with_credentials("postgresql://h:5432/db", "x", "y") == "postgresql://x:y@h:5432/db"

    def test_an_at_sign_in_the_original_password_does_not_confuse_the_host(self):
        assert ra.with_credentials("postgresql://u:p%40ss@host:5432/db", "x", "y") == "postgresql://x:y@host:5432/db"


class TestTheDefaultPasswordProbe:
    """It is an AUTHENTICATION ATTEMPT, so it must never run unless asked for."""

    def run(self, connect, kwargs=None):
        return asyncio.run(ra.default_password_accepted("postgresql://aisoc:real@h:5432/db", kwargs or {}, connect=connect))

    def test_accepted_means_true_and_the_connection_is_closed(self):
        closed = []

        class Conn:
            async def close(self_):
                closed.append(1)

        async def connect(dsn, **kw):
            assert dsn == "postgresql://aisoc_app:changeme@h:5432/db"
            return Conn()

        assert self.run(connect) is True and closed == [1]

    def test_a_refused_password_means_false(self):
        import asyncpg

        async def connect(dsn, **kw):
            raise asyncpg.exceptions.InvalidPasswordError("nope")

        assert self.run(connect) is False

    def test_anything_else_means_could_not_tell_not_safe(self):
        async def connect(dsn, **kw):
            raise OSError("unreachable")

        assert self.run(connect) is None

    def test_connection_options_are_passed_through(self):
        seen = {}

        async def connect(dsn, **kw):
            seen.update(kw)
            raise OSError

        self.run(connect, {"ssl": "require"})
        assert seen.get("ssl") == "require" and seen.get("timeout") == 10

    def test_an_accepted_published_password_is_a_defect_and_fails_strict(self):
        r = report()
        r.app_role = {"exists": True, "can_truncate_audit_log": False, "default_password_accepted": True}
        assert any("published in the repository" in d["using"] for d in r.defects) and ra.exit_code(r, strict=True, require_enforced=False) == 1
        assert "accepts the published password: YES (DEFECT: set a real password)" in ra.render(r)

    @pytest.mark.parametrize("value,wording", [(False, "accepts the published password: no"), (None, "accepts the published password: could not tell")])
    def test_refused_or_unknown_is_not_a_defect(self, value, wording):
        r = report()
        r.app_role = {"exists": True, "can_truncate_audit_log": False, "default_password_accepted": value}
        assert r.defects == [] and wording in ra.render(r)

    def test_not_checked_says_how_to_check(self):
        r = report()
        r.app_role = {"exists": True, "can_truncate_audit_log": False}
        assert "not checked (use --check-default-password)" in ra.render(r)


class TestTheFlag:
    def run_main(self, monkeypatch, capsys, args, conn, probe):
        import app.scripts.run_migrations as rm

        async def connect():
            return conn

        monkeypatch.setattr(rm, "_connect", connect)
        monkeypatch.setattr(ra, "default_password_accepted", probe)
        code = asyncio.run(ra.main(args))
        return code, capsys.readouterr().out

    def test_without_the_flag_no_login_is_ever_attempted(self, monkeypatch, capsys):
        async def probe(*a, **k):
            raise AssertionError("an authentication attempt was made without --check-default-password")

        code, out = self.run_main(monkeypatch, capsys, ["--strict"], FakeConn(), probe)
        assert code == 0 and "not checked" in out

    def test_with_the_flag_and_an_accepting_role_it_is_reported_and_fails_strict(self, monkeypatch, capsys):
        async def probe(dsn, kwargs, connect=None):
            return True

        code, out = self.run_main(monkeypatch, capsys, ["--check-default-password", "--strict"], FakeConn(), probe)
        assert code == 1 and "accepts the published password: YES" in out

    def test_with_the_flag_and_a_refusing_role_it_passes(self, monkeypatch, capsys):
        async def probe(dsn, kwargs, connect=None):
            return False

        code, out = self.run_main(monkeypatch, capsys, ["--check-default-password", "--strict"], FakeConn(), probe)
        assert code == 0 and "accepts the published password: no" in out

    def test_with_the_flag_but_no_such_role_nothing_is_attempted(self, monkeypatch, capsys):
        async def probe(*a, **k):
            raise AssertionError("probed a role that does not exist")

        code, out = self.run_main(monkeypatch, capsys, ["--check-default-password"], FakeConn(app_role_exists=False), probe)
        assert code == 0 and "Role aisoc_app" not in out

    def test_json_carries_the_role_facts(self, monkeypatch, capsys):
        async def probe(dsn, kwargs, connect=None):
            return False

        code, out = self.run_main(monkeypatch, capsys, ["--json", "--check-default-password"], FakeConn(), probe)
        assert json.loads(out)["app_role"] == {"exists": True, "can_truncate_audit_log": None, "default_password_accepted": False}
