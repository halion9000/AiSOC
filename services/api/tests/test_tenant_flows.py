"""The two-tenant flow tool: its payload generator, its flow definitions (guarded against drift from the real API), its comparison, and its safety refusals.

It exists because RLS only protects a NON-superuser connection and the default deployment is a superuser one: the shifts module relied on RLS alone, so any tenant could list, close and overwrite every other tenant's shifts and read their open
alerts, and attaching alerts to a case never checked ownership. A read-only sweep and a row-count comparison could not see either. The flows themselves need a live database (they were run against real Postgres as the superuser and as the
non-superuser, and shown to fail on the original unfixed code); these tests pin everything that does not.
"""
import json
import re
import uuid

import pytest

from app.scripts import tenant_flows as tf

SPEC = {
    "components": {
        "schemas": {
            "Req": {"type": "object", "required": ["title", "mail", "when", "ref", "level", "count", "flag", "tags", "inner"], "properties": {
                "title": {"type": "string", "minLength": 20, "maxLength": 25},
                "mail": {"type": "string", "format": "email"},
                "when": {"type": "string", "format": "date-time"},
                "ref": {"type": "string", "format": "uuid"},
                "level": {"enum": ["low", "high"]},
                "count": {"type": "integer", "minimum": 5},
                "flag": {"type": "boolean"},
                "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "inner": {"$ref": "#/components/schemas/Inner"},
                "optional": {"type": "string"},
            }},
            "Inner": {"allOf": [{"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}}, {"type": "object", "required": ["b"], "properties": {"b": {"anyOf": [{"type": "null"}, {"type": "boolean"}]}}}]},
        }
    },
    "paths": {
        "/api/v1/things": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Req"}}}}}},
        "/api/v1/things/{thing_id}/notes": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Req"}}}}}, "get": {}},
    },
}


class TestThePayloadGenerator:
    def body(self, **over):
        return tf.body_for(SPEC, "/api/v1/things", "post", **over)

    def test_every_required_field_gets_a_valid_value_of_its_kind(self):
        b = self.body()
        assert re.fullmatch(r"[\w-]{20,25}", b["title"]) and b["mail"] == "user@example.com" and b["when"] == "2026-01-01T00:00:00Z"
        assert uuid.UUID(b["ref"]) and b["level"] == "low" and b["count"] == 5 and b["flag"] is False and len(b["tags"]) == 1
        assert b["inner"] == {"a": 1, "b": False}

    def test_optional_fields_are_left_out(self):
        assert "optional" not in self.body()

    def test_it_is_deterministic_so_two_runs_send_identical_requests(self):
        assert self.body() == self.body() and json.dumps(self.body(), sort_keys=True) == json.dumps(self.body(), sort_keys=True)

    def test_overrides_win(self):
        assert self.body(title="mine", extra=1)["title"] == "mine" and self.body(extra=1)["extra"] == 1

    def test_different_endpoints_get_different_uuids(self):
        a = tf.body_for(SPEC, "/api/v1/things", "post")["ref"]
        b = tf.body_for(SPEC, "/api/v1/things/{x}/notes", "post")["ref"]
        assert a != b

    def test_a_cycle_does_not_recurse_for_ever(self):
        spec = {"components": {"schemas": {"N": {"type": "object", "required": ["n"], "properties": {"n": {"$ref": "#/components/schemas/N"}}}}}}
        assert tf.gen(spec, {"$ref": "#/components/schemas/N"}, "s") is not None


class TestFindSpec:
    def test_my_parameter_names_match_the_specs(self):
        assert tf.find_spec(SPEC, "/api/v1/things/{thing}/notes") == "/api/v1/things/{thing_id}/notes"

    def test_an_unknown_path_raises(self):
        with pytest.raises(KeyError):
            tf.find_spec(SPEC, "/api/v1/nothing/{x}")

    def test_a_template_of_the_wrong_shape_does_not_match(self):
        with pytest.raises(KeyError):
            tf.find_spec(SPEC, "/api/v1/things/{a}/{b}/notes")


class TestCompare:
    def row(self, step, status=200, ok=True, flow="f", user="A", detail=""):
        return [flow, step, user, status, ok, detail]

    def test_identical_runs_differ_in_nothing(self):
        run = [self.row("s1"), self.row("s2")]
        assert not any(tf.compare_runs(run, run).values())

    def test_a_changed_status_is_reported(self):
        d = tf.compare_runs([self.row("s", 404)], [self.row("s", 200)])
        assert d["status"] == [("s", 404, 200)]

    def test_a_changed_outcome_is_reported_even_with_the_same_status(self):
        d = tf.compare_runs([self.row("s", 200, True)], [self.row("s", 200, False)])
        assert d["outcome"] == [("s", True, False)] and d["status"] == []

    def test_steps_present_in_only_one_run_are_reported(self):
        d = tf.compare_runs([self.row("a"), self.row("b")], [self.row("a"), self.row("c")])
        assert d["only_in_first"] == ["b"] and d["only_in_second"] == ["c"]

    def test_leaks_found_in_only_one_run_are_reported_per_endpoint(self):
        sweep = lambda leaks: ["SWEEP", "x", "B", 200, not leaks, f"LEAKS: {leaks}" if leaks else ""]  # noqa: E731
        d = tf.compare_runs([sweep([["/api/v1/shifts", "f_shift", 200], ["/api/v1/audit", "f_case", 200]])], [sweep([["/api/v1/audit", "f_case", 200]])])
        assert d["leaks_only_in_first"] == ["/api/v1/shifts"] and d["leaks_only_in_second"] == []

    def test_the_sweep_row_is_not_double_counted_as_an_outcome_difference(self):
        a, b = ["SWEEP", "x", "B", 200, True, ""], ["SWEEP", "x", "B", 200, False, "LEAKS: [['/api/v1/x', 'k', 200]]"]
        assert tf.compare_runs([a], [b])["outcome"] == []


class TestTheFlowDefinitionsMatchTheRealApi:
    """Drift guard: if an endpoint is renamed or removed, the flow that used it would silently stop testing it."""

    @pytest.fixture(scope="class")
    def real_spec(self):
        from app.main import app

        return app.openapi()

    def test_every_step_targets_a_real_endpoint(self, real_spec):
        missing = []
        for flow, steps in tf.build_flows().items():
            for st in steps:
                try:
                    path = tf.find_spec(real_spec, st.tpl)
                except KeyError:
                    missing.append((flow, st.name, st.tpl))
                    continue
                if st.method not in real_spec["paths"][path]:
                    missing.append((flow, st.name, f"{st.method} {path}"))
        assert missing == [], f"steps whose endpoint no longer exists: {missing}"

    def test_every_path_parameter_is_produced_by_an_earlier_step_of_the_same_flow(self):
        for flow, steps in tf.build_flows().items():
            have: set[str] = set(tf.FLOW_SEEDS.get(flow, {}))
            for st in steps:
                for name in re.findall(r"\{(\w+)\}", st.tpl):
                    assert name in have, f"{flow}: '{st.name}' needs {{{name}}} before any step captures it"
                if st.capture:
                    have.add(st.capture[0])

    def test_seeds_belong_to_real_flows_and_are_plain_strings(self):
        flows = tf.build_flows()
        for flow, seeds in tf.FLOW_SEEDS.items():
            assert flow in flows, f"seed for a flow that does not exist: {flow}"
            assert all(isinstance(k, str) and isinstance(v() if callable(v) else v, str) and (v() if callable(v) else v) for k, v in seeds.items())

    def test_every_token_in_a_body_or_query_names_something_an_earlier_step_captured(self):
        """`{name}` in `over` / `params` is replaced by what an earlier step captured; a name nothing captured would make the step skip silently."""
        for flow, steps in tf.build_flows().items():
            have: set[str] = set(tf.FLOW_SEEDS.get(flow, {}))
            for st in steps:
                for name in tf.template_names(st.over) | tf.template_names(st.params or {}):
                    assert name in have, f"{flow}: '{st.name}' refers to {{{name}}} before any step captures it"
                if st.capture:
                    have.add(st.capture[0])

    def test_step_names_are_unique_within_a_flow(self):
        for flow, steps in tf.build_flows().items():
            names = [s.name for s in steps]
            assert len(names) == len(set(names)), flow

    def test_the_fresh_flow_is_only_tenant_A_creating_things_and_it_is_last(self):
        flows = tf.build_flows()
        assert list(flows)[-1] == "fresh"
        assert all(s.user == "A" and s.method == "post" and s.capture for s in flows["fresh"])

    def test_the_sweep_only_looks_for_ids_B_never_mentioned(self):
        """Only the FRESH flow's ids are searched for: B's own probes put A's ids in the audit log and cost dashboard, which an earlier version reported as leaks."""
        import inspect

        src = inspect.getsource(tf.run_flows)
        assert 'if st.user == "A" and flow == "fresh":' in src and src.count("fresh_ids[") == 1

    def test_every_isolation_step_is_a_tenant_B_step_and_never_a_create(self):
        for flow, steps in tf.build_flows().items():
            for st in steps:
                if st.expect == tf.ISO:
                    assert st.user == "B", (flow, st.name)

    def test_both_tenants_do_something_in_the_flows_that_need_it(self):
        users = {s.user for steps in tf.build_flows().values() for s in steps}
        assert users == {"A", "B"}


class TestSummary:
    def test_it_counts_and_lists_only_the_failures(self):
        rows = [["f", "ok step", "A", 200, True, ""], ["f", "bad step", "B", 200, False, "body here"]]
        text = tf.summarize("lbl", rows)
        assert "[lbl] 2 steps; as expected: 1; NOT as expected: 1" in text and "bad step" in text and "ok step" not in text


class TestSafetyRefusals:
    def run(self, monkeypatch, capsys, argv, env=None, environment="test"):
        from app.core.config import settings

        monkeypatch.setattr(settings, "ENVIRONMENT", environment)
        monkeypatch.delenv("TENANT_FLOWS_PASSWORD", raising=False)
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)
        called = []
        monkeypatch.setattr(tf, "run_flows", lambda *a, **k: called.append(1))
        code = tf.main(argv)
        return code, capsys.readouterr().err, called

    def test_it_refuses_without_the_explicit_flag_because_it_creates_data(self, monkeypatch, capsys):
        code, err, called = self.run(monkeypatch, capsys, ["run", "--label", "x"], {"TENANT_FLOWS_PASSWORD": "p"})
        assert code == 2 and "CREATE data" in err and called == []

    def test_it_refuses_in_production_even_with_the_flag(self, monkeypatch, capsys):
        code, err, called = self.run(monkeypatch, capsys, ["run", "--label", "x", "--yes-write-test-data"], {"TENANT_FLOWS_PASSWORD": "p"}, environment="production")
        assert code == 2 and "production" in err and called == []

    @pytest.mark.parametrize("env_value", ["Production", " production ", "PRODUCTION"])
    def test_the_production_check_ignores_case_and_whitespace(self, monkeypatch, capsys, env_value):
        code, _, called = self.run(monkeypatch, capsys, ["run", "--label", "x", "--yes-write-test-data"], {"TENANT_FLOWS_PASSWORD": "p"}, environment=env_value)
        assert code == 2 and called == []

    def test_it_refuses_without_the_password(self, monkeypatch, capsys):
        code, err, called = self.run(monkeypatch, capsys, ["run", "--label", "x", "--yes-write-test-data"])
        assert code == 2 and "TENANT_FLOWS_PASSWORD" in err and called == []

    def test_it_runs_when_everything_is_in_order_and_writes_the_results(self, monkeypatch, capsys, tmp_path):
        from app.core.config import settings

        monkeypatch.setattr(settings, "ENVIRONMENT", "test")
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "p")
        seen = {}

        async def fake(emails, password):
            seen.update(emails=emails, password=password)
            return [["f", "s", "A", 200, True, ""]]

        monkeypatch.setattr(tf, "run_flows", fake)
        out = tmp_path / "r.json"
        assert tf.main(["run", "--label", "ok", "--out", str(out), "--yes-write-test-data"]) == 0
        assert seen == {"emails": ("admin-a@example.com", "admin-b@example.com"), "password": "p"} and json.loads(out.read_text()) == [["f", "s", "A", 200, True, ""]]
        assert "[ok] 1 steps; as expected: 1" in capsys.readouterr().out

    def test_a_failing_step_makes_it_exit_1(self, monkeypatch, tmp_path):
        from app.core.config import settings

        monkeypatch.setattr(settings, "ENVIRONMENT", "test")
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "p")

        async def fake(emails, password):
            return [["f", "s", "B", 200, False, "leaked"]]

        monkeypatch.setattr(tf, "run_flows", fake)
        assert tf.main(["run", "--label", "bad", "--out", str(tmp_path / "r.json"), "--yes-write-test-data"]) == 1


class TestCompareCommand:
    def write(self, tmp_path, name, rows):
        p = tmp_path / name
        p.write_text(json.dumps(rows))
        return str(p)

    def test_identical_files_exit_0(self, tmp_path, capsys):
        f = self.write(tmp_path, "a.json", [["f", "s", "A", 200, True, ""]])
        assert tf.main(["compare", f, f]) == 0 and "status: none" in capsys.readouterr().out

    def test_different_files_exit_1_and_say_what_differs(self, tmp_path, capsys):
        a = self.write(tmp_path, "a.json", [["f", "s", "A", 404, True, ""]])
        b = self.write(tmp_path, "b.json", [["f", "s", "A", 200, False, "x"]])
        assert tf.main(["compare", a, b]) == 1
        assert "('s', 404, 200)" in capsys.readouterr().out


def test_the_password_variable_the_docs_name_is_the_one_the_cli_reads():
    doc_names = set(re.findall(r"\b(TENANT_FLOWS_[A-Z_]+)=", tf.__doc__))
    default = re.search(r'"--password-env", default="(\w+)"', open(tf.__file__, encoding="utf-8").read()).group(1)
    assert doc_names == {default}


# --- exclusion steps carry an automatic positive control -------------------------------------------------------------------------------------------------------------------------------------------------------------------
# "B's list excludes A's object" passes whenever the object is absent, including when the list is empty for an unrelated reason (a pagination default, a filter, an error answering []). 16 of the 23 such steps had no step showing the OWNER finding the object on that path.
# `absent="key"` makes the runner issue the same GET as the owner first and require it to find the object (a "control" row); shown on real Postgres: with the IOC list endpoint returning [] for everyone, the control row failed ("the owner cannot see it either, so this exclusion
# proves nothing") while the exclusion step itself still passed.
from types import SimpleNamespace as _NS  # noqa: E402

from app.scripts import tenant_flows as _tf  # noqa: E402


def _resp(status: int, text: str = "") -> _NS:
    return _NS(status_code=status, text=text)


class TestTheControl:
    def test_the_owner_finding_it_is_a_pass(self):
        assert _tf.control_found(_resp(200, '{"items": ["abc-123"]}'), "abc-123")

    @pytest.mark.parametrize("resp", [_resp(200, "[]"), _resp(200, '{"items": ["other"]}'), _resp(404, "abc-123"), _resp(403, "abc-123"), _resp(500, "abc-123"), _resp(200, "")])
    def test_anything_else_means_the_exclusion_proves_nothing(self, resp):
        assert not _tf.control_found(resp, "abc-123")


class TestTheExclusion:
    EXPECT = (200,)
    EXPECT_REFUSAL_OK = (404, 403, 200)

    def test_served_without_the_object_is_a_pass(self):
        assert _tf.exclusion_holds(_resp(200, "[]"), "abc-123", self.EXPECT)

    def test_served_with_the_object_is_a_leak(self):
        assert not _tf.exclusion_holds(_resp(200, '["abc-123"]'), "abc-123", self.EXPECT)

    @pytest.mark.parametrize("status", [404, 403])
    def test_a_refusal_is_a_pass_where_a_refusal_is_expected(self, status):
        assert _tf.exclusion_holds(_resp(status, "abc-123 not found"), "abc-123", self.EXPECT_REFUSAL_OK)

    def test_a_status_that_is_not_expected_is_a_failure_even_without_the_object(self):
        assert not _tf.exclusion_holds(_resp(500, "boom"), "abc-123", self.EXPECT)
        assert not _tf.exclusion_holds(_resp(404, ""), "abc-123", self.EXPECT)

    def test_a_refusal_that_echoes_the_object_is_still_a_pass_because_only_a_served_200_is_inspected(self):
        """A 404 body naming the requested id is normal; what must never happen is a 200 that contains it."""
        assert _tf.exclusion_holds(_resp(404, "alert abc-123 not found"), "abc-123", self.EXPECT_REFUSAL_OK)
        assert not _tf.exclusion_holds(_resp(200, "alert abc-123 found"), "abc-123", self.EXPECT_REFUSAL_OK)


class TestTheToolEnforcesTheConvention:
    steps = [(flow, st) for flow, ss in _tf.build_flows().items() for st in ss]

    def test_there_are_exclusion_steps_and_they_are_a_substantial_share_of_the_tool(self):
        assert len([1 for _, st in self.steps if st.absent]) >= 20

    def test_no_second_tenant_read_asserts_absence_with_a_bare_check(self):
        """A hand-written `not _has(...)` check has no control. Use absent=."""
        import inspect

        offenders = []
        for flow, st in self.steps:
            if st.user == "B" and st.method == "get" and st.check is not None:
                code = inspect.getsource(st.check)
                if "not _has(" in code or "nothave" in code or "status_code != 200 or" in code:
                    offenders.append(f"{flow}: {st.name}")
        assert offenders == [], "use absent= (it adds the owner's positive control automatically):\n" + "\n".join(offenders)

    def test_an_absent_step_is_a_get(self):
        assert [f"{f}: {st.name}" for f, st in self.steps if st.absent and st.method != "get"] == []

    def test_every_absent_key_is_captured_by_an_earlier_step_of_its_flow(self):
        problems = []
        for flow, ss in _tf.build_flows().items():
            captured: set[str] = set()
            for st in ss:
                if st.absent and st.absent not in captured:
                    problems.append(f"{flow}: {st.name} needs '{st.absent}' before it is captured")
                if st.capture:
                    captured.add(st.capture[0])
        assert problems == []

    def test_the_absent_object_is_not_captured_by_the_same_user_that_must_not_see_it(self):
        """The object under test must belong to the OTHER tenant: capture by A, exclusion read by B."""
        owner_of: dict[tuple[str, str], str] = {}
        bad = []
        for flow, ss in _tf.build_flows().items():
            for st in ss:
                if st.capture and flow != "fresh":
                    owner_of[(flow, st.capture[0])] = st.user
                if st.absent and owner_of.get((flow, st.absent)) == st.user:
                    bad.append(f"{flow}: {st.name}")
        assert bad == []

    def test_the_runner_issues_the_control_and_judges_the_exclusion(self):
        import inspect

        src = inspect.getsource(_tf.run_flows)
        assert "st.absent" in src and "control_found(" in src and "exclusion_holds(" in src and "[control: the owner finds it]" in src


class TestTemplatingInBodiesAndQueries:
    CTX = {"a": "1", "b": "two"}

    def test_an_exact_token_is_replaced_in_a_body_a_nested_body_and_a_list(self):
        assert tf._fill({"x": "{a}", "n": {"y": "{b}"}, "l": ["{a}", "keep"]}, self.CTX) == {"x": "1", "n": {"y": "two"}, "l": ["1", "keep"]}

    @pytest.mark.parametrize("text", ["prefix {a}", "{a} suffix", "{a}{b}", "{ a }", "{a-b}", "id: x\nwhen:\n  value: {a}", "", "{}"])
    def test_text_that_merely_contains_braces_is_left_alone(self, text):
        assert tf._fill(text, self.CTX) == text

    def test_non_strings_pass_through_untouched(self):
        assert tf._fill({"n": 3, "f": 1.5, "t": True, "z": None}, self.CTX) == {"n": 3, "f": 1.5, "t": True, "z": None}

    def test_a_name_nothing_captured_is_a_key_error_so_the_step_is_skipped_not_sent_with_a_literal_token(self):
        with pytest.raises(KeyError):
            tf._fill({"x": "{missing}"}, self.CTX)

    def test_the_names_a_body_refers_to_are_found_at_any_depth(self):
        assert tf.template_names({"x": "{a}", "n": {"y": ["{b}", "no"]}, "p": "plain {c}"}) == {"a", "b"}
        assert tf.template_names({}) == set() and tf.template_names([]) == set() and tf.template_names("{a}") == {"a"}

    def test_the_original_step_is_never_modified(self):
        step = tf.S("x", "A", "post", "/api/v1/x", over={"k": "{a}"})
        tf._fill(step.over, self.CTX)
        assert step.over == {"k": "{a}"}

    def test_the_runner_fills_the_body_and_the_query_and_skips_when_a_name_is_missing(self):
        import inspect

        src = inspect.getsource(tf.run_flows)
        assert "_fill(st.over, ctx)" in src and "_fill(st.params, ctx)" in src and "over = dict(st_over)" in src and 'kw["params"] = st_params' in src

