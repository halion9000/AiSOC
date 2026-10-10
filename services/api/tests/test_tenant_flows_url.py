"""The isolation flows against a DEPLOYED API over HTTP (`tenant_flows run-url`).

It writes test data into real environments, so every guard runs before any request; the setup is checked (two different tenants, two plain tenant admins who can do what the flows do) before anything is written; rate limiting (429) is waited out instead of reported as a leak; and the flows use the REAL ids of the two tenants instead of the ones in the scratch database."""
import json

import pytest

from app.core.security import known_permissions
from app.scripts import tenant_flows as tf


@pytest.fixture(autouse=True)
def _module_state_is_the_same_for_every_test(monkeypatch):
    """TENANT_IDS and RUN are module-level and a run changes them (and must put them back). Pin them for every test, so a leak in one test can never decide another test's result."""
    monkeypatch.setitem(tf.TENANT_IDS, "A", "default-id-a")
    monkeypatch.setitem(tf.TENANT_IDS, "B", "default-id-b")
    monkeypatch.setitem(tf.RUN, "tag", "")


@pytest.fixture(autouse=True)
def _write_nothing_into_the_repository(tmp_path, monkeypatch):
    """The command writes its result file to the current directory unless told otherwise: run every test from a scratch directory so none ever leaves a file in the working tree."""
    monkeypatch.chdir(tmp_path)


class R:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class Client:
    """Answers from a script of responses per (method, path); records every request."""

    def __init__(self, script):
        self.script, self.requests = {k: list(v) if isinstance(v, list) else [v] for k, v in script.items()}, []

    async def request(self, method, path, **kw):
        self.requests.append((method, path, kw))
        queue = self.script[(method, path)]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    async def get(self, path, **kw):
        return await self.request("GET", path, **kw)


class Sleeper:
    def __init__(self):
        self.slept = []

    async def __call__(self, seconds):
        self.slept.append(seconds)


@pytest.mark.asyncio
class TestSend:
    async def test_a_normal_response_is_returned_with_one_request_and_no_waiting(self):
        c, sleep = Client({("GET", "/x"): R(200)}), Sleeper()
        assert (await tf._send(c, "GET", "/x", sleep=sleep)).status_code == 200
        assert len(c.requests) == 1 and sleep.slept == []

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 500, 502, 503])
    async def test_nothing_but_429_is_retried_a_step_may_legitimately_expect_a_503(self, status):
        c, sleep = Client({("GET", "/x"): R(status)}), Sleeper()
        assert (await tf._send(c, "GET", "/x", sleep=sleep)).status_code == status
        assert len(c.requests) == 1 and sleep.slept == []

    async def test_a_429_is_waited_out_using_retry_after_and_then_succeeds(self):
        c, sleep = Client({("GET", "/x"): [R(429, headers={"retry-after": "3"}), R(200)]}), Sleeper()
        assert (await tf._send(c, "GET", "/x", sleep=sleep)).status_code == 200
        assert len(c.requests) == 2 and sleep.slept == [3.0]

    async def test_without_retry_after_it_backs_off_1_2_4_seconds_then_gives_up_with_the_429(self):
        c, sleep = Client({("GET", "/x"): R(429)}), Sleeper()
        assert (await tf._send(c, "GET", "/x", sleep=sleep)).status_code == 429
        assert len(c.requests) == 4 and sleep.slept == [1.0, 2.0, 4.0]

    async def test_retry_after_is_capped_at_30_seconds(self):
        c, sleep = Client({("GET", "/x"): [R(429, headers={"retry-after": "9999"}), R(200)]}), Sleeper()
        await tf._send(c, "GET", "/x", sleep=sleep)
        assert sleep.slept == [30.0]

    @pytest.mark.parametrize("header", ["soon", "", "-5", "Wed, 21 Oct 2026 07:28:00 GMT"])
    async def test_an_unusable_retry_after_falls_back_to_the_backoff(self, header):
        c, sleep = Client({("GET", "/x"): [R(429, headers={"retry-after": header}), R(200)]}), Sleeper()
        await tf._send(c, "GET", "/x", sleep=sleep)
        assert sleep.slept == [1.0]

    async def test_retries_can_be_limited(self):
        c, sleep = Client({("GET", "/x"): R(429)}), Sleeper()
        await tf._send(c, "GET", "/x", retries=1, sleep=sleep)
        assert len(c.requests) == 2 and sleep.slept == [1.0]

    async def test_the_request_is_passed_through_unchanged_on_every_attempt(self):
        c, sleep = Client({("POST", "/x"): [R(429), R(200)]}), Sleeper()
        await tf._send(c, "POST", "/x", headers={"Authorization": "t"}, json={"a": 1}, params={"p": 2}, sleep=sleep)
        assert [r[2] for r in c.requests] == [{"headers": {"Authorization": "t"}, "json": {"a": 1}, "params": {"p": 2}}] * 2


@pytest.mark.asyncio
class TestFetchSpec:
    SPEC = {"openapi": "3.1.0", "paths": {"/api/v1/x": {}}}

    async def test_it_prefers_the_path_this_api_really_serves(self):
        c = Client({("GET", "/api/openapi.json"): R(200, self.SPEC)})
        assert await tf.fetch_spec(c) == self.SPEC
        assert [r[1] for r in c.requests] == ["/api/openapi.json"]

    async def test_it_falls_back_to_the_root_path(self):
        c = Client({("GET", "/api/openapi.json"): R(404), ("GET", "/openapi.json"): R(200, self.SPEC)})
        assert await tf.fetch_spec(c) == self.SPEC

    async def test_when_neither_works_it_says_what_it_tried_and_how_to_fix_it(self):
        c = Client({("GET", "/api/openapi.json"): R(404), ("GET", "/openapi.json"): R(404)})
        with pytest.raises(tf.PreflightError) as exc:
            await tf.fetch_spec(c)
        msg = str(exc.value)
        assert "/api/openapi.json -> HTTP 404" in msg and "/openapi.json -> HTTP 404" in msg and "--spec-file" in msg

    async def test_a_200_that_is_not_an_openapi_document_does_not_count(self):
        c = Client({("GET", "/api/openapi.json"): R(200, {"hello": "world"}), ("GET", "/openapi.json"): R(200, None)})
        with pytest.raises(tf.PreflightError):
            await tf.fetch_spec(c)


def script_for(ids=("tid-a", "tid-b"), can_select=(False, False), missing=((), ()), viewable=("own", "own")):
    """A deployment with two users A and B, routed by the bearer token each request carries."""
    class Routed:
        def __init__(self):
            self.requests = []

        async def request(self, method, path, headers=None, json=None, **kw):
            who = headers["Authorization"][-1]
            self.requests.append((who, method, path))
            i = 0 if who == "A" else 1
            if path == "/api/v1/tenants/me/identity":
                return R(200, {"id": ids[i]})
            if path == "/api/v1/tenants/viewable":  # "own": only its own tenant; None: a deployment without view-as (404); a list of ids; or a raw response body
                v = viewable[i]
                if v is None:
                    return R(404)
                return R(200, {"tenants": [{"id": t} for t in ([ids[i]] if v == "own" else v)]}) if isinstance(v, (list, str)) else R(200, v)
            if path == "/api/v1/tenants/selectable":
                return R(200, {"can_select_other_tenants": can_select[i]}) if can_select[i] is not None else R(404)
            if path == "/api/v1/auth/authorize":
                return R(403) if json["permission"] in missing[i] else R(200, {"allowed": True})
            raise AssertionError(path)

    return Routed()


TOK = {"A": {"Authorization": "Bearer A"}, "B": {"Authorization": "Bearer B"}}


@pytest.mark.asyncio
class TestPreflight:
    async def test_it_returns_the_two_real_tenant_ids(self):
        assert await tf.preflight(script_for(), TOK) == {"A": "tid-a", "B": "tid-b"}

    async def test_the_same_tenant_twice_is_refused(self):
        with pytest.raises(tf.PreflightError, match="SAME tenant"):
            await tf.preflight(script_for(ids=("t", "t")), TOK)

    @pytest.mark.parametrize("who,flags", [("A", (True, False)), ("B", (False, True))])
    async def test_a_user_with_cross_tenant_power_is_refused_and_named(self, who, flags):
        with pytest.raises(tf.PreflightError) as exc:
            await tf.preflight(script_for(can_select=flags), TOK)
        assert f"user {who} may look at other tenants" in str(exc.value) and "plain tenant admins" in str(exc.value)

    @pytest.mark.parametrize("who,viewable", [("A", (["tid-a", "tid-child"], "own")), ("B", ("own", ["tid-b", "tid-a"])), ("A", (["tid-a", "tid-b", "tid-c"], "own"))])
    async def test_a_user_who_may_view_other_tenants_is_refused_and_named(self, who, viewable):
        """If A managed B (or had platform power), 'B cannot be viewed by A' would fail for a legitimate reason."""
        with pytest.raises(tf.PreflightError) as exc:
            await tf.preflight(script_for(viewable=viewable), TOK)
        assert f"user {who} may VIEW other tenants" in str(exc.value) and "unrelated" in str(exc.value)

    async def test_the_view_check_happens_before_any_permission_is_probed_or_anything_is_written(self):
        c = script_for(viewable=(["tid-a", "tid-x"], "own"))
        with pytest.raises(tf.PreflightError):
            await tf.preflight(c, TOK)
        assert not any(p == "/api/v1/auth/authorize" for _, _, p in c.requests) and all(m == "GET" for _, m, _ in c.requests)

    async def test_a_deployment_without_view_as_cannot_be_checked_and_is_tolerated(self):
        assert await tf.preflight(script_for(viewable=(None, None)), TOK) == {"A": "tid-a", "B": "tid-b"}

    @pytest.mark.parametrize("body", [{}, {"tenants": None}, {"tenants": "x"}, {"other": 1}])
    async def test_an_answer_of_an_unknown_shape_is_tolerated_not_trusted_either_way(self, body):
        assert await tf.preflight(script_for(viewable=(body, body)), TOK) == {"A": "tid-a", "B": "tid-b"}

    async def test_both_users_are_asked_what_they_may_view(self):
        c = script_for()
        await tf.preflight(c, TOK)
        assert sorted(who for who, _, p in c.requests if p == "/api/v1/tenants/viewable") == ["A", "B"]

    async def test_a_deployment_without_the_selectable_endpoint_is_tolerated(self):
        assert await tf.preflight(script_for(can_select=(None, None)), TOK) == {"A": "tid-a", "B": "tid-b"}

    async def test_missing_permissions_are_listed_for_the_user_who_lacks_them(self):
        with pytest.raises(tf.PreflightError) as exc:
            await tf.preflight(script_for(missing=((), ("users:write", "rules:write"))), TOK)
        assert "user B lacks users:write, rules:write" in str(exc.value)

    async def test_every_required_permission_is_checked_for_both_users(self):
        c = script_for()
        await tf.preflight(c, TOK)
        checked = {(who, path) for who, _, path in c.requests if path == "/api/v1/auth/authorize"}
        assert checked == {("A", "/api/v1/auth/authorize"), ("B", "/api/v1/auth/authorize")}
        assert sum(1 for _, _, p in c.requests if p == "/api/v1/auth/authorize") == 2 * len(tf.REQUIRED_PERMISSIONS)

    async def test_an_unidentifiable_tenant_is_an_error(self):
        class Broken:
            async def request(self, method, path, **kw):
                return R(500)

        with pytest.raises(tf.PreflightError, match="cannot be identified"):
            await tf.preflight(Broken(), TOK)

    def test_every_required_permission_is_a_real_one(self):
        """An unknown name would answer 422, which is not a 403, so a typo here would silently count as 'allowed'."""
        assert set(tf.REQUIRED_PERMISSIONS) <= known_permissions()

    def test_none_of_the_required_permissions_is_a_platform_permission(self):
        from app.core.security import PLATFORM_PERMISSIONS

        assert not set(tf.REQUIRED_PERMISSIONS) & PLATFORM_PERMISSIONS


class TestPortability:
    def test_the_flows_use_the_real_tenant_ids_wherever_they_name_a_tenant(self, monkeypatch):
        old = dict(tf.TENANT_IDS)
        monkeypatch.setitem(tf.TENANT_IDS, "A", "11111111-2222-3333-4444-555555555555")
        monkeypatch.setitem(tf.TENANT_IDS, "B", "99999999-8888-7777-6666-000000000000")
        dump = json.dumps({f: [(s.name, s.tpl, s.over, s.params) for s in steps] for f, steps in tf.build_flows().items()}, default=str)
        assert old["A"] not in dump and old["B"] not in dump
        assert "11111111-2222-3333-4444-555555555555" in dump and "99999999-8888-7777-6666-000000000000" in dump

    def test_the_checks_read_the_ids_when_they_run_not_when_the_module_loads(self, monkeypatch):
        monkeypatch.setitem(tf.TENANT_IDS, "A", "id-of-a")
        monkeypatch.setitem(tf.TENANT_IDS, "B", "id-of-b")
        step = next(s for steps in tf.build_flows().values() for s in steps if s.name == "B's picker offers only B's own tenant")
        good = R(200, {"can_select_other_tenants": False, "tenants": [{"id": "id-of-b"}]})
        leaky = R(200, {"can_select_other_tenants": False, "tenants": [{"id": "id-of-b"}, {"id": "id-of-a"}]})
        assert step.check(good, {}) and not step.check(leaky, {})

    def test_no_check_depends_on_a_seeded_tenant_slug(self):
        """A flow must not assume the seeded tenants' slugs (tenant-a / tenant-b): that would make it fail on any real deployment. The match is a standalone token, so a route that merely contains those letters (/platform/all-tenant-access) is not mistaken for a slug."""
        import inspect
        import re

        slug = re.compile(r"(?<![\w-])tenant-[ab](?!\w)")
        assert not slug.search(inspect.getsource(tf))
        # the guard still catches real uses, and only those
        assert slug.search("slug == 'tenant-a'") and slug.search('"tenant-b"') and slug.search("name = tenant-a-x") and slug.search("tenant-a")
        assert not slug.search("/api/v1/platform/all-tenant-access/x") and not slug.search("tenant-access") and not slug.search("my-tenant-a") and not slug.search("tenant-ab")

    def test_run_flows_sends_every_request_through_the_retrying_sender(self):
        import inspect
        import re

        src = inspect.getsource(tf.run_flows)
        assert not re.search(r"\bc\.(get|post|request)\(", src), "a request outside _send would turn a 429 into a false failure"
        assert src.count("_send(") >= 4 and "preflight(" in src and "TENANT_IDS.update(" in src
        assert src.index("preflight(") < src.index("build_flows()"), "the real ids must be installed BEFORE the flows are built"


URL = ["run-url", "--label", "t", "--email-a", "a@x.com", "--email-b", "b@x.com"]
ENVP = {"TENANT_FLOWS_PASSWORD": "pw"}


class TestRunUrlCommand:
    @pytest.fixture
    def harness(self, monkeypatch, tmp_path, capsys):
        for var in ("TENANT_FLOWS_PASSWORD", "TENANT_FLOWS_PASSWORD_A", "TENANT_FLOWS_PASSWORD_B"):
            monkeypatch.delenv(var, raising=False)
        from types import SimpleNamespace

        h = SimpleNamespace(rows=[["f", "s", "A", 200, True, ""]], out=tmp_path / "r.json")
        calls = []

        async def fake(emails, password, **kw):
            calls.append({"emails": emails, "password": password, **kw})
            return h.rows

        monkeypatch.setattr(tf, "run_flows", fake)

        def go(argv, env=ENVP):
            for k, v in env.items():
                monkeypatch.setenv(k, v)
            code = tf.main(argv)
            return code, capsys.readouterr(), calls

        h.go = go
        return h

    def ok(self, host="staging.example.com", scheme="https", extra=()):
        return [*URL, "--base-url", f"{scheme}://{host}", "--confirm-host", host, "--yes-write-test-data", *extra]

    def test_the_happy_path_calls_the_runner_with_everything_and_writes_the_results(self, harness):
        code, cap, calls = harness.go(self.ok(extra=["--out", str(harness.out)]))
        assert code == 0 and len(calls) == 1
        assert calls[0] == {"emails": ("a@x.com", "b@x.com"), "password": "pw", "base_url": "https://staging.example.com", "password_b": "pw", "spec": None, "timeout": 30.0, "concurrency": 3, "sweep": True, "skip_flows": tf.DESTRUCTIVE_FLOWS, "cleanup": True}
        assert json.loads(harness.out.read_text()) == harness.rows and "[t] 1 steps; as expected: 1" in cap.out
        assert "They will CREATE test data in both tenants" in cap.err

    def test_it_refuses_without_the_explicit_flag(self, harness):
        argv = [*URL, "--base-url", "https://staging.example.com", "--confirm-host", "staging.example.com"]
        code, cap, calls = harness.go(argv)
        assert code == 2 and "CREATE data" in cap.err and calls == []

    @pytest.mark.parametrize("typed", ["app.example.com", "staging.example.org", "", "staging"])
    def test_it_refuses_when_the_retyped_host_does_not_match(self, harness, typed):
        argv = [*URL, "--base-url", "https://staging.example.com", "--confirm-host", typed, "--yes-write-test-data"]
        code, cap, calls = harness.go(argv)
        assert code == 2 and "does not match" in cap.err and calls == []

    def test_the_confirmation_ignores_case_and_surrounding_spaces(self, harness):
        argv = [*URL, "--base-url", "https://Staging.Example.com", "--confirm-host", "  STAGING.example.COM ", "--yes-write-test-data"]
        code, _, calls = harness.go(argv)
        assert code == 0 and len(calls) == 1

    @pytest.mark.parametrize("url", ["staging.example.com", "ftp://staging.example.com", "https://", "//staging.example.com", "file:///etc/passwd"])
    def test_it_refuses_something_that_is_not_an_http_url_with_a_host(self, harness, url):
        argv = [*URL, "--base-url", url, "--confirm-host", "staging.example.com", "--yes-write-test-data"]
        code, cap, calls = harness.go(argv)
        assert code == 2 and calls == []

    def test_it_refuses_plain_http_to_a_host_that_is_not_local(self, harness):
        code, cap, calls = harness.go(self.ok(scheme="http"))
        assert code == 2 and "plain http" in cap.err and calls == []

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
    def test_plain_http_is_fine_for_a_local_host(self, harness, host):
        argv = [*URL, "--base-url", f"http://{host}:8080", "--confirm-host", host.strip("[]"), "--yes-write-test-data"]
        code, _, calls = harness.go(argv)
        assert code == 0 and len(calls) == 1

    def test_plain_http_to_a_remote_host_needs_the_explicit_flag(self, harness):
        code, _, calls = harness.go(self.ok(scheme="http", extra=["--allow-insecure-http"]))
        assert code == 0 and len(calls) == 1

    def test_it_refuses_without_passwords(self, harness):
        code, cap, calls = harness.go(self.ok(), env={})
        assert code == 2 and "TENANT_FLOWS_PASSWORD_A" in cap.err and calls == []

    def test_one_missing_password_is_enough_to_refuse(self, harness):
        code, _, calls = harness.go(self.ok(), env={"TENANT_FLOWS_PASSWORD_A": "only-a"})
        assert code == 2 and calls == []

    def test_each_tenant_can_have_its_own_password(self, harness):
        _, _, calls = harness.go(self.ok(), env={"TENANT_FLOWS_PASSWORD_A": "pa", "TENANT_FLOWS_PASSWORD_B": "pb"})
        assert calls[0]["password"] == "pa" and calls[0]["password_b"] == "pb"

    def test_the_password_variables_can_be_renamed(self, harness):
        _, _, calls = harness.go(self.ok(extra=["--password-env-a", "MY_A", "--password-env-b", "MY_B"]), env={"MY_A": "x", "MY_B": "y"})
        assert (calls[0]["password"], calls[0]["password_b"]) == ("x", "y")

    def test_options_reach_the_runner(self, harness, tmp_path):
        spec = tmp_path / "spec.json"
        spec.write_text(json.dumps({"paths": {"/api/v1/x": {}}}))
        _, _, calls = harness.go(self.ok(extra=["--spec-file", str(spec), "--timeout", "7.5", "--concurrency", "2", "--no-sweep"]))
        assert calls[0]["spec"] == {"paths": {"/api/v1/x": {}}} and calls[0]["timeout"] == 7.5 and calls[0]["concurrency"] == 2 and calls[0]["sweep"] is False

    def test_a_failed_preflight_exits_2_and_says_nothing_was_written(self, harness, monkeypatch):
        async def boom(*a, **k):
            raise tf.PreflightError("both users belong to the SAME tenant")

        monkeypatch.setattr(tf, "run_flows", boom)
        code, cap, _ = harness.go(self.ok())
        assert code == 2 and "preflight failed, nothing was written: both users belong to the SAME tenant" in cap.err

    def test_a_step_that_is_not_as_expected_exits_1(self, harness):
        harness.rows = [["f", "s", "B", 200, False, "leaked"]]
        code, cap, _ = harness.go(self.ok(extra=["--out", str(harness.out)]))
        assert code == 1 and "NOT as expected: 1" in cap.out

    def test_a_setup_error_and_a_finding_have_different_exit_codes(self, harness, monkeypatch):
        """2 means 'fix the setup', 1 means 'the flows found a problem': a typo'd password must never look like an isolation failure."""
        assert 1 != 2
        async def bad_login(*a, **k):
            raise tf.PreflightError("login failed for tenant A (a@x.com): HTTP 401. Check the account name and the password.")

        monkeypatch.setattr(tf, "run_flows", bad_login)
        code, cap, _ = harness.go(self.ok())
        assert code == 2 and "login failed" in cap.err

    def test_the_in_process_command_also_reports_a_preflight_error_as_2(self, monkeypatch, capsys):
        from app.core.config import settings

        monkeypatch.setattr(settings, "ENVIRONMENT", "test")
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "p")

        async def boom(emails, password):
            raise tf.PreflightError("login failed for tenant B")

        monkeypatch.setattr(tf, "run_flows", boom)
        assert tf.main(["run", "--label", "x", "--yes-write-test-data"]) == 2
        assert "preflight failed, nothing was written: login failed for tenant B" in capsys.readouterr().err

    def test_the_url_mode_never_imports_the_application_or_its_settings(self, harness):
        """It must work from a machine that only has network access to the deployment: no database settings, no ENVIRONMENT, no app import."""
        import inspect

        assert "app.main" not in inspect.getsource(tf._main_url) and "settings" not in inspect.getsource(tf._main_url)


@pytest.mark.asyncio
class TestTheRealRunnerLogsIn:
    """run_flows itself (not a stand-in for it) against a fake HTTP client: a bad login must be a PreflightError (exit 2, nothing written), and each tenant must log in with ITS OWN password."""

    @pytest.fixture
    def server(self, monkeypatch):
        import httpx

        seen = {"logins": [], "keys": [], "bases": [], "paths": []}
        good = {"a@x.com": "pw-a", "b@x.com": "pw-b", "admin-a": "pw-a", "admin-b": "pw-b"}

        class FakeAsyncClient:
            def __init__(self, *a, base_url=None, **kw):
                seen["bases"].append(base_url)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, path, **kw):
                seen["paths"].append(path)
                if path == "/api/v1/auth/login":
                    body = kw["json"]
                    key = "email" if "email" in body else "account_name"
                    seen["keys"].append(key)
                    seen["logins"].append((body[key], body["password"]))
                    ok = good.get(body[key]) == body["password"]
                    return R(200, {"access_token": "t-" + body[key][0]}) if ok else R(401, {"detail": "bad"})
                return R(500)  # nothing after the login matters here

        monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
        return seen

    async def run(self, **kw):
        return await tf.run_flows(("a@x.com", "b@x.com"), "pw-a", base_url="http://x.example/", spec={"paths": {}}, **kw)

    async def test_a_wrong_password_for_A_is_a_preflight_error_naming_the_tenant(self, server):
        with pytest.raises(tf.PreflightError, match=r"login failed for tenant A \(a@x\.com\): HTTP 401"):
            await tf.run_flows(("a@x.com", "b@x.com"), "WRONG", base_url="http://x.example", spec={"paths": {}}, password_b="pw-b")

    async def test_a_wrong_password_for_B_is_a_preflight_error_naming_that_tenant(self, server):
        with pytest.raises(tf.PreflightError, match=r"login failed for tenant B \(b@x\.com\)"):
            await self.run(password_b="WRONG")

    async def test_the_message_says_what_to_check(self, server):
        with pytest.raises(tf.PreflightError, match="Check the account name and the password"):
            await tf.run_flows(("a@x.com", "b@x.com"), "WRONG", base_url="http://x.example", spec={"paths": {}})

    async def test_each_tenant_logs_in_with_its_own_password(self, server):
        with pytest.raises(tf.PreflightError):  # stops at the preflight (the fake answers 500): after both logins
            await self.run(password_b="pw-b")
        assert server["logins"] == [("a@x.com", "pw-a"), ("b@x.com", "pw-b")]

    async def test_an_account_name_is_sent_as_an_account_name_and_an_address_as_an_email(self, server):
        for identifiers, keys in ((("admin-a", "admin-b"), ["account_name", "account_name"]), (("a@x.com", "b@x.com"), ["email", "email"]), (("admin-a", "b@x.com"), ["account_name", "email"])):
            server["keys"].clear()
            with pytest.raises(tf.PreflightError):  # stops at the preflight (the fake answers 500): after both logins
                await tf.run_flows(identifiers, "pw-a", base_url="http://x.example", spec={"paths": {}}, password_b="pw-b")
            assert server["keys"] == keys, identifiers

    async def test_account_names_log_in_with_each_tenants_own_password_too(self, server):
        with pytest.raises(tf.PreflightError):
            await tf.run_flows(("admin-a", "admin-b"), "pw-a", base_url="http://x.example", spec={"paths": {}}, password_b="pw-b")
        assert server["logins"] == [("admin-a", "pw-a"), ("admin-b", "pw-b")]

    async def test_a_refused_account_name_login_names_the_tenant_and_says_what_to_check(self, server):
        with pytest.raises(tf.PreflightError, match=r"login failed for tenant A \(admin-a\): HTTP 401.*account name.*LOGIN_ALLOW_EMAIL"):
            await tf.run_flows(("admin-a", "admin-b"), "WRONG", base_url="http://x.example", spec={"paths": {}})

    async def test_without_a_separate_password_B_uses_the_same_one(self, server):
        with pytest.raises(tf.PreflightError, match=r"tenant B"):
            await self.run()  # b@x.com has password pw-b, but only pw-a was given
        assert server["logins"][1] == ("b@x.com", "pw-a")

    async def test_the_base_url_loses_a_trailing_slash(self, server):
        with pytest.raises(tf.PreflightError):
            await self.run(password_b="pw-b")
        assert server["bases"] == ["http://x.example"]

    async def test_nothing_is_requested_after_a_failed_login(self, server):
        with pytest.raises(tf.PreflightError):
            await self.run(password_b="WRONG")
        assert set(server["paths"]) == {"/api/v1/auth/login"}


class TestARunCanBeRepeatedAndTouchesNothingItDidNotCreate:
    """Against a real environment: the SECOND run must not collide with the first (fixed names gave 71 failures on a re-run), the flows that REPLACE configuration are opt-in, and the inbox flow acts only on tokens it minted."""

    def test_a_tag_changes_every_generated_name_and_no_tag_changes_nothing(self, monkeypatch):
        def bodies(tag):
            monkeypatch.setitem(tf.RUN, "tag", tag)
            return json.dumps({f: [(s.name, s.over, s.params) for s in steps] for f, steps in tf.build_flows().items()}, default=str)

        assert bodies("") == bodies(""), "without a tag the requests stay byte-identical (the in-process runs compare against each other)"
        assert bodies("aaaaaa") != bodies("bbbbbb")

    def test_a_generated_value_carries_the_tag_and_stays_within_its_limits(self, monkeypatch):
        spec = {"components": {"schemas": {}}}
        string = {"type": "string", "maxLength": 40}
        monkeypatch.setitem(tf.RUN, "tag", "")
        plain = tf.gen(spec, string, "/api/v1/things.post.name")
        monkeypatch.setitem(tf.RUN, "tag", "a1b2c3")
        tagged = tf.gen(spec, string, "/api/v1/things.post.name")
        assert plain != tagged and tagged.endswith("a1b2c3") and tagged.startswith("flow-") and len(tagged) <= 40
        assert tf.gen(spec, {"type": "string", "format": "uuid"}, "s") != (monkeypatch.setitem(tf.RUN, "tag", ""), tf.gen(spec, {"type": "string", "format": "uuid"}, "s"))[1]

    def test_two_fields_of_one_body_do_not_collapse_into_the_same_value(self, monkeypatch):
        monkeypatch.setitem(tf.RUN, "tag", "a1b2c3")
        spec = {"components": {"schemas": {}}}
        obj = {"type": "object", "required": ["name", "title"], "properties": {"name": {"type": "string"}, "title": {"type": "string"}}}
        body = tf.gen(spec, obj, "/api/v1/things.post")
        assert body["name"] != body["title"]

    @pytest.mark.parametrize("name", ["flow-role-a", "flow-role-b", "flow-parser-a", "ext-a-1", "ext-a-2", "ext-b-1", "ext-fresh"])
    def test_every_free_form_name_that_collided_on_a_rerun_carries_the_tag(self, monkeypatch, name):
        """These were hard-coded, so the second run against the same environment got '409 already exists' (rbac roles, the parser, the identity-graph nodes) and every dependent step was skipped."""
        monkeypatch.setitem(tf.RUN, "tag", "abc123")
        dump = json.dumps({f: [(s.over, s.params) for s in steps] for f, steps in tf.build_flows().items()}, default=str)
        assert f"{name}-abc123" in dump and f'"{name}"' not in dump
        monkeypatch.setitem(tf.RUN, "tag", "")
        dump = json.dumps({f: [(s.over, s.params) for s in steps] for f, steps in tf.build_flows().items()}, default=str)
        assert f'"{name}"' in dump, "without a tag (in-process) the name is unchanged"

    def test_the_tenant_users_flow_uses_tagged_emails_and_usernames(self, monkeypatch):
        monkeypatch.setitem(tf.RUN, "tag", "abc123")
        steps = tf.build_flows()["tenant_users"]
        text = json.dumps([(s.name, s.over) for s in steps], default=str)
        assert "flow-user-a-abc123@example.com" in text and "flowuseraabc123" in text
        assert "flow-user-a@example.com" not in text
        monkeypatch.setitem(tf.RUN, "tag", "")
        assert "flow-user-a@example.com" in json.dumps([s.over for s in tf.build_flows()["tenant_users"]], default=str)

    def test_the_token_fingerprint_is_exactly_the_servers(self):
        from app.api.v1.endpoints.inbox import _fingerprint

        for token in ("aitnb_ReM_M1FUYG9X0abcdef", "x" * 9, "x" * 8, "short", "", "aitnb_" + "Z" * 43):
            assert tf._token_fingerprint(token) == _fingerprint(token), token

    def test_a_capture_takes_the_value_at_the_path_and_applies_the_transform_when_given(self):
        body = {"token": "aitnb_0123456789", "items": [{"id": 7}]}
        assert tf._capture_value(("x", "token"), body) == "aitnb_0123456789"
        assert tf._capture_value(("x", "items.0.id"), body) == "7"
        assert tf._capture_value(("x", "token", tf._token_fingerprint), body) == "...23456789"

    def test_the_inbox_flow_never_picks_a_token_off_a_list(self):
        steps = tf.build_flows()["inbox_tokens"]
        assert not [s for s in steps if s.capture and "fingerprint" in s.capture[1]], "a list's first entry may be a token the flow did not create"
        for s in steps:
            if s.capture:
                assert s.method == "post" and s.capture[1] == "token" and len(s.capture) == 3 and s.capture[2] is tf._token_fingerprint

    def test_the_inbox_flow_revokes_every_token_it_created(self):
        steps = tf.build_flows()["inbox_tokens"]
        created = {s.capture[0] for s in steps if s.capture}
        # only a SUCCESSFUL delete revokes a token: "B cannot revoke A's token" is a delete that must fail with a 404
        revoked = {name for s in steps if s.method == "delete" and 204 in s.expect for name in created if s.tpl.endswith("{" + name + "}")}
        # a rotation retires the token it rotated; the one it produced, and the one A minted, must be revoked by the flow
        rotated_from = {s.tpl.split("/")[-2].strip("{}") for s in steps if s.tpl.endswith("/rotate") and 200 in s.expect}  # only a SUCCESSFUL rotation retires a token ("B cannot rotate A's token" expects 404)
        assert created - rotated_from == revoked

    def test_every_flow_that_replaces_existing_configuration_is_in_the_destructive_set(self):
        flows = tf.build_flows()
        assert tf.DESTRUCTIVE_FLOWS <= set(flows)
        replacing = ("/api/v1/business-context/rules", "/api/v1/tenants/me/settings", "/api/v1/marketplace/install")
        for name, steps in flows.items():
            hits = [s.tpl for s in steps if s.method in ("post", "put", "patch", "delete") and s.tpl.startswith(replacing)]
            assert bool(hits) == (name in tf.DESTRUCTIVE_FLOWS), (name, hits)


@pytest.mark.asyncio
class TestRunFlowsAgainstADeployment:
    """The real run_flows against a fake deployment and two tiny flows."""

    @pytest.fixture
    def deployment(self, monkeypatch):
        import httpx

        seen = {"paths": [], "tag_at_build": [], "ids_at_build": [], "bodies": []}

        class FakeAsyncClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, path, **kw):
                seen["paths"].append(path)
                if kw.get("json") is not None:
                    seen["bodies"].append(kw["json"])
                who = (kw.get("headers") or {}).get("Authorization", "  ")[-1]
                if path == "/api/v1/auth/login":
                    return R(200, {"access_token": "t-" + kw["json"]["email"][0]})
                if path == "/api/v1/tenants/me/identity":
                    return R(200, {"id": "real-a" if who == "a" else "real-b"})
                if path == "/api/v1/tenants/selectable":
                    return R(200, {"can_select_other_tenants": False})
                if path == "/api/v1/auth/authorize":
                    return R(200, {"allowed": True})
                return R(200, {})

        def build():
            seen["tag_at_build"].append(tf.RUN["tag"])
            seen["ids_at_build"].append(dict(tf.TENANT_IDS))
            return {"keep": [tf.S("A reads keep", "A", "get", "/api/v1/keep", expect=(200,))], "business_context_rules": [tf.S("A replaces", "A", "get", "/api/v1/skipme", expect=(200,))]}

        monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
        monkeypatch.setattr(tf, "build_flows", build)
        monkeypatch.setitem(tf.RUN, "tag", "")
        return seen

    SPEC = {"paths": {}}

    async def run(self, **kw):
        return await tf.run_flows(("a@x.com", "b@x.com"), "pw", base_url="http://x.example", spec=self.SPEC, sweep=False, **kw)

    async def test_a_skipped_flow_makes_no_requests_at_all(self, deployment):
        rows = await self.run(skip_flows=tf.DESTRUCTIVE_FLOWS)
        assert "/api/v1/keep" in deployment["paths"] and "/api/v1/skipme" not in deployment["paths"]
        assert [r[0] for r in rows] == ["keep"]

    async def test_without_skipping_both_flows_run(self, deployment):
        rows = await self.run()
        assert {r[0] for r in rows} == {"keep", "business_context_rules"} and all(r[4] for r in rows)

    async def test_the_real_tenant_ids_are_in_place_when_the_flows_are_built(self, deployment):
        await self.run()
        assert deployment["ids_at_build"][0] == {"A": "real-a", "B": "real-b"}

    async def test_the_tenant_ids_do_not_leak_into_the_next_run(self, deployment):
        assert tf.TENANT_IDS == {"A": "default-id-a", "B": "default-id-b"}  # a known starting state, set by the autouse fixture
        await self.run()
        assert tf.TENANT_IDS == {"A": "default-id-a", "B": "default-id-b"}, "the run left the deployment's tenant ids behind"

    async def test_a_deployment_run_gets_a_fresh_random_tag_each_time_and_it_does_not_leak(self, deployment):
        await self.run()
        await self.run()
        t1, t2 = deployment["tag_at_build"]
        assert t1 and t2 and t1 != t2 and len(t1) == 6 and all(c in "0123456789abcdef" for c in t1)
        assert tf.RUN["tag"] == ""

    async def test_an_explicit_tag_wins(self, deployment):
        await self.run(run_tag="mine42")
        assert deployment["tag_at_build"] == ["mine42"]

    async def test_the_state_is_restored_even_when_the_run_fails_midway(self, deployment, monkeypatch):
        before = dict(tf.TENANT_IDS)
        assert before == {"A": "default-id-a", "B": "default-id-b"}

        def boom():
            raise RuntimeError("flows could not be built")

        monkeypatch.setattr(tf, "build_flows", boom)
        with pytest.raises(RuntimeError):
            await self.run(run_tag="zz")
        assert tf.TENANT_IDS == before and tf.RUN["tag"] == ""


class TestIncludeDestructiveFlag:
    @pytest.fixture
    def cli(self, monkeypatch, capsys):
        for var in ("TENANT_FLOWS_PASSWORD_A", "TENANT_FLOWS_PASSWORD_B"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "pw")
        calls = []

        async def fake(emails, password, **kw):
            calls.append(kw)
            return [["f", "s", "A", 200, True, ""]]

        monkeypatch.setattr(tf, "run_flows", fake)
        return lambda *extra: (tf.main([*URL, "--base-url", "https://staging.example.com", "--confirm-host", "staging.example.com", "--yes-write-test-data", *extra]), capsys.readouterr().err, calls)

    def test_by_default_the_replace_style_flows_are_skipped_and_the_operator_is_told(self, cli):
        code, err, calls = cli()
        assert code == 0 and calls[0]["skip_flows"] == tf.DESTRUCTIVE_FLOWS
        assert "SKIPPED because they replace existing configuration" in err
        for name in tf.DESTRUCTIVE_FLOWS:
            assert name in err

    def test_the_flag_runs_them_and_says_nothing_was_skipped(self, cli):
        code, err, calls = cli("--include-destructive")
        assert code == 0 and calls[0]["skip_flows"] == frozenset() and "SKIPPED" not in err

    def test_the_in_process_command_never_skips_anything(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "ENVIRONMENT", "test")
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "p")
        seen = []

        async def fake(emails, password):  # the in-process command calls it with exactly two positional arguments
            seen.append((emails, password))
            return [["f", "s", "A", 200, True, ""]]

        monkeypatch.setattr(tf, "run_flows", fake)
        assert tf.main(["run", "--label", "x", "--yes-write-test-data"]) == 0 and len(seen) == 1


class TestTheOAuthFlowNeverTouchesARealConnectorApp:
    def seed(self):
        v = tf.FLOW_SEEDS["oauth_apps"]["ct"]
        return v() if callable(v) else v

    def test_it_registers_an_app_for_a_connector_type_named_for_the_run(self, monkeypatch):
        monkeypatch.setitem(tf.RUN, "tag", "a1b2c3")
        assert self.seed() == "flowtest-a1b2c3"

    def test_without_a_tag_the_name_is_stable_for_in_process_runs(self, monkeypatch):
        monkeypatch.setitem(tf.RUN, "tag", "")
        assert self.seed() == "flowtest"

    def test_it_is_a_name_the_api_accepts(self, monkeypatch):
        import re

        monkeypatch.setitem(tf.RUN, "tag", "a1b2c3")
        assert re.match(r"^[a-zA-Z0-9_\-]{1,100}$", self.seed())  # the API's own rule for a connector type

    def test_it_is_not_one_of_the_real_connector_names(self, monkeypatch):
        for tag in ("", "abcdef"):
            monkeypatch.setitem(tf.RUN, "tag", tag)
            assert self.seed() not in {"github", "slack", "okta", "jira", "microsoft365", "google", "aws"}

    def test_the_oauth_flow_is_therefore_not_destructive(self):
        assert "oauth_apps" not in tf.DESTRUCTIVE_FLOWS

    def test_the_runner_evaluates_a_callable_seed_when_each_flow_starts(self):
        import inspect

        src = inspect.getsource(tf.run_flows)
        assert "v() if callable(v) else v" in src and "FLOW_SEEDS.get(flow, {})" in src


@pytest.mark.asyncio
class TestCleanupAfterTheSweep:
    """What the FRESH flow created is deleted again once the leak sweep has finished with it, through routes taken from the API's own spec, so the next run (and the environment) starts clean."""

    SPEC = {
        "paths": {
            "/api/v1/widgets": {"post": {}},
            "/api/v1/widgets/{id}": {"delete": {}},
            "/api/v1/gadgets": {"post": {}},  # nothing can delete a gadget: no <path>/{id} route at all
            "/api/v1/gizmos": {"post": {}},
            "/api/v1/gizmos/{id}": {"get": {}},  # a route for one gizmo EXISTS but it has no DELETE method
            "/api/v1/things": {"get": {}},  # for the sweep
            "/api/v1/others": {"post": {}},
            "/api/v1/others/{id}": {"delete": {}},
        }
    }

    @pytest.fixture
    def env(self, monkeypatch):
        import httpx

        seen = {"requests": [], "delete_status": 204}

        class FakeAsyncClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, path, **kw):
                who = (kw.get("headers") or {}).get("Authorization", "  ")[-1]
                seen["requests"].append((method, path, who))
                if path == "/api/v1/auth/login":
                    return R(200, {"access_token": "t-" + kw["json"]["email"][0]})
                if path == "/api/v1/tenants/me/identity":
                    return R(200, {"id": "real-" + who})
                if path == "/api/v1/tenants/selectable":
                    return R(200, {"can_select_other_tenants": False})
                if path == "/api/v1/auth/authorize":
                    return R(200, {"allowed": True})
                if method == "POST":
                    return R(201, {"id": "id-" + path.rsplit("/", 1)[-1]})
                if method == "DELETE":
                    return R(seen["delete_status"], {"detail": "x"})
                return R(200, {})

        def build():
            return {
                "other": [tf.S("A makes another", "A", "post", "/api/v1/others", capture=("o_thing", "id"))],
                "fresh": [
                    tf.S("A creates a fresh widget", "A", "post", "/api/v1/widgets", capture=("f_widget", "id")),
                    tf.S("A creates a fresh gadget", "A", "post", "/api/v1/gadgets", capture=("f_gadget", "id")),
                    tf.S("A creates a fresh gizmo", "A", "post", "/api/v1/gizmos", capture=("f_gizmo", "id")),
                ],
            }

        monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
        monkeypatch.setattr(tf, "build_flows", build)
        return seen

    async def run(self, **kw):
        return await tf.run_flows(("a@x.com", "b@x.com"), "pw", base_url="http://x.example", spec=self.SPEC, **kw)

    def deletes(self, env):
        return [(m, p, w) for m, p, w in env["requests"] if m == "DELETE"]

    async def test_a_fresh_object_is_deleted_at_the_path_it_was_created_at_plus_its_id_by_A(self, env):
        rows = await self.run(sweep=False)
        assert self.deletes(env) == [("DELETE", "/api/v1/widgets/id-widgets", "a")]
        assert [r for r in rows if r[0] == "CLEANUP"] == [["CLEANUP", "A deletes the fresh object 'f_widget'", "A", 204, True, ""]]

    async def test_an_object_nothing_can_delete_is_left_alone_and_makes_no_request_or_row(self, env):
        rows = await self.run(sweep=False)
        assert not any("gadgets/" in p for _, p, _ in env["requests"]) and not any("f_gadget" in r[1] for r in rows)

    async def test_an_object_whose_route_exists_but_has_no_delete_method_is_not_deleted(self, env):
        rows = await self.run(sweep=False)
        assert not any("gizmos/" in p for _, p, _ in env["requests"]) and not any("f_gizmo" in r[1] for r in rows)

    async def test_only_what_the_fresh_flow_created_is_deleted(self, env):
        await self.run(sweep=False)
        assert not any("others/" in p for _, p, _ in env["requests"])

    @pytest.mark.parametrize("status,ok", [(200, True), (202, True), (204, True), (404, True), (403, False), (409, False), (500, False)])
    async def test_a_gone_object_is_fine_and_a_refusal_is_a_finding(self, env, status, ok):
        env["delete_status"] = status
        rows = await self.run(sweep=False)
        row = next(r for r in rows if r[0] == "CLEANUP")
        assert row[3] == status and row[4] is ok and (row[5] == "" if ok else row[5] != "")

    async def test_it_can_be_turned_off(self, env):
        rows = await self.run(sweep=False, cleanup=False)
        assert self.deletes(env) == [] and not any(r[0] == "CLEANUP" for r in rows)

    async def test_a_deployment_run_cleans_up_by_default(self, env):
        await self.run(sweep=False)
        assert len(self.deletes(env)) == 1

    def test_an_in_process_run_does_not_clean_up_by_default_its_database_is_thrown_away(self):
        import inspect

        assert "cleanup = base_url is not None" in inspect.getsource(tf.run_flows)

    async def test_it_happens_after_the_leak_sweep_has_finished_with_the_objects(self, env):
        await self.run(sweep=True)
        order = [(m, p) for m, p, _ in env["requests"] if p in ("/api/v1/things", "/api/v1/widgets/id-widgets")]
        assert order == [("GET", "/api/v1/things"), ("DELETE", "/api/v1/widgets/id-widgets")]

    async def test_a_failed_delete_request_is_reported_not_raised(self, env, monkeypatch):
        original = tf._send

        async def flaky(c, method, path, **kw):
            if method == "DELETE":
                raise RuntimeError("connection reset")
            return await original(c, method, path, **kw)

        monkeypatch.setattr(tf, "_send", flaky)
        rows = await self.run(sweep=False)
        assert [r for r in rows if r[0] == "CLEANUP"] == [["CLEANUP", "A deletes the fresh object 'f_widget'", "A", "EXC", False, "RuntimeError"]]

    def test_the_cli_can_switch_it_off(self, monkeypatch, capsys):
        monkeypatch.setenv("TENANT_FLOWS_PASSWORD", "pw")
        calls = []

        async def fake(emails, password, **kw):
            calls.append(kw)
            return [["f", "s", "A", 200, True, ""]]

        monkeypatch.setattr(tf, "run_flows", fake)
        base = [*URL, "--base-url", "https://staging.example.com", "--confirm-host", "staging.example.com", "--yes-write-test-data"]
        assert tf.main([*base, "--no-cleanup"]) == 0 and calls[-1]["cleanup"] is False
        assert tf.main(base) == 0 and calls[-1]["cleanup"] is True
