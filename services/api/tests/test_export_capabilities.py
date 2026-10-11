"""The capability reference: generated from the live routes, never edited by hand, and honest about what it knows.

It exists so an agent (Cipher) can say what AiSOC can do even where it has no tool, instead of guessing. What it must never do is overstate protection: writing 'login only' for a route that is public, or checked inside its handler, is worse than saying nothing (it did exactly that on its
first run, which is how a tenant admin being able to list every tenant came to light).
"""
import uuid
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI

from app.api.v1.deps import AuthUser, require_permission
from app.core.route_introspect import access_kind
from app.main import app as real_app
from app.scripts import export_capabilities as ec

ROOT = Path(__file__).resolve().parents[3]
FULL_FILE = ROOT / "docs" / "api" / "AISOC_CAPABILITIES.md"
INDEX_FILE = ROOT / "docs" / "api" / "aisoc-areas.md"
CORE_COPY = ROOT.parent / "Jarvis" / "agents" / "cipher" / "knowledge" / "aisoc-areas.md"


def tiny_app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/v1/things", summary="list the things", dependencies=[Depends(require_permission("things:read"))])
    def list_things():
        return []

    @app.post("/api/v1/things", dependencies=[Depends(require_permission("things:write"))])
    def make_thing():
        return {}

    @app.delete("/api/v1/things/{thing_id}", summary="remove | a thing\nwith a newline", dependencies=[Depends(require_permission("things:delete"))])
    def delete_thing(thing_id: str):
        return {}

    @app.get("/api/v1/me")
    def who_am_i(user: AuthUser):
        return {}

    @app.post("/api/v1/auth/login")
    def log_in():
        return {}

    @app.get("/auth/sso/login")
    def sso_login():
        return {}

    @app.get("/api/v1/")
    def root_of_api():
        return {}

    return app


@pytest.fixture(scope="module")
def tiny_ops():
    return ec.operations(tiny_app())


@pytest.fixture(scope="module")
def real_ops():
    return ec.operations(real_app)


class TestOperations:
    def test_each_method_of_each_route_is_one_operation_in_a_stable_order(self, tiny_ops):
        got = [(o.area, o.method, o.path) for o in tiny_ops]
        assert got == sorted(got, key=lambda t: (t[0], t[2], t[1]))
        assert ("things", "GET", "/things") in got and ("things", "POST", "/things") in got and ("things", "DELETE", "/things/{thing_id}") in got
        assert len(got) == len(set(got)) == 7

    def test_head_and_options_declared_on_a_route_are_skipped(self):
        """FastAPI does not add them by itself, so a route has to declare them to exercise the filter."""
        app = FastAPI()
        app.add_api_route("/api/v1/multi", lambda: {}, methods=["GET", "HEAD", "OPTIONS"])
        assert [o.method for o in ec.operations(app)] == ["GET"]

    def test_head_and_options_are_not_operations(self, tiny_ops):
        assert {o.method for o in tiny_ops} == {"GET", "POST", "DELETE"}

    def test_the_api_prefix_is_stripped_and_a_route_outside_it_is_marked(self, tiny_ops):
        by = {(o.method, o.path): o for o in tiny_ops}
        assert not by[("GET", "/things")].outside_api
        sso = by[("GET", "/auth/sso/login")]
        assert sso.outside_api and sso.area == "auth"

    def test_the_area_is_the_first_path_segment_and_the_bare_root_is_named(self, tiny_ops):
        assert {o.area for o in tiny_ops} == {"things", "me", "auth", "(root)"}

    def test_the_summary_is_the_routes_own_or_the_function_name_made_readable(self, tiny_ops):
        by = {(o.method, o.path): o.summary for o in tiny_ops}
        assert by[("GET", "/things")] == "List the things"
        assert by[("POST", "/things")] == "Make thing"
        assert by[("GET", "/me")] == "Who am i"

    def test_the_permissions_are_the_ones_the_route_asks_for(self, tiny_ops):
        by = {(o.method, o.path): o.permissions for o in tiny_ops}
        assert by[("GET", "/things")] == ("things:read",) and by[("POST", "/things")] == ("things:write",) and by[("GET", "/me")] == ()

    def test_the_three_kinds_of_protection_are_told_apart(self, tiny_ops):
        by = {(o.method, o.path): o.access for o in tiny_ops}
        assert by[("GET", "/things")] == "permission"
        assert by[("GET", "/me")] == "signed-in"
        assert by[("POST", "/auth/login")] == "open" and by[("GET", "/auth/sso/login")] == "open"

    def test_access_kind_matches_what_the_operations_say(self):
        app = tiny_app()
        from app.core.route_introspect import walk_routes

        kinds = {p: access_kind(r) for p, r in walk_routes(app.routes)}
        assert kinds["/api/v1/me"] == "signed-in" and kinds["/api/v1/things"] == "permission" and kinds["/api/v1/auth/login"] == "open"


class TestRendering:
    def test_the_full_reference_lists_every_operation_exactly_once(self, tiny_ops):
        text = ec.render_full(tiny_ops)
        rows = [l for l in text.splitlines() if l.startswith(("| GET ", "| POST ", "| DELETE "))]
        assert len(rows) == len(tiny_ops)

    def test_the_area_table_counts_add_up(self, tiny_ops):
        text = ec.render_full(tiny_ops)
        assert "| [things](#things) | 1 | 2 |" in text
        assert f"**{len(tiny_ops)}** operations in **4** areas" in text

    def test_a_pipe_or_a_newline_in_a_summary_cannot_break_the_table(self, tiny_ops):
        row = next(l for l in ec.render_full(tiny_ops).splitlines() if "/things/{thing_id}" in l and l.startswith("| DELETE"))
        assert "Remove \\| a thing with a newline" in row and row.count("|") - row.count("\\|") == 5

    def test_a_route_outside_the_api_prefix_says_so(self, tiny_ops):
        assert "`/auth/sso/login (outside `/api/v1`)`" in ec.render_full(tiny_ops).replace("\\`", "`") or "(outside `/api/v1`)" in ec.render_full(tiny_ops)

    def test_protection_is_stated_exactly_as_far_as_it_is_known_and_never_as_login_only(self, tiny_ops):
        for text in (ec.render_full(tiny_ops), ec.render_index(tiny_ops)):
            assert "login only" not in text
        full = ec.render_full(tiny_ops)
        assert "`things:read`" in full and ec.SIGNED_IN_TEXT in full and ec.OPEN_TEXT in full
        assert "a check may be inside the handler" in full

    def test_it_says_GET_is_a_declaration_not_proof(self, tiny_ops):
        assert "not proof that the handler never writes" in ec.render_full(tiny_ops)
        assert "not proof a handler never writes" in ec.render_index(tiny_ops)

    def test_the_index_has_exactly_one_line_per_area_and_says_it_is_a_map_not_a_tool_list(self, tiny_ops):
        text = ec.render_index(tiny_ops)
        bullets = [l for l in text.splitlines() if l.startswith("- **")]
        assert [b.split("**")[1] for b in bullets] == ["(root)", "auth", "me", "things"]
        assert "MAP, not a list of tools" in text and "never guess its contents, never invent a tool, and never try to call an endpoint directly" in text

    def test_the_index_line_counts_reads_and_changes_and_names_the_protection(self, tiny_ops):
        line = next(l for l in ec.render_index(tiny_ops).splitlines() if l.startswith("- **things**"))
        assert "1 reads, 2 changes" in line and "protection: `things:delete`, `things:read`, `things:write`" in line and "e.g. List the things" in line
        me = next(l for l in ec.render_index(tiny_ops).splitlines() if l.startswith("- **me**"))
        assert "1 signed-in with no permission declared" in me
        auth = next(l for l in ec.render_index(tiny_ops).splitlines() if l.startswith("- **auth**"))
        assert "2 with no sign-in required" in auth

    def test_rendering_twice_gives_the_same_text(self, tiny_ops):
        assert ec.render_full(tiny_ops) == ec.render_full(tiny_ops) and ec.render_index(tiny_ops) == ec.render_index(tiny_ops)

    def test_an_empty_application_renders_without_failing(self):
        assert "**0** operations in **0** areas" in ec.render_full([]) and "**0** operations in **0** areas" in ec.render_index([])


class TestTheCommand:
    def test_it_writes_both_files_creating_folders_and_check_then_passes(self, tmp_path, capsys):
        full, index = tmp_path / "deep" / "dir" / "full.md", tmp_path / "idx.md"
        assert ec.main(["--full", str(full), "--index", str(index)]) == 0
        assert full.exists() and index.exists()
        assert ec.main(["--full", str(full), "--index", str(index), "--check"]) == 0
        assert "up to date" in capsys.readouterr().out

    def test_check_fails_when_a_file_is_changed_or_missing_and_writes_nothing(self, tmp_path, capsys):
        full, index = tmp_path / "full.md", tmp_path / "idx.md"
        ec.main(["--full", str(full), "--index", str(index)])
        index.write_text(index.read_text(encoding="utf-8") + "\nhand edit\n", encoding="utf-8")
        before = index.read_text(encoding="utf-8")
        assert ec.main(["--full", str(full), "--index", str(index), "--check"]) == 1
        assert index.read_text(encoding="utf-8") == before, "--check must not rewrite"
        full.unlink()
        assert ec.main(["--full", str(full), "--index", str(index), "--check"]) == 1
        assert not full.exists()
        assert "out of date" in capsys.readouterr().err


class TestTheRealApplication:
    def test_there_are_hundreds_of_operations_and_the_counts_add_up(self, real_ops):
        assert len(real_ops) > 400
        # The same path can exist under /api/v1 AND at the root (single sign-on aliases): those are different routes, which is why the reference marks the root ones.
        assert len({(o.method, o.path, o.outside_api) for o in real_ops}) == len(real_ops)
        areas = ec._by_area(real_ops)
        assert sum(len(v) for v in areas.values()) == len(real_ops)
        assert sum(sum(o.is_read for o in v) + sum(not o.is_read for o in v) for v in areas.values()) == len(real_ops)

    def test_a_path_that_exists_both_under_the_api_prefix_and_at_the_root_is_listed_twice_and_marked(self, real_ops):
        both = {(o.method, o.path) for o in real_ops if o.outside_api} & {(o.method, o.path) for o in real_ops if not o.outside_api}
        assert both, "single sign-on routes exist in both places"
        text = ec.render_full(real_ops)
        for method, path in both:
            assert f"| {method} | `{path}` |" in text and f"| {method} | `{path} (outside `/api/v1`)`" in text.replace("\\`", "`") or f"{path} (outside" in text

    def test_known_operations_say_the_right_thing(self, real_ops):
        by = {(o.method, o.path): o for o in real_ops}
        assert by[("GET", "/hunts")].permissions == ("hunts:read",)
        assert by[("GET", "/hunts/{hunt_id}/runs")].permissions == ("lake:query",)
        assert by[("GET", "/admin/tenants")].permissions == ("platform:cross_tenant_query",)
        assert by[("POST", "/admin/tenants/provision")].permissions == ("mssp:onboard",)
        assert by[("GET", "/auth/me")].access == "signed-in"
        assert by[("POST", "/auth/login")].access == "open"
        assert by[("GET", "/rules")].permissions == ("rules:view",)

    def test_most_operations_declare_a_permission_and_the_rest_are_a_small_known_group(self, real_ops):
        permissioned = sum(o.access == "permission" for o in real_ops)
        assert permissioned / len(real_ops) > 0.8
        assert not [o for o in real_ops if o.access == "permission" and not o.permissions]
        assert not [o for o in real_ops if o.access != "permission" and o.permissions]

    def test_the_committed_full_reference_is_what_the_routes_produce_today(self, real_ops):
        assert FULL_FILE.read_text(encoding="utf-8") == ec.render_full(real_ops), "docs/api/AISOC_CAPABILITIES.md is out of date: python -m app.scripts.export_capabilities --full ../../docs/api/AISOC_CAPABILITIES.md --index ../../docs/api/aisoc-areas.md"

    def test_the_committed_index_is_what_the_routes_produce_today(self, real_ops):
        assert INDEX_FILE.read_text(encoding="utf-8") == ec.render_index(real_ops), "docs/api/aisoc-areas.md is out of date: regenerate it (see the test above)"

    def test_the_index_is_small_enough_to_hand_to_an_agent(self, real_ops):
        assert len(ec.render_index(real_ops)) < 25_000

    def test_the_copy_in_the_core_checkout_is_the_same_when_one_is_next_to_this_repo(self, real_ops):
        if not CORE_COPY.exists():
            pytest.skip("no copy in a CORE checkout next to this repository")
        assert CORE_COPY.read_text(encoding="utf-8") == ec.render_index(real_ops), "Cipher's knowledge file is out of date: copy docs/api/aisoc-areas.md to the CORE repo's agents/cipher/knowledge/aisoc-areas.md"
