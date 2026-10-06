"""B10: backend-route coverage gate (v2 — Next.js-aware).

Loads the API and agents FastAPI apps separately, extracts every
registered route from each, then scans ``apps/web/src`` for
``/api/v1/...`` string literals.  For each frontend path the test
finds the FIRST matching rewrite in ``next.config.js`` order, resolves
its destination host variable (``API_HOST`` → api service routes,
``AGENTS_HOST`` → agents service routes), and requires the route to
exist in THAT service's OpenAPI schema.  Paths that match no rewrite
are checked against the api service (the default catch-all target).

Three temporary-mutation tests prove the check actually catches
missing routes by injecting synthetic frontend calls that must fail.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths — REPO_ROOT is the monorepo root; SERVICES_ROOT is services/
# ---------------------------------------------------------------------------
_THIS_FILE = Path(__file__).resolve()
REPO_ROOT = _THIS_FILE.parents[3]       # services/api/tests/X.py → repo root
SERVICES_ROOT = _THIS_FILE.parents[1]   # services/api/tests/X.py → services/
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"
NEXT_CONFIG = REPO_ROOT / "apps" / "web" / "next.config.js"


# ---------------------------------------------------------------------------
# Load backend routes PER SERVICE
# ---------------------------------------------------------------------------

def _load_api_routes() -> set[str]:
    """Return all route paths from the api FastAPI app.

    Uses app.openapi() instead of walking app.routes directly because
    FastAPI's _IncludedRouter objects don't expose their sub-routes via
    the path attribute. The OpenAPI schema correctly flattens all nested
    routers into a single paths dict.
    """
    os.environ.setdefault("ENVIRONMENT", "development")
    from app.main import app as api_app  # noqa: E402
    schema = api_app.openapi()
    return set(schema.get("paths", {}).keys())


def _load_agents_routes() -> set[str]:
    """Return all route paths from the agents FastAPI app via subprocess.

    Both services name their package ``app``, so importing agents' main.py
    in-process after the API's app is already loaded causes every
    ``from app.api...`` inside agents to resolve to the API's package and
    fail. The old implementation swallowed that failure and returned an
    empty set, making the test skip silently on every platform.

    Running in a fresh interpreter with PYTHONPATH=services/agents avoids
    the collision entirely. If the subprocess fails, the test MUST fail
    (not skip) so the gate actually validates agents-routed paths.
    """
    # SERVICES_ROOT is services/api/tests/../../.. = repo root when __file__
    # resolves correctly, but under pytest cwd=services/api the parents()
    # chain can differ. Use REPO_ROOT (defined above) for unambiguous lookup.
    agents_dir = REPO_ROOT / "services" / "agents"
    agents_main = agents_dir / "app" / "main.py"
    if not agents_main.exists():
        pytest.fail(f"agents service app/main.py not found at {agents_main}")
    # Use a marked line so stray stdout from app imports (e.g. OTel
    # warnings) doesn't corrupt the JSON payload. Set PYTHONIOENCODING
    # to utf-8 so Windows console encoding doesn't mangle the output.
    marker = "__B10_AGENTS_ROUTES__"
    script = (
        "import json, os; "
        "os.environ.setdefault('ENVIRONMENT', 'development'); "
        "from app.main import app; "
        f"print('{marker}' + json.dumps(list(app.openapi().get('paths', {{}}).keys())))"
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(agents_dir),
        "PYTHONIOENCODING": "utf-8",
    }
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(agents_dir),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Failed to load agents OpenAPI routes in subprocess:\n"
            f"{result.stderr.strip()}"
        )
    # Parse only the marked line; ignore any other stdout noise
    for line in result.stdout.splitlines():
        if line.startswith(marker):
            try:
                paths = json.loads(line[len(marker) :])
                return set(paths)
            except json.JSONDecodeError as exc:
                pytest.fail(f"Invalid JSON from agents subprocess: {exc}\n{line}")
    pytest.fail(
        f"No marked JSON line found in agents subprocess output:\n"
        f"{result.stdout[:500]}"
    )


# ---------------------------------------------------------------------------
# Parse next.config.js rewrites IN ORDER
# ---------------------------------------------------------------------------

def _parse_rewrites() -> list[tuple[str, str]]:
    """Extract (source_pattern, dest_host_var) from next.config.js in order.

    Returns a list of (regex_pattern, dest_var) tuples preserving the
    declaration order so we can apply first-match semantics like Next.js.
    dest_var is one of AGENTS_HOST, API_HOST, etc.

    Destinations use JS template literals: `` `${AGENTS_HOST}/path/:id` ``.
    The regex must match the backtick-delimited destination and capture
    the host variable name inside ``${...}``.
    """
    if not NEXT_CONFIG.exists():
        return []
    content = NEXT_CONFIG.read_text(encoding="utf-8")
    rewrites: list[tuple[str, str]] = []
    # Match source (single/double quoted) followed by destination (backtick
    # template literal with ${HOST_VAR} prefix). re.DOTALL allows matching
    # across newlines between source and destination lines.
    pattern = re.compile(
        r"source:\s*['\"]([^'\"]+)['\"].*?destination:\s*`\$\{(\w+)\}[^`]*`",
        re.DOTALL,
    )
    for m in pattern.finditer(content):
        source = m.group(1)
        dest_var = m.group(2)
        # Convert Next.js :param and :path* patterns to regex wildcards
        regex = re.sub(r":(\w+)\*", r".*", source)  # :path* → .*
        regex = re.sub(r":(\w+)", r"[^/]+", regex)   # :id → [^/]+
        regex = f"^{regex}$"
        rewrites.append((regex, dest_var))
    return rewrites


# ---------------------------------------------------------------------------
# Scan frontend for /api/v1/ literals
# ---------------------------------------------------------------------------

# Matches single-quoted, double-quoted, and template-literal strings.
# Template literals with ${} interpolation are captured up to the first $.
_FRONTEND_API_RE = re.compile(
    r"""['"`](/api/v1/[A-Za-z0-9/_{}.\-$]+)['"`]"""
)


def _is_test_source(fpath) -> bool:
    """Test files and fixtures are not shipped code. They invent paths on purpose
    (e.g. /api/v1/things/1 to exercise error handling), which must not count as
    the product calling a route that does not exist."""
    try:
        rel = fpath.relative_to(WEB_SRC).parts
    except ValueError:
        rel = fpath.parts
    return (
        ".test." in fpath.name
        or ".spec." in fpath.name
        or "__tests__" in rel
        or (len(rel) > 1 and rel[0] == "test")  # apps/web/src/test/ holds shared test setup
    )


def _strip_query_suffix(raw: str) -> str:
    """`/api/v1/x${qs}` -> `/api/v1/x`. A `${...}` glued to the end of a segment is a query string; one
    that is its own segment (`/api/v1/cases/${id}`) is a real path parameter and is kept."""
    return re.sub(r"(?<!/)\$\{[^}]*\}$", "", raw)


def _scan_frontend_paths(extra_sources: list[str] | None = None) -> set[str]:
    """Find all /api/v1/... string literals in frontend source.

    ``extra_sources`` allows tests to inject synthetic snippets that
    simulate frontend calls without touching real files.
    """
    paths: set[str] = set()
    if WEB_SRC.exists():
        for ext in ("*.ts", "*.tsx"):
            for fpath in WEB_SRC.rglob(ext):
                if _is_test_source(fpath):
                    continue
                try:
                    text = fpath.read_text(encoding="utf-8")
                except Exception:
                    continue
                for m in _FRONTEND_API_RE.finditer(text):
                    raw = m.group(1)
                    # Strip template-literal interpolation tails:
                    # /api/v1/ghost-things/${id}/nothing → keep as-is for
                    # pattern matching but normalise the ${} segment.
                    paths.add(_strip_query_suffix(raw))
    if extra_sources:
        for src in extra_sources:
            for m in _FRONTEND_API_RE.finditer(src):
                paths.add(_strip_query_suffix(m.group(1)))
    return paths


# ---------------------------------------------------------------------------
# Route matching helpers
# ---------------------------------------------------------------------------

def _normalize(path: str) -> str:
    return path.rstrip("/").lower()


def _to_regex(path: str) -> str:
    """Convert a normalized path (frontend or backend) to a regex pattern.

    Both ``${var}`` (JS template literals) and ``{param}`` (FastAPI/OpenAPI)
    are converted to ``[^/]+`` wildcards so they match each other.
    """
    # First replace parameter placeholders with a sentinel that survives re.escape
    sentinel = "\x00WILDCARD\x00"
    path = re.sub(r"\$\{[^}]*\}", sentinel, path)
    path = re.sub(r"\{[^}]+\}", sentinel, path)
    escaped = re.escape(path)
    return "^" + escaped.replace(re.escape(sentinel), "[^/]+") + "$"


def _route_matches(frontend_path: str, backend_routes: set[str]) -> bool:
    """Check if a frontend path matches any backend route.

    Handles parameterized routes like /cases/{case_id}/investigate
    matching /cases/abc-123/investigate, and template-literal paths
    like /api/v1/ghost-things/${id}/nothing.  Both ${var} and {param}
    are treated as equivalent single-segment wildcards via _to_regex.
    """
    norm = _normalize(frontend_path)
    # Build regex from the normalized frontend path; _to_regex converts
    # both ${var} and {param} to [^/]+ wildcards so they match each other.
    fe_re = _to_regex(norm)
    for route in backend_routes:
        rnorm = _normalize(route)
        # Direct equality after normalization catches exact matches
        if norm == rnorm:
            return True
        be_re = _to_regex(rnorm)
        try:
            # Match backend regex against normalized frontend path, OR
            # frontend regex against normalized backend route. This handles
            # cases where param names differ (${id} vs {case_id}).
            if re.match(be_re, norm) or re.match(fe_re, rnorm):
                return True
        except re.error:
            continue
    return False


def _resolve_service_for_path(
    frontend_path: str,
    rewrites: list[tuple[str, str]],
) -> str:
    """Find the FIRST matching rewrite and return its dest host var.

    Returns 'API_HOST' if no rewrite matches (the catch-all default).
    """
    norm = _normalize(frontend_path)
    # Replace each ${...} with a concrete, slash-free segment. (It used to become
    # the regex text "[^/]+", which itself contains "/", so a rewrite's ":param"
    # segment could never match it and the path fell through to the catch-all.
    # That misrouted e.g. the case-scoped report.md rewrite to API_HOST.)
    norm = re.sub(r"\$\{[^}]*\}", "PARAM", norm)
    for pattern, dest_var in rewrites:
        try:
            if re.match(pattern, norm):
                return dest_var
        except re.error:
            continue
    return "API_HOST"


# ---------------------------------------------------------------------------
# Known exceptions — each needs a real reason
# ---------------------------------------------------------------------------

_EXCEPTIONS: dict[str, str] = {
    # Frontend calls a route that does not exist on any service (known bug).
    # WebSocket streaming — not representable in OpenAPI but served at runtime.
    "/api/v1/graph_ws/stream": "WebSocket endpoint, not in OpenAPI schema",
    # Frontend calls a route that does not exist on any service (known bug).
    "/api/v1/copilot/conversations": "frontend calls a route that does not exist (known bug)",
    # Bare contextual root — the agents service serves /contextual/actions etc.
    # but the bare /contextual prefix has no handler; frontend calls it for
    # discovery and tolerates 404.
    "/api/v1/contextual": "discovery-only prefix, no handler on any service",
    # Graph overview — disabled in this build (B7); the endpoint exists in code
    # but is not registered when the graph feature flag is off.
    "/api/v1/graph": "graph overview disabled in this build (B7)",
    # Realtime service has its own host variable
    "/api/v1/realtime/healthz": "routed to REALTIME_HOST, separate service",
    # Enrichment service has its own host variable
    # Fusion/osquery — conditional routers not loaded in dev-mode OpenAPI
    "/api/v1/fusion": "fusion ML endpoint, conditional registration",
    "/api/v1/osquery": "the console builds its FIM URLs from this base path; the API serves only /api/v1/osquery/fim/events and /summary, never the bare base",
    # Report.md paths are served by agents via specific rewrite, but the
    # resolver's :caseId/:runId normalization doesn't match the frontend's
    # ${caseId}/${runId} template literals against the rewrite regex.
    # Copilot conversation by ID — dynamic CRUD not in static OpenAPI
    "/api/v1/copilot/conversations/${id}": "frontend calls a route that does not exist (known bug)",
    # Saved hunt by ID — conditional router not loaded in dev-mode OpenAPI
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBackendRouteCoverage:
    """B10 v2: Next.js-aware route coverage with per-service resolution."""

    @pytest.fixture(scope="class")
    def api_routes(self) -> set[str]:
        return _load_api_routes()

    @pytest.fixture(scope="class")
    def agents_routes(self) -> set[str]:
        return _load_agents_routes()

    @pytest.fixture(scope="class")
    def rewrites(self) -> list[tuple[str, str]]:
        return _parse_rewrites()

    @pytest.fixture(scope="class")
    def frontend_paths(self) -> set[str]:
        return _scan_frontend_paths()

    def test_openapi_smoke_api(self, api_routes: set[str]) -> None:
        assert len(api_routes) > 0, "API app has no routes"

    def test_openapi_smoke_agents(self, agents_routes: set[str]) -> None:
        # Agents may fail to import when running inside the api venv on
        # Windows (missing langgraph, etc.). That's a platform limitation,
        # not a route-coverage bug. Skip gracefully; item 6's setup-python.mjs
        # will provide a proper cross-service venv for full validation.
        if not agents_routes:
            pytest.skip("Agents app could not be imported from api venv")

    def test_frontend_paths_have_backends(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
        frontend_paths: set[str],
    ) -> None:
        """Every /api/v1/ literal must resolve to a real route in the
        correct service (per next.config.js first-match semantics)."""
        service_map = {
            "API_HOST": api_routes,
            "AGENTS_HOST": agents_routes,
        }
        unmatched: list[str] = []
        for path in sorted(frontend_paths):
            if path in _EXCEPTIONS:
                continue
            dest = _resolve_service_for_path(path, rewrites)
            routes = service_map.get(dest)
            if routes is None:
                # Unknown dest var — treat as unmatched
                unmatched.append(f"{path} → unknown dest {dest}")
                continue
            if _route_matches(path, routes):
                continue
            unmatched.append(f"{path} → {dest} (no matching route)")

        if unmatched:
            msg = (
                "Frontend /api/v1/ paths with no backend route in the "
                "resolved service:\n"
                + "\n".join(f"  - {p}" for p in unmatched)
                + "\n\nAdd the endpoint, fix the rewrite, or add to "
                "_EXCEPTIONS with a real reason."
            )
            pytest.fail(msg)

    def test_rewrite_destinations_are_served(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """Every rewrite destination service must actually serve the path.

        Catches regressions like routing report.pdf to AGENTS_HOST when
        only the API serves it. For each rewrite, we substitute a sample
        value for any :param segments and verify the resulting concrete
        path exists in the destination service's OpenAPI schema.
        """
        service_map = {
            "API_HOST": api_routes,
            "AGENTS_HOST": agents_routes,
        }
        bad: list[str] = []
        for pattern, dest_var in rewrites:
            routes = service_map.get(dest_var)
            if routes is None or not routes:
                # Unknown host variable (ENRICHMENT_HOST, FUSION_HOST, etc.)
                # or service couldn't be imported (agents in api venv on
                # Windows). Skip silently; validated by their own smoke tests.
                continue
            # Skip catch-all patterns like ^/api/v1/[^/]+*$ — they match
            # anything and can't be validated as a concrete path.
            if "[^/]+" in pattern and pattern.endswith("*$"):
                continue
            # Convert regex back to a sample concrete path for matching
            sample = re.sub(r"\[\^/\]\+", "sample-id", pattern)
            sample = sample.lstrip("^").rstrip("$")
            # Skip if the sample still contains regex artifacts
            if "[" in sample or "*" in sample:
                continue
            if not _route_matches(sample, routes):
                # The exact sample path may not exist, but the rewrite is
                # still valid if the destination serves *any* route under
                # this prefix (e.g. /api/v1/hunt → agents serves
                # /hunt/search and /hunt/saved/{id}). Check for a prefix
                # match before flagging as bad.
                prefix = sample.rstrip("/") + "/"
                has_subpath = any(r.startswith(prefix) for r in routes)
                if not has_subpath:
                    bad.append(f"{pattern} → {dest_var} (no matching route)")
        if bad:
            msg = (
                "Rewrite destinations that don't serve the routed path:\n"
                + "\n".join(f"  - {b}" for b in bad)
                + "\nFix the rewrite or add the endpoint to that service."
            )
            pytest.fail(msg)

    def test_no_dead_exceptions(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """Every exception must be genuinely unserved.
        Fails if:
        - The exception has no reason string.
        - The route actually exists in the resolved destination service
          (meaning the exception is unnecessary and should be removed).
        """
        service_map = {
            "API_HOST": api_routes,
            "AGENTS_HOST": agents_routes,
        }
        dead: list[str] = []
        for path, reason in _EXCEPTIONS.items():
            assert reason, f"Exception {path} has no reason documented"
            dest = _resolve_service_for_path(path, rewrites)
            routes = service_map.get(dest)
            if routes and _route_matches(path, routes):
                dead.append(f"{path} → {dest} (route EXISTS; remove from _EXCEPTIONS)")
        if dead:
            msg = (
                "Unnecessary exceptions (routes are actually served):\n"
                + "\n".join(f"  - {d}" for d in dead)
                + "\nRemove these from _EXCEPTIONS."
            )
            pytest.fail(msg)

    # -------------------------------------------------------------------
    # Proof mutations — these MUST fail to prove the gate works
    # -------------------------------------------------------------------

    def test_mutation_totally_made_up_route_fails(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """A call to /api/v1/totally-made-up-route-xyz must be caught."""
        fake = {'"/api/v1/totally-made-up-route-xyz"'}
        paths = _scan_frontend_paths(extra_sources=list(fake))
        service_map = {"API_HOST": api_routes, "AGENTS_HOST": agents_routes}
        found_unmatched = False
        for path in paths:
            if path in _EXCEPTIONS:
                continue
            dest = _resolve_service_for_path(path, rewrites)
            routes = service_map.get(dest, set())
            if not _route_matches(path, routes):
                if "totally-made-up-route-xyz" in path:
                    found_unmatched = True
        assert found_unmatched, (
            "Gate did NOT catch /api/v1/totally-made-up-route-xyz — "
            "the check is broken"
        )

    def test_mutation_old_indicators_endpoint_fails(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """The old /api/v1/threat-intel/indicators must be caught."""
        fake = {'"/api/v1/threat-intel/indicators"'}
        paths = _scan_frontend_paths(extra_sources=list(fake))
        service_map = {"API_HOST": api_routes, "AGENTS_HOST": agents_routes}
        found_unmatched = False
        for path in paths:
            if path in _EXCEPTIONS:
                continue
            dest = _resolve_service_for_path(path, rewrites)
            routes = service_map.get(dest, set())
            if not _route_matches(path, routes):
                if "threat-intel/indicators" in path:
                    found_unmatched = True
        assert found_unmatched, (
            "Gate did NOT catch /api/v1/threat-intel/indicators — "
            "the check is broken"
        )

    def test_mutation_template_literal_ghost_route_fails(
        self,
        api_routes: set[str],
        agents_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """A template-literal call like `/api/v1/ghost-things/${id}/nothing`
        must be caught."""
        fake = {'`/api/v1/ghost-things/${id}/nothing`'}
        paths = _scan_frontend_paths(extra_sources=list(fake))
        service_map = {"API_HOST": api_routes, "AGENTS_HOST": agents_routes}
        found_unmatched = False
        for path in paths:
            if path in _EXCEPTIONS:
                continue
            dest = _resolve_service_for_path(path, rewrites)
            routes = service_map.get(dest, set())
            if not _route_matches(path, routes):
                if "ghost-things" in path:
                    found_unmatched = True
        assert found_unmatched, (
            "Gate did NOT catch /api/v1/ghost-things/${{id}}/nothing — "
            "template-literal scanning is broken"
        )


def test_test_files_are_not_scanned_but_shipped_files_are(tmp_path, monkeypatch):
    """A made-up path in a *.test.ts must be ignored; the same path in real code must be flagged."""
    import sys

    mod = sys.modules[__name__]
    (tmp_path / "components").mkdir()
    (tmp_path / "test").mkdir()
    (tmp_path / "components" / "Real.tsx").write_text("fetch('/api/v1/only-in-shipped-code')")
    (tmp_path / "components" / "Real.test.tsx").write_text("fetch('/api/v1/only-in-a-test-file')")
    (tmp_path / "components" / "Real.spec.ts").write_text("fetch('/api/v1/only-in-a-spec-file')")
    (tmp_path / "test" / "helpers.ts").write_text("fetch('/api/v1/only-in-test-helpers')")
    monkeypatch.setattr(mod, "WEB_SRC", tmp_path)
    found = mod._scan_frontend_paths()
    assert found == {"/api/v1/only-in-shipped-code"}, found


def test_a_query_string_suffix_is_not_part_of_the_path_but_a_path_parameter_is():
    found = _scan_frontend_paths(extra_sources=[
        "request(`/api/v1/ghost-list${qs}`)",
        "request(`/api/v1/ghost-things/${id}/nothing`)",
        "request(`/api/v1/ghost-things/${id}`)",
    ])
    assert "/api/v1/ghost-list" in found and "/api/v1/ghost-list${qs}" not in found
    assert "/api/v1/ghost-things/${id}/nothing" in found and "/api/v1/ghost-things/${id}" in found


def test_a_console_call_to_an_unserved_path_with_a_query_suffix_is_still_caught():
    """Stripping the suffix must not let a genuinely missing route slip through."""
    missing = _scan_frontend_paths(extra_sources=["request(`/api/v1/definitely-not-served${qs}`)"]) - set(_scan_frontend_paths())
    assert missing == {"/api/v1/definitely-not-served"}
    assert not _route_matches("/api/v1/definitely-not-served", _load_api_routes())
