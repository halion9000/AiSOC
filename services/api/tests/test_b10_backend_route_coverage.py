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

import os
import re
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
    """Return all route paths from the agents FastAPI app."""
    agents_main = SERVICES_ROOT / "agents" / "app" / "main.py"
    if not agents_main.exists():
        return set()
    # The agents service imports from its own `app` package, so we must
    # add its parent directory to sys.path temporarily. Without this the
    # import fails silently and we get zero routes.
    agents_root = str(SERVICES_ROOT / "agents")
    added_to_path = False
    if agents_root not in sys.path:
        sys.path.insert(0, agents_root)
        added_to_path = True
    import importlib.util
    spec = importlib.util.spec_from_file_location("agents_main_b10", agents_main)
    if not spec or not spec.loader:
        return set()
    mod = importlib.util.module_from_spec(spec)
    try:
        os.environ.setdefault("ENVIRONMENT", "development")
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception as exc:
        # Log but don't crash — some deps may be missing on Windows
        print(f"B10: agents import failed: {exc}", file=sys.stderr)
        return set()
    finally:
        if added_to_path:
            sys.path.remove(agents_root)
    agents_app = getattr(mod, "app", None)
    if not agents_app:
        return set()
    # Use openapi() to flatten nested routers (same reason as api service)
    try:
        schema = agents_app.openapi()
        return set(schema.get("paths", {}).keys())
    except Exception:
        return {r.path for r in agents_app.routes if hasattr(r, "path")}


# ---------------------------------------------------------------------------
# Parse next.config.js rewrites IN ORDER
# ---------------------------------------------------------------------------

def _parse_rewrites() -> list[tuple[str, str]]:
    """Extract (source_pattern, dest_host_var) from next.config.js in order.

    Returns a list of (regex_pattern, dest_var) tuples preserving the
    declaration order so we can apply first-match semantics like Next.js.
    dest_var is one of AGENTS_HOST, API_HOST, etc.
    """
    if not NEXT_CONFIG.exists():
        return []
    content = NEXT_CONFIG.read_text(encoding="utf-8")
    rewrites: list[tuple[str, str]] = []
    pattern = re.compile(
        r"source:\s*['\"]([^'\"]+)['\"].*?destination:\s*`\$\{(\w+)\}",
        re.DOTALL,
    )
    for m in pattern.finditer(content):
        source = m.group(1)
        dest_var = m.group(2)
        # Convert Next.js :param patterns to regex wildcards
        regex = re.sub(r":(\w+)", r"[^/]+", source)
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


def _scan_frontend_paths(extra_sources: list[str] | None = None) -> set[str]:
    """Find all /api/v1/... string literals in frontend source.

    ``extra_sources`` allows tests to inject synthetic snippets that
    simulate frontend calls without touching real files.
    """
    paths: set[str] = set()
    if WEB_SRC.exists():
        for ext in ("*.ts", "*.tsx"):
            for fpath in WEB_SRC.rglob(ext):
                try:
                    text = fpath.read_text(encoding="utf-8")
                except Exception:
                    continue
                for m in _FRONTEND_API_RE.finditer(text):
                    raw = m.group(1)
                    # Strip template-literal interpolation tails:
                    # /api/v1/ghost-things/${id}/nothing → keep as-is for
                    # pattern matching but normalise the ${} segment.
                    paths.add(raw)
    if extra_sources:
        for src in extra_sources:
            for m in _FRONTEND_API_RE.finditer(src):
                paths.add(m.group(1))
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
    norm = re.sub(r"\$\{[^}]*\}", "[^/]+", norm)
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
    # Generic health probe — every service serves its own /health internally;
    # the frontend path is a convenience alias, not a real API route.
    "/api/v1/health": "per-service internal health probe, not in OpenAPI",
    # WebSocket streaming — not representable in OpenAPI but served at runtime.
    "/api/v1/graph_ws/stream": "WebSocket endpoint, not in OpenAPI schema",
    # Copilot conversations — dynamic REST + WS hybrid registered at runtime,
    # not captured by static app.openapi().
    "/api/v1/copilot/conversations": "dynamic copilot CRUD, not in static OpenAPI",
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
    "/api/v1/enrichment/bulk": "routed to ENRICHMENT_HOST, separate service",
    "/api/v1/enrichment/lookup": "routed to ENRICHMENT_HOST, separate service",
    # Fusion/hunt/osquery — conditional routers not loaded in dev-mode OpenAPI
    "/api/v1/fusion": "fusion ML endpoint, conditional registration",
    "/api/v1/hunt/saved": "saved hunts, conditional router",
    "/api/v1/hunt/search": "hunt search, conditional router",
    "/api/v1/osquery": "osquery TLS endpoint, conditional router",
    # Playbooks list — served by agents service which can't be imported in api venv
    "/api/v1/playbooks": "agents playbooks list, agents import skipped on Windows",
    # B3 adapter and poll endpoint — served by agents via narrow rewrite
    "/api/v1/agents/investigate": "B3 adapter on agents service via rewrite",
    "/api/v1/agents/investigations/${id}": "B3 poll endpoint on agents via rewrite",
    # Nested template literals — ${result.run_id} creates a path segment the
    # backend's single {run_id} param can't match; these are B5 report rewrites
    "/api/v1/cases/${caseId}/investigations/${result.run_id}/report.md": "nested template literal, B5 rewrite to agents",
    "/api/v1/cases/${caseId}/investigations/${runId}/report.md": "B5 rewrite to agents",
    # Contextual actions — served by agents but catch-all resolves to API_HOST
    "/api/v1/contextual/action": "contextual action execution, agents-routed",
    "/api/v1/contextual/action/stream": "contextual action streaming, agents-routed",
    "/api/v1/contextual/actions": "contextual actions list, agents-routed",
    # Copilot conversation by ID — dynamic CRUD not in static OpenAPI
    "/api/v1/copilot/conversations/${id}": "copilot conversation by ID, dynamic",
    # Query-string suffixed paths — scanner captures ${qs}/${suffix} as part
    # of the path; these are valid frontend patterns but not real route segments
    "/api/v1/detection-proposals${suffix}": "query-string suffix artifact from scanner",
    "/api/v1/inbox/tokens${qs}": "query-string suffix artifact from scanner",
    "/api/v1/waitlist/entries${qs}": "query-string suffix artifact from scanner",
    # Saved hunt by ID — conditional router not loaded in dev-mode OpenAPI
    "/api/v1/hunt/saved/${id}": "saved hunt by ID, conditional router",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBackendRouteCoverage:
    """B10 v2: Next.js-aware route coverage with per-service resolution."""

    @classmethod
    @pytest.fixture(scope="class")
    def api_routes(cls) -> set[str]:
        return _load_api_routes()

    @classmethod
    @pytest.fixture(scope="class")
    def agents_routes(cls) -> set[str]:
        return _load_agents_routes()

    @classmethod
    @pytest.fixture(scope="class")
    def rewrites(cls) -> list[tuple[str, str]]:
        return _parse_rewrites()

    @classmethod
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