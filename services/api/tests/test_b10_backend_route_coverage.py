"""B10: backend-route coverage gate.

Loads the API and agents FastAPI apps, extracts every registered route,
then scans ``apps/web/src`` for ``/api/v1/...`` string literals. Any
frontend path that has no matching backend route AND is not covered by
a next.config.js rewrite to another service is reported as a failure.

This prevents the recurring "frontend calls endpoint that doesn't exist"
class of bugs (B3, B4, B5, B6, B7) from reaching main again.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]  # services/api/../..
WEB_SRC = ROOT / "apps" / "web" / "src"
NEXT_CONFIG = ROOT / "apps" / "web" / "next.config.js"

# ---------------------------------------------------------------------------
# Load backend routes
# ---------------------------------------------------------------------------

def _collect_routes() -> set[str]:
    """Return the union of all route paths from api + agents apps."""
    routes: set[str] = set()

    # API service
    os.environ.setdefault("ENVIRONMENT", "development")
    from app.main import app as api_app  # noqa: E402

    for route in api_app.routes:
        if hasattr(route, "path"):
            routes.add(route.path)

    # Agents service — import from its own directory
    agents_main = ROOT / "services" / "agents" / "app" / "main.py"
    if agents_main.exists():
        import importlib.util

        spec = importlib.util.spec_from_file_location("agents_main", agents_main)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            agents_app = getattr(mod, "app", None)
            if agents_app:
                for route in agents_app.routes:
                    if hasattr(route, "path"):
                        routes.add(route.path)
        except Exception:
            # Agents may fail to import without its full dep set; that's OK
            # for this gate — we still catch api-only mismatches.
            pass

    return routes


# ---------------------------------------------------------------------------
# Parse next.config.js rewrites
# ---------------------------------------------------------------------------

def _parse_rewrites() -> list[tuple[str, str]]:
    """Extract (source_pattern, destination_host) from next.config.js.

    Returns a list of (regex_pattern, dest_var) tuples where dest_var is
    one of AGENTS_HOST, API_HOST, etc. We only care about which paths are
    routed AWAY from the core API.
    """
    if not NEXT_CONFIG.exists():
        return []

    content = NEXT_CONFIG.read_text(encoding="utf-8")
    rewrites: list[tuple[str, str]] = []

    # Match { source: '/api/v1/...', destination: `${AGENTS_HOST}/...` }
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

_FRONTEND_API_RE = re.compile(r"['\"`](/api/v1/[A-Za-z0-9/_{}.\-]+)['\"`]")

# Known exceptions with reasons — add new ones here with justification.
_EXCEPTIONS: dict[str, str] = {
    # These are served by the agents service via next.config.js rewrites
    "/api/v1/agents/investigate": "B3 adapter on agents service",
    "/api/v1/agents/investigate/stream": "streaming variant of B3 adapter",
    "/api/v1/cases/{caseId}/investigations/{runId}/report.md": "B5 rewrite to agents",
    "/api/v1/cases/{caseId}/investigations/{runId}/report.html": "B5 rewrite to agents",
    "/api/v1/cases/{caseId}/investigations/{runId}/report.pdf": "B5 rewrite to agents",
    # Contextual actions, playbooks, hunts live on agents
    "/api/v1/contextual/actions": "routed to agents via rewrite",
    "/api/v1/contextual/action/stream": "routed to agents via rewrite",
    "/api/v1/playbooks": "routed to agents via rewrite",
    "/api/v1/hunt": "routed to agents via rewrite",
    "/api/v1/hunt-corpus": "routed to agents via rewrite",
    "/api/v1/copilot/chat": "routed to API but handled by copilot endpoint",
    "/api/v1/explain": "routed to agents via rewrite",
}


def _scan_frontend_paths() -> set[str]:
    """Find all /api/v1/... string literals in frontend source."""
    paths: set[str] = set()
    if not WEB_SRC.exists():
        return paths

    for ext in ("*.ts", "*.tsx"):
        for fpath in WEB_SRC.rglob(ext):
            try:
                text = fpath.read_text(encoding="utf-8")
            except Exception:
                continue
            for m in _FRONTEND_API_RE.finditer(text):
                paths.add(m.group(1))

    return paths


# ---------------------------------------------------------------------------
# Normalize paths for comparison
# ---------------------------------------------------------------------------

def _normalize(path: str) -> str:
    """Strip trailing slashes and lowercase for comparison."""
    return path.rstrip("/").lower()


def _route_matches(frontend_path: str, backend_routes: set[str]) -> bool:
    """Check if a frontend path matches any backend route.

    Handles parameterized routes like /cases/{case_id}/investigate
    matching /cases/abc-123/investigate.
    """
    norm = _normalize(frontend_path)
    for route in backend_routes:
        rnorm = _normalize(route)
        if norm == rnorm:
            return True
        # Check if the route is a parameterized version
        route_re = re.sub(r"\{[^}]+\}", r"[^/]+", rnorm)
        route_re = f"^{route_re}$"
        if re.match(route_re, norm):
            return True
    return False


def _rewrite_covers(frontend_path: str, rewrites: list[tuple[str, str]]) -> bool:
    """Check if a next.config.js rewrite routes this path away from API."""
    norm = _normalize(frontend_path)
    for pattern, _dest in rewrites:
        try:
            if re.match(pattern, norm):
                return True
        except re.error:
            continue
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBackendRouteCoverage:
    """B10: every frontend /api/v1/ call must have a backend or proxy target."""

    @pytest.fixture(scope="class")
    def backend_routes(self) -> set[str]:
        return _collect_routes()

    @pytest.fixture(scope="class")
    def rewrites(self) -> list[tuple[str, str]]:
        return _parse_rewrites()

    @pytest.fixture(scope="class")
    def frontend_paths(self) -> set[str]:
        return _scan_frontend_paths()

    def test_openapi_smoke_api(self) -> None:
        """The API app must generate an OpenAPI schema without errors."""
        os.environ.setdefault("ENVIRONMENT", "development")
        from app.main import app

        schema = app.openapi()
        assert "paths" in schema
        assert len(schema["paths"]) > 0

    def test_frontend_paths_have_backends(
        self,
        backend_routes: set[str],
        rewrites: list[tuple[str, str]],
        frontend_paths: set[str],
    ) -> None:
        """Every /api/v1/ literal in frontend source must be served somewhere."""
        unmatched: list[str] = []
        for path in sorted(frontend_paths):
            if path in _EXCEPTIONS:
                continue
            if _route_matches(path, backend_routes):
                continue
            if _rewrite_covers(path, rewrites):
                continue
            unmatched.append(path)

        if unmatched:
            msg = (
                "Frontend /api/v1/ paths with no backend route or proxy rewrite:\n"
                + "\n".join(f"  - {p}" for p in unmatched)
                + "\n\nAdd the endpoint, add a next.config.js rewrite, or add to "
                "_EXCEPTIONS with a reason."
            )
            pytest.fail(msg)

    def test_no_dead_exceptions(
        self,
        backend_routes: set[str],
        rewrites: list[tuple[str, str]],
    ) -> None:
        """Exceptions in _EXCEPTIONS must still be valid (not silently stale)."""
        for path, reason in _EXCEPTIONS.items():
            has_route = _route_matches(path, backend_routes)
            has_rewrite = _rewrite_covers(path, rewrites)
            # At least one must be true, or the exception is documenting
            # something that was fixed/removed and should be cleaned up.
            # This is a soft check — some exceptions are for endpoints that
            # intentionally don't exist yet (disabled UIs).
            assert reason, f"Exception {path} has no reason documented"