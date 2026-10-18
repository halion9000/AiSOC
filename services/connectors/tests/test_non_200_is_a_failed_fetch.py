"""A non-200 answer while polling is a failed fetch, not an empty one.

Connectors swallow their fetch errors and return []. Without ``_fetch_failed()`` the scheduler cannot tell a revoked key (401) or a rate limit (429) from a quiet source, and the
connection shows healthy while nothing is collected. Every ``status != 200`` branch in the polling path must record the failure.
"""

from __future__ import annotations

import ast
import pathlib

_POLLING = {"fetch_alerts", "_paginate", "_paginate_offset", "_paginate_cursor", "_fetch_logs", "_fetch_events", "_bearer", "_login", "_refresh_token"}
_DIR = pathlib.Path(__file__).resolve().parent.parent / "app" / "connectors"


def _non_200_branches(tree: ast.AST):
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) and fn.name in _POLLING:
            for n in ast.walk(fn):
                t = n.test if isinstance(n, ast.If) else None
                if (
                    isinstance(t, ast.Compare)
                    and isinstance(t.left, ast.Attribute)
                    and t.left.attr in ("status_code", "status")
                    and isinstance(t.ops[0], ast.NotEq)
                    and getattr(t.comparators[0], "value", None) == 200
                ):
                    yield fn.name, n


def test_every_non_200_branch_in_the_polling_path_records_the_failure():
    missing = []
    for path in sorted(_DIR.glob("*.py")):
        for name, node in _non_200_branches(ast.parse(path.read_text(encoding="utf-8"))):
            if not any("_fetch_failed" in ast.dump(stmt) for stmt in node.body):
                missing.append(f"{path.name}:{node.lineno} in {name}")
    assert not missing, "non-200 treated as an empty poll: " + ", ".join(missing)
