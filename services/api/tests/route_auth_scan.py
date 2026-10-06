"""Static scan: which API routes enforce no authorization at all?

A route counts as guarded when it declares Depends(require_permission("x")) or its
BODY (comments and docstring excluded) contains a guard-style call (require_*,
ensure_*, assert_*, check_*, ...), a role comparison, or has_permission. This is
a heuristic safety net, not proof of correctness: it exists so that a NEW route
cannot quietly ship with a login check only.
"""
import ast
import glob
import os
import re

ENDPOINTS = os.path.join(os.path.dirname(__file__), "..", "app", "api", "v1", "endpoints")
GUARD = re.compile(
    r"\b_?(require|ensure|assert|check|verify|authorize|enforce|guard)_?\w*\s*\(|\.require_permission|has_permission"
    r"|\brole\s*(==|!=|in|not in)|platform_admin|is_admin|\.role\b",
    re.I,
)
METHODS = ("get", "post", "put", "patch", "delete")


def unguarded_routes() -> list[str]:
    out = []
    for path in sorted(glob.glob(os.path.join(ENDPOINTS, "*.py"))):
        src = open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        prefix = ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and getattr(node.value.func, "id", "") == "APIRouter":
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = kw.value.value
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for dec in fn.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in METHODS and getattr(dec.func.value, "id", "") == "router"):
                    continue
                route = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else ""
                header = ast.get_source_segment(src, fn) or ""
                header = header.partition(":\n")[0]
                decorator = ast.get_source_segment(src, dec) or ""   # dependencies=[Depends(require_permission(...))] lives here
                declared = bool(re.search(r'require_permission\(\s*["\']', header)) or bool(re.search(r'require_permission\(\s*["\']', decorator))
                body = fn.body[1:] if fn.body and isinstance(fn.body[0], ast.Expr) and isinstance(getattr(fn.body[0], "value", None), ast.Constant) else fn.body
                inline = bool(GUARD.search("\n".join(ast.unparse(b) for b in body)))
                if not declared and not inline:
                    out.append(f"{dec.func.attr.upper()} {prefix}{route} [{os.path.basename(path)}::{fn.name}]")
    return sorted(set(out))
