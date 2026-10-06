"""B11: every console call uses an HTTP METHOD the API actually serves for that path.

B10 checks that the path a console call uses exists. It cannot see a console that calls a
REAL path with the WRONG method or body, which is exactly how the IOC lookup stayed broken:
GET /enrichment/lookup?ioc= was sent to an endpoint that only accepts POST. A feature like
that fails silently ("not found" in the UI) and looks like a data problem.

For each console call to /api/v1/... that the API serves (rewrites to other services are not
checked here), this finds the call's OWN options object (by matching its parentheses, so the
next call's `method:` is never borrowed) and requires that method on a matching route.
Paths the API does not serve at all are B10's job and are skipped here.
"""
import re

from app.main import app
from test_b10_backend_route_coverage import (
    WEB_SRC,
    _is_test_source,
    _normalize,
    _parse_rewrites,
    _resolve_service_for_path,
    _to_regex,
)

_CALL = re.compile(r"(?:request(?:<(?:[^<>]|<[^<>]*>)*>)?|authFetch)\(\s*([`'\"])(/api/v1/[^`'\"]*)\1")
_METHOD = re.compile(r"method:\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]")
_HTTP = ("get", "post", "put", "patch", "delete")


def _call_span(text: str, open_idx: int) -> str:
    """The text of the call whose '(' is at open_idx, honouring quotes and template literals."""
    depth, i, quote = 0, open_idx, None
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1]
        i += 1
    return text[open_idx : open_idx + 400]


def console_calls(sources: list[tuple[str, str]]) -> list[tuple[str, int, str, str]]:
    """(file, line, METHOD, path) for every console call with a literal /api/v1 path."""
    out = []
    for name, text in sources:
        for m in _CALL.finditer(text):
            path = m.group(2).split("?")[0]
            path = re.sub(r"(?<!/)\$\{[^}]*\}$", "", path)  # `/x${qs}` is a query string, not a path segment
            method_match = _METHOD.search(_call_span(text, text.index("(", m.start())))
            out.append((name, text[: m.start()].count("\n") + 1, method_match.group(1) if method_match else "GET", path.rstrip("/")))
    return out


def _served() -> dict[str, set[str]]:
    served: dict[str, set[str]] = {}
    for path, ops in app.openapi()["paths"].items():
        served.setdefault(_normalize(path), set()).update(m.upper() for m in ops if m in _HTTP)
    return served


def find_method_mismatches(calls, served, rewrites) -> list[str]:
    problems = []
    for name, line, method, path in calls:
        if _resolve_service_for_path(path, rewrites) != "API_HOST":
            continue  # goes to another service; that service's routes are not in this schema
        norm = _normalize(path)
        regex = _to_regex(norm)
        methods = set()
        for template, ms in served.items():
            if norm == template or re.match(_to_regex(template), norm) or re.match(regex, template):
                methods |= ms
        if methods and method not in methods:
            problems.append(f"{name}:{line}  {method} {path}   (the API serves {sorted(methods)} here)")
    return sorted(set(problems))


def _web_sources() -> list[tuple[str, str]]:
    out = []
    for ext in ("*.ts", "*.tsx"):
        for f in WEB_SRC.rglob(ext):
            if not _is_test_source(f):
                out.append((str(f.relative_to(WEB_SRC)), f.read_text(encoding="utf-8", errors="replace")))
    return out


def test_every_console_call_uses_a_method_the_api_serves():
    sources = _web_sources()
    calls = console_calls(sources)
    assert len(calls) > 120, "the scan found almost no console calls: the detector is broken, not the console fixed"
    problems = find_method_mismatches(calls, _served(), _parse_rewrites())
    assert not problems, "console calls whose HTTP method the API does not serve for that path:\n  " + "\n  ".join(problems)


# ----------------------------------------------------------------- the detector itself ----
def _check(snippet: str) -> list[str]:
    return find_method_mismatches(console_calls([("x.ts", snippet)]), _served(), _parse_rewrites())


def test_flags_the_enrichment_bug_as_it_was():
    """/enrichment/lookup is GET-only; the console POSTed (and the service behind it only took POST)."""
    assert len(_check("request('/api/v1/enrichment/lookup', { method: 'POST', body: '{}' })")) == 1


def test_flags_a_wrong_method_on_a_templated_path():
    assert len(_check("request(`/api/v1/cases/${id}/timeline`, { method: 'POST' })")) == 1


def test_accepts_correct_calls_including_the_default_get():
    ok = [
        "request('/api/v1/enrichment/lookup', { params: { ioc } })",
        "request('/api/v1/enrichment/bulk', { method: 'POST', body: '{}' })",
        "request(`/api/v1/cases/${id}/timeline`)",
        "request<Foo>(`/api/v1/cases/${id}/tasks`, { method: 'POST', body: JSON.stringify(t) })",
    ]
    for snippet in ok:
        assert _check(snippet) == [], snippet


def test_never_borrows_the_next_calls_method():
    """The mistake my first audit made: a GET followed by a POST must not be reported as a POST."""
    snippet = (
        "const a = () => request('/api/v1/enrichment/lookup');\n"
        "const b = () => request('/api/v1/enrichment/bulk', { method: 'POST', body: '{}' });\n"
    )
    assert _check(snippet) == []


def test_a_query_string_suffix_is_not_a_path_segment():
    assert console_calls([("x.ts", "request(`/api/v1/enrichment/lookup${qs}`)")])[0][3] == "/api/v1/enrichment/lookup"


def test_paths_the_api_does_not_serve_are_left_to_b10():
    assert _check("request('/api/v1/definitely-not-a-route', { method: 'POST' })") == []


def test_calls_routed_to_other_services_are_not_checked_against_this_api():
    assert _check("request('/api/v1/playbooks', { method: 'POST' })") == []
