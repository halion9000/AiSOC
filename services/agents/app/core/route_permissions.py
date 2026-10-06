"""Which permission does a request to the agents service need?

The web console talks to this service DIRECTLY for playbooks, hunts, contextual
actions and investigations (see apps/web/next.config.js), so the API's own checks
never see those requests. This table is how the agents service authorizes them;
the answer ("may this caller do X?") comes from the API, which owns the role
table. Permission names are the API's (core/security.py ROLE_PERMISSIONS).

First matching rule wins. Methods None means any method. A request that matches
no rule needs a valid login but no particular permission (as before).
Calls carrying the internal token skip this: the API already authorized the user.
"""
import re

_WRITE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ANY = None

RULES: list[tuple[re.Pattern[str], frozenset[str] | None, str]] = [
    # playbooks
    (re.compile(r"^/api/v1/playbooks/draft-from-nl$"), frozenset({"POST"}), "playbooks:write"),
    (re.compile(r"^/api/v1/playbooks/[^/]+/run$"), frozenset({"POST"}), "playbooks:execute"),
    (re.compile(r"^/api/v1/playbooks(/runs(/[^/]+)?|/[^/]+)?$"), frozenset({"GET"}), "playbooks:read"),
    (re.compile(r"^/api/v1/playbooks(/[^/]+)?$"), _WRITE, "playbooks:write"),
    # hunting: querying the data lake
    (re.compile(r"^/api/v1/hunt-corpus/reload$"), frozenset({"POST"}), "settings:write"),
    (re.compile(r"^/api/v1/hunt(-corpus)?(/.*)?$"), _ANY, "lake:query"),
    # contextual helpers (explain / summarize / draft): anyone who can read alerts
    (re.compile(r"^/api/v1/contextual(/.*)?$"), _ANY, "alerts:read"),
    # investigations
    (re.compile(r"^/api/v1/agents/investigate$"), frozenset({"POST"}), "cases:write"),
    (re.compile(r"^/api/v1/agents/investigations/[^/]+$"), frozenset({"GET"}), "cases:read"),
    (re.compile(r"^/api/v1/cases/[^/]+/investigate$"), frozenset({"POST"}), "cases:write"),
    (re.compile(r"^/api/v1/cases/[^/]+/triage$"), frozenset({"POST"}), "cases:write"),
    (re.compile(r"^/api/v1/cases/[^/]+/investigations(/.*)?$"), frozenset({"GET"}), "cases:read"),
    (re.compile(r"^/api/v1/investigations(/.*)?$"), frozenset({"GET"}), "cases:read"),
    (re.compile(r"^/api/v1/investigations(/.*)?$"), _WRITE, "cases:write"),
]

# Path prefixes the console routes straight to this service. Every route this
# service serves under them MUST be covered by a rule (tested).
CONSOLE_FACING_PREFIXES = (
    "/api/v1/playbooks",
    "/api/v1/hunt",
    "/api/v1/contextual",
    "/api/v1/agents/investigate",
    "/api/v1/agents/investigations",
    "/api/v1/cases/",
    "/api/v1/investigations",
)


def required_permission(method: str, path: str) -> str | None:
    method = (method or "GET").upper()
    for pattern, methods, permission in RULES:
        if pattern.match(path) and (methods is None or method in methods):
            return permission
    return None
