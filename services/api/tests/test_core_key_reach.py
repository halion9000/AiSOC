"""A ratchet on what CORE's API key can WRITE (or otherwise do) beyond Cipher's tools.

An audit of every non-read route CORE's real key scopes can reach found 27, of which Cipher's tools call 7, and several of the other 20 were serious: the key could approve its own approval, publish an investigation to a public link, run a rule backtest that returns data-lake rows, search the tenant's connected SIEMs, and create assets, posture findings, identity nodes and insider-threat indicators. Each was closed by a narrow permission or a signed-in-session requirement.
This test pins what REMAINS, exactly. It is computed from the routes themselves with the same function every check uses, so it needs no network and no database. If a route is added that a scope the key holds guards, or a scope is added to the key, this fails until the new route is added below WITH A REASON: the point is that the key's reach is never widened silently.
"""
from route_introspect import required_permissions as _required_permissions
from route_introspect import walk_routes

from app.api.v1.deps import require_signed_in_session
from app.core.security import permission_in
from app.main import app
from app.scripts import bootstrap_production as bp

# What Cipher's tools call (hand-written write tools). Each is a deliberate capability.
USED_BY_A_TOOL = {
    ("POST", "/alerts/{alert_id}/claim"), ("POST", "/alerts/{alert_id}/escalate"), ("POST", "/alerts/{alert_id}/snooze"),
    ("PATCH", "/cases/{case_id}"), ("POST", "/cases/{case_id}/comments"), ("POST", "/cases/{case_id}/investigate"), ("POST", "/investigations/{run_id}/close"),
}
# What the key can reach that NO tool calls, and why each is left open (or why it is a problem still). Adding a route here is a decision, not a formality.
LEFT_OPEN = {
    # Case management: the same permission (cases:write) as the four case tools. Internal workflow data. Narrowing it would be a `cases:work` split.
    ("POST", "/cases"): "create a case: case management, cases:write",
    ("POST", "/cases/{case_id}/alerts"): "attach alerts to a case: case management, cases:write",
    ("POST", "/cases/{case_id}/notes"): "add a note: case management, cases:write",
    ("POST", "/cases/{case_id}/observables"): "add an observable: case management, cases:write",
    ("POST", "/cases/{case_id}/tasks"): "add a task: case management, cases:write",
    ("PATCH", "/cases/{case_id}/tasks/{task_id}"): "update a task: case management, cases:write",
    # Raising an approval is left open ON PURPOSE (an integration may raise one) but it push-notifies the on-call analyst: a way to put a request in front of a human. DECIDING it needs a person.
    ("POST", "/approvals"): "raise an approval request (it push-notifies on-call): left open for integrations; deciding one is human-only",
    # Review and unpublish of replays: reading a preview needs cases:read; unpublishing only reduces exposure. PUBLISHING is human-only.
    ("POST", "/ledger/{run_id}/publish/preview"): "preview what a public replay would hide: cases:read, a read despite the POST",
    ("DELETE", "/ledger/publish/{slug}"): "unpublish a replay: only reduces exposure",
    # LLM-calling routes needing only alerts:read: they spend the tenant's model credit and send alert data to its model provider. NOT yet narrowed: a real remaining width.
    ("POST", "/alerts/{alert_id}/explain"): "LLM explanation of an alert: spends model credit and sends alert data to the model provider (alerts:read): NOT YET NARROWED",
    ("POST", "/kb/query"): "LLM knowledge-base query: spends model credit (alerts:read): NOT YET NARROWED",
    # Deliberate: a ticket opens the tenant's live alert and case streams, so it needs both alerts:read and cases:read (and the key holds both).
    ("POST", "/realtime/ticket"): "mint a realtime stream ticket: needs alerts:read AND cases:read, deliberately",
}
# Routes the permission view says the key can reach, but which ALSO need a signed-in person (an API key of any scope is refused).
HUMAN_ONLY = {("POST", "/approvals/{approval_id}/decide"), ("POST", "/ledger/{run_id}/publish")}


def _reachable_non_reads():
    out = {}
    for full, route in walk_routes(app.routes):
        needed = set(_required_permissions(route))
        if not needed or not all(permission_in(bp.CORE_KEY_SCOPES, p) for p in needed):
            continue
        human_only = require_signed_in_session in [d.call for d in route.dependant.dependencies]
        for method in route.methods - {"HEAD", "OPTIONS", "GET"}:
            out[(method, full.replace("/api/v1", "", 1))] = human_only
    return out


REACH = _reachable_non_reads()


def test_the_non_read_routes_the_key_can_use_are_exactly_the_tools_plus_the_listed_ones():
    usable = {k for k, human_only in REACH.items() if not human_only}
    expected = USED_BY_A_TOOL | set(LEFT_OPEN)
    assert usable == expected, f"NEW (add with a reason, or narrow the permission): {sorted(usable - expected)}; GONE (remove from this list): {sorted(expected - usable)}"


def test_the_two_routes_the_permissions_alone_would_let_the_key_use_are_refused_to_any_api_key():
    assert {k for k, human_only in REACH.items() if human_only} == HUMAN_ONLY


def test_every_write_tool_cipher_has_is_in_the_reachable_set():
    """A tool whose route the key cannot reach would answer 403 forever."""
    for method, path in USED_BY_A_TOOL:
        assert (method, path) in REACH and not REACH[(method, path)], (method, path)


def test_every_left_open_route_carries_a_reason_and_the_not_yet_narrowed_ones_say_so():
    assert all(reason.strip() for reason in LEFT_OPEN.values())
    not_narrowed = sorted(p for (_, p), reason in LEFT_OPEN.items() if "NOT YET NARROWED" in reason)
    assert not_narrowed == ["/alerts/{alert_id}/explain", "/kb/query"], "if one of these is narrowed, remove its marker; if a new one is left open without being narrowed, mark it"


def test_the_keys_scopes_are_the_narrow_halves_and_none_of_the_broad_permissions_they_were_split_from():
    for broad in ("alerts:write", "rules:read", "connectors:read", "threat_intel:read", "threat_intel:write", "lake:query", "hunts:write", "rules:write", "connectors:write"):
        assert broad not in bp.CORE_KEY_SCOPES, f"CORE's key holds {broad}"
    assert not any(permission_in(bp.CORE_KEY_SCOPES, broad) for broad in ("alerts:write", "rules:read", "connectors:read", "threat_intel:read", "lake:query")), "a narrow scope now implies a broad one"


def test_the_ratchet_sees_the_routes_it_claims_to():
    """Guards the guard: if the scan found nothing, the exact-set test above would pass vacuously on an empty application."""
    assert len(REACH) >= 15 and ("POST", "/alerts/{alert_id}/claim") in REACH and ("POST", "/approvals/{approval_id}/decide") in REACH
