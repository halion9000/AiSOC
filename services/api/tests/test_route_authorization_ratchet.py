"""Authorization ratchet: the set of routes with NO guard may only shrink.

199 routes authenticated the caller but never checked what the caller may do
(found while fixing the case endpoints, where a viewer could create cases).
Fixing them all at once risks locking legitimate roles out, so it is staged.
This test freezes today's list: a NEW unguarded route fails the build, and
guarding an old one fails it too until it is removed from the baseline, so the
list can only ever get shorter.

To fix a route: add Depends(require_permission("...")) (or an inline guard),
then delete its line from tests/data/unguarded_routes.txt.
Some routes are legitimately self-service (your own passkeys, push
subscriptions, saved views). Leave those in the baseline.
"""
import os

from route_auth_scan import unguarded_routes

BASELINE = os.path.join(os.path.dirname(__file__), "data", "unguarded_routes.txt")


def _baseline() -> set[str]:
    with open(BASELINE, encoding="utf-8") as f:
        return {l.strip() for l in f if l.strip() and not l.startswith("#")}


def test_no_new_route_ships_without_an_authorization_check():
    new = sorted(set(unguarded_routes()) - _baseline())
    assert not new, (
        "These routes check that you are logged in but not what you may do. Add "
        'Depends(require_permission("<area>:<read|write>")) (or an inline guard):\n  ' + "\n  ".join(new)
    )


def test_the_baseline_only_shrinks():
    stale = sorted(_baseline() - set(unguarded_routes()))
    assert not stale, "These routes are guarded now (or gone). Delete them from tests/data/unguarded_routes.txt:\n  " + "\n  ".join(stale)


def test_the_scanner_actually_sees_the_routes():
    found = unguarded_routes()
    assert len(found) > 100, "scanner found almost nothing: it is broken, not the codebase fixed"
    # a route we know is guarded must NOT be listed (cases were fixed in d8d3c28f)
    assert not any("cases.py::create_case" in r for r in found)
