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
    """If the scanner broke and found nothing, the other two tests would pass for the wrong reason.

    So check that it still DETECTS routes that are deliberately login-only, and still
    recognises routes that are guarded (cases were fixed in d8d3c28f).
    """
    found = unguarded_routes()
    for known_open in ("passkeys.py::passkey_register_begin", "saved_views.py::create_saved_view", "push.py::subscribe", "phishing.py::submit"):
        assert any(known_open in r for r in found), f"the scanner no longer detects {known_open}: it is broken"
    for known_guarded in ("cases.py::create_case", "assets.py::delete_asset", "deployment.py::update_deployment_config", "mssp.py::create_rule_override"):
        assert not any(known_guarded in r for r in found), f"{known_guarded} should be recognised as guarded"
