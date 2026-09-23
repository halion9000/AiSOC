"""Google Chronicle event-warehouse provider — Phase 4.5 scaffold.

Reads YARA-L / UDM search out of ``hunt.translated_query["udm"]`` and
would run it against the configured Chronicle (Google SecOps) backend.
Stub today — see the Splunk provider (built out in the same review pass
this docstring was updated in) for the same pattern once this one is
ready to follow it: advertise the contract, fail with
:class:`HuntNotConfigured` so the scheduler walks the chain.

Hal, live review, 2026-09-22: deliberately NOT built out in the same
pass as Splunk, after researching what it would actually take —
recorded here rather than guessed at, since getting Google OAuth2
wrong is a real security risk, not just an inconvenience:

1. **Auth is real OAuth2 service-account JWT signing and token
   exchange**, not a static bearer token like Splunk's
   ``SPLUNK_HMAC_TOKEN``. Google's own docs point at the
   ``google-auth`` Python library
   (``google.oauth2.service_account.Credentials`` +
   ``requests.AuthorizedSession`` or an async equivalent) for this —
   hand-rolling JWT signing without that library, just to avoid a new
   dependency, is exactly the kind of shortcut that turns into a
   security bug later.
2. **The settings schema here is already incomplete for a real call**:
   ``CHRONICLE_PROJECT_ID`` and ``CHRONICLE_SERVICE_ACCOUNT_JSON``
   alone aren't enough — Google's endpoints are also keyed by
   ``location`` (region) and ``instance`` ID
   (``{region}-chronicle.googleapis.com/.../projects/{project}/locations/{location}/instances/{instance}/...``),
   neither of which has a settings field yet.
3. **The search API itself is async / long-running-operation shaped**,
   not a single synchronous call like Splunk's oneshot search: you
   POST to start a search session, get an operation ID back, and poll
   ``GetOperation`` until ``done: true`` before results are available
   — a materially different, poll-loop-with-timeout shape than every
   other provider in this module, including this one's own
   ``run_hunt`` signature's current one-shot-await assumption.

None of this is unbuildable — it's the same class of work as Splunk,
just with a real external dependency, an extra settings migration, and
a fundamentally different control-flow shape that deserves live testing
against an actual Chronicle instance rather than a best-guess
implementation nobody can verify. Recording this now so whoever picks
it up next starts from real research instead of another cold read of
Google's docs.
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.models.saved_hunt import SavedHunt

from .base import HuntNotConfigured, _BaseProvider

logger = logging.getLogger(__name__)


class ChronicleProvider(_BaseProvider):
    """Run UDM hunts against the configured Chronicle backend."""

    name = "chronicle"
    translated_query_key = "udm"

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        _ = self._read_translated(hunt)
        _ = max_rows
        if not settings.CHRONICLE_PROJECT_ID or not settings.CHRONICLE_SERVICE_ACCOUNT_JSON:
            raise HuntNotConfigured("chronicle: CHRONICLE_PROJECT_ID or CHRONICLE_SERVICE_ACCOUNT_JSON not configured")
        logger.info(
            "event_warehouse.chronicle.run_hunt_not_yet_live hunt_id=%s",
            hunt.id,
        )
        raise HuntNotConfigured("chronicle: provider scaffolded but live UDM execution not yet shipped — see module docstring for what's actually needed")
