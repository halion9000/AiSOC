"""Splunk event-warehouse provider — Phase 4.5.

Reads SPL out of ``hunt.translated_query["spl"]`` and runs it against
the configured Splunk search head via the REST API's oneshot search
endpoint (``/services/search/jobs`` with ``exec_mode=oneshot``) — a
single POST that returns the result set directly rather than the
create-job-then-poll flow, matching this module's own count-only need.

Security invariants — mirrors ``app.services.esql_runner`` exactly:

* **SSRF guard.** :func:`_validate_splunk_url` enforces that the target
  host matches the configured ``SPLUNK_URL`` setting. A mismatched host
  raises :class:`ValueError` before any outbound request leaves the
  process.
* **Air-gap policy.** The final URL routes through
  :func:`enforce_airgap_for_url` so ``AISOC_AIRGAPPED=true`` can't be
  bypassed by a Splunk-specific code path.
* **No new dependencies.** Uses ``httpx`` (already a hard dep of the
  API service) rather than the official Splunk SDK — the module
  docstring's own original plan offered this as the faster path
  ("Adding the live implementation is a one-PR change once we land a
  splunk-sdk dep" / "2. POST the SPL to /services/search/jobs"), and a
  plain REST call needs no new dependency to build out or to verify.

Hal, live review, 2026-09-22: was a scaffold that raised
``HuntNotConfigured`` unconditionally, real credentials or not — see
this file's git history for the original docstring's own explicit
four-step plan, which this implementation follows. Also depended on
``SPLUNK_URL``/``SPLUNK_HMAC_TOKEN`` settings fields that, until a
separate fix the same night, were never actually declared on
``Settings`` at all (see ``app.core.config``'s own comment) — so even
once this provider does real work, it was previously unreachable via
correctly-set environment variables regardless.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings
from app.models.saved_hunt import SavedHunt

from .base import HuntExecutionError, HuntNotConfigured, _BaseProvider

logger = logging.getLogger(__name__)


def _validate_splunk_url(url: str) -> str:
    """Validate ``url`` against the configured Splunk host.

    Raises :class:`ValueError` if the host or scheme does not match,
    preventing SSRF. Returns a *reconstructed* URL built solely from
    the validated scheme and netloc, mirroring
    ``app.services.esql_runner._validate_es_url`` exactly — this
    discards any user-supplied path or query so a saved hunt can't be
    pointed at an attacker-controlled path under the same host.
    """
    allowed = urlparse(settings.SPLUNK_URL)
    candidate = urlparse(url)
    if candidate.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {candidate.scheme!r}")
    if candidate.netloc != allowed.netloc:
        raise ValueError(f"Splunk URL host {candidate.netloc!r} is not the configured host {allowed.netloc!r}")
    return f"{candidate.scheme}://{candidate.netloc}"


def _as_search_command(spl: str) -> str:
    """Prefix ``spl`` with ``search`` unless it already opens with a
    generating command.

    Splunk's ``/services/search/jobs`` endpoint requires the search
    string to start with a generating command (``search``, ``|
    tstats``, ``| metadata``, etc.) — a bare filter expression like
    ``index=main sourcetype=auth_log`` needs the explicit ``search``
    verb prepended, but a query that already opens with a pipe (already
    a generating command) or with the literal ``search`` keyword itself
    must not get a second one stacked in front of it.

    Caught by testing before shipping, not by inspection: an earlier
    version of this function only checked for a leading pipe, so a
    translated query that already started with ``search`` (a very
    common shape — many SPL translators emit it explicitly) got
    prefixed again into ``search search ...``, a malformed query
    Splunk would have rejected outright.
    """
    stripped = spl.strip()
    if stripped.startswith("|"):
        return stripped
    if stripped.lower().startswith("search ") or stripped.lower() == "search":
        return stripped
    return f"search {stripped}"


class SplunkProvider(_BaseProvider):
    """Run SPL hunts against the configured Splunk search head."""

    name = "splunk"
    translated_query_key = "spl"

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        spl = self._read_translated(hunt)

        if not settings.SPLUNK_URL or not settings.SPLUNK_HMAC_TOKEN:
            raise HuntNotConfigured("splunk: SPLUNK_URL or SPLUNK_HMAC_TOKEN not configured")

        try:
            safe_url = _validate_splunk_url(settings.SPLUNK_URL)
        except ValueError:
            # Re-raise unchanged — callers distinguish URL errors from
            # transport errors, same convention as esql_runner.py.
            raise

        jobs_url = f"{safe_url.rstrip('/')}/services/search/jobs"
        # enforce_airgap_for_url is a no-op when AISOC_AIRGAPPED is
        # false, so this is safe to call unconditionally.
        enforce_airgap_for_url(jobs_url)

        search = _as_search_command(spl)

        try:
            async with httpx.AsyncClient(timeout=60.0, verify=True) as client:
                resp = await client.post(
                    jobs_url,
                    headers={"Authorization": f"Bearer {settings.SPLUNK_HMAC_TOKEN}"},
                    data={
                        "search": search,
                        "exec_mode": "oneshot",
                        "output_mode": "json",
                        "count": str(max_rows),
                    },
                )
                resp.raise_for_status()
                data = resp.json()
        except AirgapViolation:
            # Let the air-gap signal propagate unchanged so the caller
            # can apply its dedicated handling, same convention as
            # esql_runner.py.
            raise
        except httpx.HTTPError as exc:
            raise HuntExecutionError(f"Splunk execution failed: {exc}") from exc

        results = data.get("results")
        if not isinstance(results, list):
            # A malformed or unexpected response shape — Splunk changed
            # something, or oneshot returned an error body instead of
            # results. Treat as an execution error rather than
            # silently reporting zero hits.
            raise HuntExecutionError(f"Splunk returned an unexpected response shape: {list(data.keys())!r}")

        logger.info(
            "event_warehouse.splunk.run_hunt hunt_id=%s hit_count=%d",
            hunt.id,
            len(results),
        )
        return len(results)
