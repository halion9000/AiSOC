"""
Forwarded from CORE.

CORE (the operator's MSP workspace) already holds the credentials for tools such as Huntress and Blumira and reads them itself. It posts what it finds into this
platform's push inbox (``/v1/inbox/{token}``) and reports each run's outcome to ``/api/v1/inbox/core-feed/{token}/status``. That report is what fills in a row of
this type, so the Connectors page shows these sources the same way as any other: healthy or not, when they last synced, how many events arrived, how many errors.

This class exists so the type is in the catalog (with a name and description). It never polls anything itself: ``externally_managed`` tells the scheduler to leave
these rows alone, because a poll here would overwrite the status CORE reports with a meaningless "healthy, 0 events".
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

CORE_FEED_TYPE = "core_feed"


class CoreFeedConnector(BaseConnector):
    connector_id = CORE_FEED_TYPE
    connector_name = "Forwarded from CORE"
    connector_category = "siem"

    # The scheduler skips connectors that set this: their status and counters are written by whatever forwards the data, not by a poll.
    externally_managed = True

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return ()

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "A source CORE reads with its own saved credentials (Huntress, Blumira, ...) and forwards here. "
                "These rows are created and kept up to date by CORE; there is nothing to configure."
            ),
            docs_url="/docs/connectors/core-feed",
            fields=[
                Field(
                    "vendor",
                    "string",
                    "Source",
                    required=False,
                    help_text="Set by CORE (for example: huntress). Nothing to enter here.",
                ),
            ],
        )

    def __init__(self, vendor: str | None = None, **_managed: Any) -> None:
        # The row CORE creates stores {"vendor": ..., "managed_by": "core"}, and the Test button passes the whole blob here, so extra keys must not be an error.
        self._vendor = vendor or ""

    async def test_connection(self) -> dict[str, Any]:
        # Nothing to reach from here: the data arrives by push. Say so plainly rather than reporting a success that was never checked.
        return {
            "success": True,
            "connector": self.connector_id,
            "note": "Data is pushed by CORE; this platform has no credentials for the source. Check the source in CORE.",
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        return []
