"""The ``core_feed`` connector as the Test button uses it: built from the row's whole stored settings."""

import asyncio

from app.connectors import CONNECTOR_REGISTRY


def test_it_can_be_built_from_exactly_the_settings_the_row_stores():
    cls = CONNECTOR_REGISTRY["core_feed"]
    # What the status endpoint stores, and what the Test button passes to the class.
    connector = cls(**{"vendor": "huntress", "managed_by": "core"})
    result = asyncio.run(connector.test_connection())
    assert result["success"] is True
    assert "CORE" in result["note"]
