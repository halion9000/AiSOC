import asyncio
import uuid

import pytest
from app.services import core_feed_cases as cfc


@pytest.mark.parametrize("value", ["false", "0", "off", "No"])
def test_the_kill_switch_turns_auto_cases_off(monkeypatch, value):
    monkeypatch.setenv("AISOC_AUTO_CASES", value)
    assert cfc.enabled() is False
    assert asyncio.run(cfc.open_cases_for_new_alerts(object(), uuid.uuid4())) == 0  # never touches the database


def test_auto_cases_are_on_by_default(monkeypatch):
    monkeypatch.delenv("AISOC_AUTO_CASES", raising=False)
    assert cfc.enabled() is True
