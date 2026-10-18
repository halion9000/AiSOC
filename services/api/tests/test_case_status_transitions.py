"""A case's status only moves forward, but steps may be skipped (choosing 'In progress' on a new case used to be refused with a bare 422)."""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.cases import _STATUS_ORDER, _TRANSITIONS


def test_a_new_case_can_go_straight_to_investigating():
    assert "investigating" in _TRANSITIONS["new"]


@pytest.mark.parametrize("status", _STATUS_ORDER)
def test_nothing_goes_backwards_and_nothing_stays_put(status):
    later = set(_STATUS_ORDER[_STATUS_ORDER.index(status) + 1 :])
    assert _TRANSITIONS[status] == later
    assert status not in _TRANSITIONS[status]


def test_a_closed_case_is_final():
    assert _TRANSITIONS["closed"] == set()


def test_every_status_the_api_accepts_has_a_row():
    assert set(_TRANSITIONS) == set(_STATUS_ORDER)
