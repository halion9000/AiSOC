"""The template queries used when no LLM answers must not let the hypothesis break out of their quoted string.

``_fallback_queries`` escaped only the double quote (not the backslash) and cut to 60 characters AFTER escaping, so a hypothesis ending in a backslash, or containing a backslash-quote,
produced a quote that ended the string early and let the rest of the text run as query syntax.
"""

from __future__ import annotations

import re

import pytest
from app.api.v1.endpoints.hunts import _fallback_queries

BS = chr(92)
Q = chr(34)


def _unescaped_quotes(text: str) -> int:
    """Quotes that are not escaped by an odd run of backslashes."""
    return len(re.findall(r"(?<!" + re.escape(BS) + r")(?:" + re.escape(BS * 2) + r")*" + Q, text))


@pytest.mark.parametrize(
    "hypothesis",
    [
        "normal text with " + Q + "quotes" + Q + " inside",
        "ends with a backslash " + BS,
        "breakout " + BS + Q + " | DROP",
        "a" * 59 + BS,
        "a" * 59 + Q,
        "x" + BS * 2 + Q + " || true",
    ],
)
def test_the_hypothesis_stays_inside_its_quoted_string(hypothesis):
    q = _fallback_queries(hypothesis)
    # esql: one quoted LIKE operand; spl: one quoted term; kql: one quoted operand. Each must have exactly two unescaped quotes.
    assert _unescaped_quotes(q["esql"]) == 2, q["esql"]
    assert _unescaped_quotes(q["spl"]) == 2, q["spl"]
    assert _unescaped_quotes(q["kql"]) == 2, q["kql"]


def test_a_plain_hypothesis_is_unchanged_in_the_query():
    assert 'LIKE "%lateral movement%"' in _fallback_queries("lateral movement")["esql"]
