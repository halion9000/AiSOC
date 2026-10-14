"""Suggest which AiSOC tenant a vendor's client belongs to, from the names alone.

The same customer is spelled differently in every tool ("Acme Dental, LLC", "Acme Dental", "ACME DENTAL INC."). This module is pure (no database): it normalizes names and
ranks candidate tenants. It only SUGGESTS; a person confirms, and a choice a person made is never replaced by a suggestion.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher

# Words that say what KIND of company it is, not which one. Dropped so "Acme Dental, LLC" and "Acme Dental" are the same name.
_NOISE = frozenset(
    {"llc", "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "pllc", "pc", "lp", "llp", "plc", "the"}
)

EXACT = 1.0
SUGGEST_THRESHOLD = 0.6


def normalize_name(name: str) -> str:
    """Lowercase, strip accents and punctuation, turn "&" into "and", drop company-type words, collapse spaces."""
    text = unicodedata.normalize("NFKD", name or "")
    text = "".join(c for c in text if not unicodedata.combining(c)).lower().replace("&", " and ").replace(".", "").replace("'", "")
    tokens = [t for t in re.sub(r"[^a-z0-9]+", " ", text).split() if t not in _NOISE]
    return " ".join(tokens)


@dataclass(frozen=True)
class Candidate:
    tenant_id: str
    name: str


@dataclass(frozen=True)
class Suggestion:
    tenant_id: str
    name: str
    score: float


def score(a: str, b: str) -> float:
    """0..1 similarity of two names. 1.0 only when they normalize to the same text; one name wholly containing the other's words scores high but below exact."""
    na, nb = normalize_name(a), normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return EXACT
    ta, tb = set(na.split()), set(nb.split())
    if ta <= tb or tb <= ta:
        # "Acme" vs "Acme Dental Group": every word of the shorter is in the longer. Likely the same customer, but never as sure as an exact match.
        return 0.85 if min(len(ta), len(tb)) >= 1 and len(na) >= 3 and len(nb) >= 3 else 0.0
    jaccard = len(ta & tb) / len(ta | tb)
    ratio = SequenceMatcher(None, na, nb).ratio()
    return round(max(jaccard, ratio * 0.9), 4)


def suggest(vendor_client_name: str, candidates: list[Candidate], limit: int = 3) -> list[Suggestion]:
    """The best-matching tenants for a vendor client name, best first, only those scoring at least SUGGEST_THRESHOLD."""
    scored = [Suggestion(c.tenant_id, c.name, score(vendor_client_name, c.name)) for c in candidates]
    kept = [s for s in scored if s.score >= SUGGEST_THRESHOLD]
    kept.sort(key=lambda s: (-s.score, s.name.lower()))
    return kept[:limit]


def is_confident(suggestions: list[Suggestion]) -> bool:
    """True when the top suggestion is an exact normalized match and no other tenant ties it (two tenants with the same normalized name must be chosen by a person)."""
    if not suggestions or suggestions[0].score < EXACT:
        return False
    return len(suggestions) == 1 or suggestions[1].score < EXACT


DUPLICATE_THRESHOLD = 0.75


def duplicate_groups(candidates: list[Candidate]) -> list[list[Candidate]]:
    """Client tenants that look like the same customer ("Acme Dental" / "Acme Dental LLC" / "ACME Dental Group"), grouped, each group name-sorted.

    Two tenants are linked when their names score at least DUPLICATE_THRESHOLD; a chain (A~B, B~C) makes one group. Only groups of two or more are returned.
    """
    parent = list(range(len(candidates)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            if score(candidates[i].name, candidates[j].name) >= DUPLICATE_THRESHOLD:
                parent[find(i)] = find(j)
    groups: dict[int, list[Candidate]] = {}
    for i, c in enumerate(candidates):
        groups.setdefault(find(i), []).append(c)
    out = [sorted(g, key=lambda c: c.name.lower()) for g in groups.values() if len(g) > 1]
    return sorted(out, key=lambda g: g[0].name.lower())
