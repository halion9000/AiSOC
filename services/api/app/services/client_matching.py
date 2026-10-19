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
    # Why, when it is not just the name (the machines they have in common).
    reason: str | None = None


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


@dataclass(frozen=True)
class DeviceOverlap:
    """How many of a tool client's machine names are also machines under one AiSOC client."""

    tenant_id: str
    shared: int
    total: int


def device_suggestions(overlaps: list[DeviceOverlap], names: dict[str, str]) -> list[Suggestion]:
    """Suggestions from machines in common. It takes at least three shared machines and 40% of the tool client's machines, or (for a small client) two and 70%, so one stray
    name never decides. The score stays below an exact name match (1.0): machines say "very likely", a matching name says "same".
    """
    out: list[Suggestion] = []
    for o in overlaps:
        if o.total <= 0 or o.tenant_id not in names:
            continue
        share = o.shared / o.total
        if (o.shared >= 3 and share >= 0.4) or (o.shared >= 2 and share >= 0.7):
            out.append(
                Suggestion(
                    o.tenant_id,
                    names[o.tenant_id],
                    round(min(0.99, 0.6 + 0.39 * share), 4),
                    f"{o.shared} of its {o.total} devices are already under this client",
                )
            )
    return out


def merge_suggestions(by_name: list[Suggestion], by_devices: list[Suggestion], limit: int = 3) -> list[Suggestion]:
    """One entry per tenant, the stronger of its name score and its device score (the device reason kept when it is the one shown), best first."""
    best: dict[str, Suggestion] = {}
    for s in [*by_name, *by_devices]:
        cur = best.get(s.tenant_id)
        if cur is None or s.score > cur.score or (s.score == cur.score and s.reason and not cur.reason):
            best[s.tenant_id] = s
    # a name match that the machines also back up says so
    reasons = {s.tenant_id: s.reason for s in by_devices}
    merged = [Suggestion(s.tenant_id, s.name, s.score, s.reason or reasons.get(s.tenant_id)) for s in best.values()]
    merged.sort(key=lambda s: (-s.score, s.name.lower()))
    return merged[:limit]


# ---- machine names too common to prove anything -----------------------------------------------------------------------------------------------------------------

# Names every client has some of ("MacBook-Pro", "Server", "DESKTOP"), and the "Johns-MacBook-Pro" pattern Apple suggests, say nothing about WHICH client a machine belongs to. Windows' own random
# names (DESKTOP-4F8K2QH) are different: they are unique per machine, so they are good evidence and are kept.
_GENERIC_NAMES = frozenset(
    {
        "mac",
        "macbook",
        "macbookpro",
        "macbookair",
        "imac",
        "macmini",
        "macstudio",
        "macpro",
        "user",
        "users",
        "server",
        "servers",
        "desktop",
        "laptop",
        "pc",
        "computer",
        "workstation",
        "localhost",
        "host",
        "admin",
        "administrator",
        "test",
        "testing",
        "win",
        "windows",
        "win10",
        "win11",
        "unknown",
        "default",
        "guest",
        "dc",
        "ws",
        "vm",
        "iphone",
        "ipad",
        "android",
    }
)
_GENERIC_WITH_NUMBER = re.compile(
    r"^(pc|server|srv|desktop|laptop|workstation|computer|ws|user|mac|win|dc|vm|host|test|admin)[-_ ]?\d{0,3}$"
)
_APPLE_PERSONAL = re.compile(
    r"^[a-z]+s?[-_ ]?(macbook|imac|mac[-_ ]?mini|mac[-_ ]?studio|mac|iphone|ipad)([-_ ]?(pro|air|mini|studio))?([-_ ]?\d+)?$"
)
MIN_USABLE_HOSTNAMES = 3


def is_generic_hostname(name: str) -> bool:
    """True when a machine name is too common to say which client it belongs to: a stock word (mac, server, user, laptop...), a stock word with a short number (server2, pc-01), Apple's
    "<Name>s-MacBook-Pro" pattern, or anything shorter than four characters. Compared lower-cased, ignoring ``.local`` and the domain."""
    n = (name or "").strip().lower().split(".")[0]
    if len(n) < 4:
        return True
    squashed = re.sub(r"[-_ ]", "", n)
    if n in _GENERIC_NAMES or squashed in _GENERIC_NAMES or _GENERIC_WITH_NUMBER.match(n):
        return True
    return bool(_APPLE_PERSONAL.match(n))


def usable_hostnames(keys: set[str] | list[str]) -> set[str]:
    """The machine names that can serve as evidence: the generic ones removed."""
    return {k for k in keys if k and not is_generic_hostname(k)}


def device_auto_match(overlaps: list[DeviceOverlap], min_names: int = MIN_USABLE_HOSTNAMES) -> str | None:
    """The one client a tool client can be linked to without asking, or None. ALL of the tool client's usable (non-generic) machine names must already be machines under that one client,
    there must be at least ``min_names`` of them (two machines agreeing is a coincidence waiting to happen; a client that small is only ever SUGGESTED), and no other client may share any of
    them. ``DeviceOverlap.total`` must already be counted over usable names only.
    """
    found = [o for o in overlaps if o.shared > 0]
    if len(found) != 1:
        return None
    o = found[0]
    return o.tenant_id if o.total >= min_names and o.shared == o.total else None
