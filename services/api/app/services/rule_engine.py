"""
Detection rule execution engine.
Supports: Sigma (pySigma), YARA, KQL (simulated), EQL (simulated).
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class RuleLanguage(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    KQL = "kql"
    EQL = "eql"
    LUCENE = "lucene"
    REGEX = "regex"


@dataclass
class RuleMatch:
    """A single rule match result."""

    rule_id: str
    rule_name: str
    rule_language: str
    severity: str
    matched: bool
    match_details: dict[str, Any] = field(default_factory=dict)
    matched_fields: list[str] = field(default_factory=list)
    score: float = 0.0
    error: str | None = None
    execution_time_ms: float = 0.0


@dataclass
class HuntResult:
    """Result from a threat hunt across events."""

    hunt_id: str
    tenant_id: str
    rules_evaluated: int
    rules_matched: int
    total_events_scanned: int
    matched_events: list[dict[str, Any]]
    match_summary: list[dict[str, Any]]
    execution_time_ms: float
    errors: list[str]


# ─── Sigma Runner ─────────────────────────────────────────────────────────────


def _run_sigma(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """
    Execute a Sigma rule against a list of events.
    Uses pySigma for parsing; falls back to a lightweight YAML-based evaluator.
    Returns (matched_events, error_message).
    """
    try:
        from sigma.backends.opensearch import OpensearchLuceneBackend
        from sigma.rule import SigmaRule

        sigma_rule = SigmaRule.from_yaml(rule_body)
        backend = OpensearchLuceneBackend()
        queries = backend.convert_rule(sigma_rule)

        # Use the generated Lucene query to evaluate events
        matched = []
        for event in events:
            for query in queries:
                if _lucene_match(query, event):
                    matched.append(event)
                    break
        return matched, None

    except ImportError:
        # pySigma not available – use simple YAML condition evaluator
        return _sigma_fallback(rule_body, events), None
    except Exception as exc:
        logger.warning("Sigma parse error: %s", exc)
        return _sigma_fallback(rule_body, events), str(exc)


def _sigma_fallback(rule_body: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Minimal Sigma evaluator for simple field: value conditions.
    Parses the `detection` block and checks field/value presence.
    """
    try:
        import yaml

        rule = yaml.safe_load(rule_body)
        detection = rule.get("detection", {})

        matched = []
        for event in events:
            flat_event = _flatten_dict(event)
            if _eval_sigma_detection(detection, flat_event):
                matched.append(event)
        return matched
    except Exception as exc:
        logger.debug("Sigma fallback evaluator error: %s", exc)
        return []


def _eval_sigma_detection(detection: dict, flat_event: dict[str, Any]) -> bool:
    """Evaluate Sigma detection section (keywords + condition)."""
    condition = detection.get("condition", "selection")
    selections: dict[str, bool] = {}

    for sel_name, sel_def in detection.items():
        if sel_name == "condition":
            continue
        if isinstance(sel_def, dict):
            match = True
            for field_name, field_val in sel_def.items():
                # Strip Sigma modifier suffixes (e.g. `cmdline|contains` -> `cmdline`).
                field_lower = field_name.lower().split("|", 1)[0]
                ev_val = str(flat_event.get(field_lower, "")).lower()
                if isinstance(field_val, list):
                    hit = any(str(v).lower() in ev_val for v in field_val)
                else:
                    hit = str(field_val).lower() in ev_val
                if not hit:
                    match = False
                    break
            selections[sel_name] = match
        elif isinstance(sel_def, list):
            # keywords list
            flat_str = " ".join(str(v) for v in flat_event.values()).lower()
            selections[sel_name] = all(str(kw).lower() in flat_str for kw in sel_def)

    # Evaluate condition expression (supports: and, or, not, 1 of, all of)
    return _eval_condition(condition, selections)


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string using a safe boolean AST parser.

    SECURITY: Earlier revisions used `eval()` here, which allowed arbitrary
    Python expressions inside the Sigma `condition` field to execute in the
    API process. The condition is user-controlled (Sigma rule body) and
    therefore must be parsed, not evaluated.

    Supported grammar:
        - boolean literals (case-insensitive): true | false
        - selection name references (must be present in `selections` mapping)
        - unary operator:   not <expr>
        - binary operators: <expr> and <expr> | <expr> or <expr>
        - parentheses:      ( <expr> )
        - Sigma quantifiers (subset): "1 of selection*" / "all of selection*"

    Anything else short-circuits to the safe default of ANDing all selections.
    """
    expr = condition.strip()
    try:
        return _SigmaConditionParser(expr, selections).parse()
    except Exception as exc:  # noqa: BLE001 — keep behaviour identical to legacy fallback
        logger.debug("Sigma condition parse error (%r): %s", condition, exc)
        return all(selections.values()) if selections else False


class _SigmaConditionParser:
    """Tiny recursive-descent parser for Sigma condition expressions.

    The grammar accepted is a strict subset of the Sigma spec, sufficient to
    cover every shipped detection rule in `detections/` while refusing
    anything that could lead to code execution.
    """

    _TOKEN_RE = re.compile(
        # Token alternatives: opening paren, closing paren, or a "word" that
        # may start with a digit (for the `1 of …` quantifier) or a letter /
        # underscore. The leading `\s*` is consumed by the caller via lstrip
        # so that trailing whitespace doesn't break the match loop.
        r"(?P<lparen>\()|(?P<rparen>\))|(?P<word>[A-Za-z0-9_][A-Za-z0-9_*]*)",
    )

    def __init__(self, expr: str, selections: dict[str, bool]) -> None:
        self._expr = expr
        self._selections = selections
        self._tokens = self._tokenize(expr)
        self._pos = 0

    def parse(self) -> bool:
        result = self._parse_or()
        if self._pos != len(self._tokens):
            raise ValueError(f"unexpected trailing token: {self._tokens[self._pos]!r}")
        return result

    # ── tokenizer ────────────────────────────────────────────────────────────
    def _tokenize(self, expr: str) -> list[str]:
        tokens: list[str] = []
        pos = 0
        n = len(expr)
        while pos < n:
            # Skip any inter-token whitespace.
            while pos < n and expr[pos].isspace():
                pos += 1
            if pos >= n:
                break
            m = self._TOKEN_RE.match(expr, pos)
            if not m:
                raise ValueError(f"invalid character at position {pos}: {expr[pos]!r}")
            if m.group("lparen"):
                tokens.append("(")
            elif m.group("rparen"):
                tokens.append(")")
            else:
                tokens.append(m.group("word"))
            pos = m.end()
        return tokens

    # ── grammar ──────────────────────────────────────────────────────────────
    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _match(self, *expected: str) -> bool:
        tok = self._peek()
        if tok is None:
            return False
        if tok.lower() in expected:
            self._consume()
            return True
        return False

    def _parse_or(self) -> bool:
        left = self._parse_and()
        while self._match("or"):
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        left = self._parse_not()
        while self._match("and"):
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self) -> bool:
        if self._match("not"):
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")

        if tok == "(":
            self._consume()
            value = self._parse_or()
            if not self._match(")"):
                raise ValueError("missing closing parenthesis")
            return value

        # Quantifier forms: "1 of <pattern>" / "all of <pattern>"
        lowered = tok.lower()
        if lowered in {"1", "all"} and (self._pos + 2) <= len(self._tokens):
            next_tok = self._tokens[self._pos + 1] if self._pos + 1 < len(self._tokens) else None
            if next_tok and next_tok.lower() == "of":
                self._consume()  # quantifier
                self._consume()  # 'of'
                pattern_tok = self._peek()
                if pattern_tok is None or pattern_tok in {"(", ")"}:
                    raise ValueError("quantifier missing pattern")
                self._consume()
                return self._evaluate_quantifier(lowered, pattern_tok)

        # Bare identifier / literal.
        self._consume()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if tok in self._selections:
            return bool(self._selections[tok])
        # Unknown selection name → treat as missing (False) rather than raising
        # so that legacy rules referring to absent selections still produce a
        # deterministic result.
        return False

    def _evaluate_quantifier(self, quantifier: str, pattern: str) -> bool:
        if pattern == "them":
            values = list(self._selections.values())
        elif "*" in pattern:
            regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            values = [v for name, v in self._selections.items() if regex.match(name)]
        else:
            values = [self._selections.get(pattern, False)]

        if not values:
            return False
        if quantifier == "1":
            return any(values)
        return all(values)


# ─── YARA Runner ──────────────────────────────────────────────────────────────


def _run_yara(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """
    Execute a YARA rule against event payloads.
    Compiles and matches each event's raw_payload or JSON representation.
    """
    try:
        import yara

        compiled = yara.compile(source=rule_body)
        matched = []
        for event in events:
            payload_bytes = _event_to_bytes(event)
            matches = compiled.match(data=payload_bytes)
            if matches:
                event_copy = dict(event)
                event_copy["_yara_matches"] = [m.rule for m in matches]
                matched.append(event_copy)
        return matched, None
    except ImportError:
        return [], "yara-python not installed"
    except Exception as exc:
        logger.warning("YARA execution error: %s", exc)
        return [], str(exc)


def _event_to_bytes(event: dict[str, Any]) -> bytes:
    """Convert event dict to bytes for YARA matching."""
    payload = event.get("raw_payload") or event.get("ocsf_json") or json.dumps(event)
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        try:
            return payload.encode("utf-8", errors="replace")
        except Exception:
            return b""
    return json.dumps(payload).encode("utf-8")


# ─── KQL / EQL runner ─────────────────────────────────────────────────────────
#
# A small, honest evaluator. KQL: ``field:value`` (quoted or with ``*`` wildcards), free text, ``and`` / ``or`` / ``not`` and parentheses, with ``not`` binding tighter than ``and`` and ``and`` tighter
# than ``or``. EQL: the same conditions after a ``<category> where`` prefix, plus ``==`` and ``!=``, for single events. EQL ``sequence`` rules need ordered matching across events, which this does
# not do, so they come back as an error instead of quietly matching on one event of the sequence (which would raise alerts the rule never meant).

_QUERY_TOKEN = re.compile(r'\s*(?:(\()|(\))|"((?:[^"\\]|\\.)*)"|((?:[^\s()"]|"(?:[^"\\]|\\.)*")+))')


def _query_tokens(query: str) -> list[tuple[str, str]]:
    """Split a query into (kind, text): ``(`` ``)``, quoted strings, and bare words."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    query = query.strip()
    while pos < len(query):
        m = _QUERY_TOKEN.match(query, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.group(1):
            tokens.append(("(", "("))
        elif m.group(2):
            tokens.append((")", ")"))
        elif m.group(3) is not None:
            tokens.append(("quoted", m.group(3)))
        else:
            tokens.append(("word", m.group(4)))
    return tokens


def _term_matches(term: str, flat_event: dict[str, Any]) -> bool:
    """One condition: ``field:value`` / ``field==value`` / ``field!=value`` or free text."""
    for op in ("!=", "==", ":"):
        if op in term:
            field_name, _, value = term.partition(op)
            field_name, value = field_name.strip().lower(), value.strip().strip('"').lower()
            if field_name and value != "":
                actual = str(flat_event.get(field_name, "")).lower()
                if "*" in value:
                    hit = bool(re.fullmatch(".*".join(re.escape(part) for part in value.split("*")), actual))
                elif op == ":":
                    hit = value in actual
                else:
                    hit = actual == value
                return (not hit) if op == "!=" else hit
    needle = term.strip().strip('"').lower()
    return needle in " ".join(str(v) for v in flat_event.values()).lower()


def _eval_query(tokens: list[tuple[str, str]], flat_event: dict[str, Any]) -> bool:
    pos = 0

    def peek() -> tuple[str, str] | None:
        return tokens[pos] if pos < len(tokens) else None

    def is_word(tok: tuple[str, str] | None, *words: str) -> bool:
        return tok is not None and tok[0] == "word" and tok[1].lower() in words

    def parse_or() -> bool:
        nonlocal pos
        value = parse_and()
        while is_word(peek(), "or"):
            pos += 1
            right = parse_and()  # always parsed, so the cursor moves past it
            value = value or right
        return value

    def parse_and() -> bool:
        nonlocal pos
        value = parse_not()
        while is_word(peek(), "and"):
            pos += 1
            right = parse_not()
            value = value and right
        return value

    def parse_not() -> bool:
        nonlocal pos
        if is_word(peek(), "not"):
            pos += 1
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise ValueError("the query ends where a condition was expected")
        if tok[0] == "(":
            pos += 1
            value = parse_or()
            if peek() is None or peek()[0] != ")":  # type: ignore[index]
                raise ValueError("a ( is never closed")
            pos += 1
            return value
        if tok[0] == ")":
            raise ValueError("a ) has no matching (")
        pos += 1
        text = tok[1]
        # EQL writes comparisons with spaces: ``field == "value"``.
        if tok[0] == "word" and is_word(peek(), "==", "!=") and pos + 1 < len(tokens):
            text = f"{text}{tokens[pos][1]}{tokens[pos + 1][1]}"
            pos += 2
            return _term_matches(text, flat_event)
        # ``field: "quoted value"`` arrives as the word ``field:`` then a quoted token.
        if tok[0] == "word" and text.endswith(":") and peek() is not None and peek()[0] == "quoted":  # type: ignore[index]
            text = f"{text}{peek()[1]}"  # type: ignore[index]
            pos += 1
        elif tok[0] == "quoted":
            text = f'"{text}"'
        return _term_matches(text, flat_event)

    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"unexpected {tokens[pos][1]!r} in the query")
    return result


def _kql_match(query: str, flat_event: dict[str, Any]) -> bool:
    tokens = _query_tokens(query)
    if not tokens:
        return False
    return _eval_query(tokens, flat_event)


def _run_kql(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """KQL over a batch of events: the events that match, and an error message when the query cannot be read."""
    matched: list[dict] = []
    try:
        for event in events:
            if _kql_match(rule_body, _flatten_dict(event)):
                matched.append(event)
    except ValueError as exc:
        return [], f"Could not read the query: {exc}"
    except Exception as exc:  # noqa: BLE001 - one bad event must not hide the error from the rule's owner
        return matched, str(exc)
    return matched, None


_EQL_PREFIX = re.compile(r"^\s*(\w+)\s+where\s+", re.IGNORECASE)

# ``sequence [by f1, f2] [with maxspan=5m]`` then two or more ``[category where condition]`` steps: the steps must be seen in that order, for events that share the ``by`` values, and (with
# maxspan) all within that long of the first. The events that complete a sequence are the match.
_SEQ_HEAD = re.compile(r"^\s*sequence\b(?P<by>\s+by\s+[^\[]*?)?(?P<span>\s+with\s+maxspan\s*=\s*\d+\s*[smhd])?\s*(?=\[)", re.IGNORECASE)
_SEQ_SPAN = re.compile(r"maxspan\s*=\s*(\d+)\s*([smhd])", re.IGNORECASE)
_TIME_FIELDS = ("@timestamp", "timestamp", "time", "event_time", "created_at", "published")
_SPAN_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _event_seconds(flat_event: dict[str, Any]) -> float | None:
    """When the event happened, in seconds, from the first time field it has (ISO text or a number); None when it has none that can be read."""
    for key in _TIME_FIELDS:
        raw = flat_event.get(key)
        if isinstance(raw, bool) or raw is None:
            continue
        if isinstance(raw, int | float):
            return float(raw) / 1000.0 if raw > 1e11 else float(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                moment = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
            except ValueError:
                continue
            return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()
    return None


def _split_steps(text_after_head: str) -> list[str]:
    """The text of each ``[...]`` step, honouring quotes so a ``]`` inside a string does not end one. Raises ValueError for an unbalanced step."""
    steps, depth, start, quote = [], 0, 0, ""
    for i, ch in enumerate(text_after_head):
        if quote:
            if ch == quote and text_after_head[i - 1] != "\\":
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "[":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                raise ValueError("a ] has no matching [")
            if depth == 0:
                steps.append(text_after_head[start:i].strip())
    if depth != 0 or quote:
        raise ValueError("a [ step is never closed")
    return steps


def _category_ok(category: str, flat_event: dict[str, Any]) -> bool:
    """``any`` matches every event. A named category must match the event's own category when it has one (``category``, ``event.category`` or ``event_type``); an event that names none is not excluded."""
    if category.lower() == "any":
        return True
    for key in ("category", "event.category", "event_type"):
        value = flat_event.get(key)
        if isinstance(value, str) and value:
            return value.lower() == category.lower()
    return True


def _run_eql_sequence(body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    head = _SEQ_HEAD.match(body)
    if head is None:
        return [], "Could not read the sequence: it should look like  sequence by host.name with maxspan=5m [process where ...] [network where ...]"
    by_fields = [f.strip().lower() for f in re.sub(r"^\s*by\s+", "", head.group("by") or "", flags=re.IGNORECASE).split(",") if f.strip()]
    for field_name in by_fields:
        if not re.fullmatch(r"[\w.@-]+", field_name):
            return [], f"Could not read the 'by' part of the sequence (got: {field_name[:40]!r}); it is a comma separated list of field names, then optionally  with maxspan=5m  using s, m, h or d."
    span = None
    if head.group("span"):
        m = _SEQ_SPAN.search(head.group("span"))
        span = int(m.group(1)) * _SPAN_SECONDS[m.group(2).lower()] if m else None
    try:
        raw_steps = _split_steps(body[head.end():])
    except ValueError as exc:
        return [], f"Could not read the sequence: {exc}"
    if len(raw_steps) < 2:
        return [], "A sequence needs at least two steps, each in [square brackets]."
    steps: list[tuple[str, str]] = []
    for text in raw_steps:
        m = _EQL_PREFIX.match(text)
        if m is None:
            return [], f"Each step must read  category where condition  (got: {text[:60]!r})."
        steps.append((m.group(1), text[m.end():]))
    timed: list[tuple[float, int, dict[str, Any], dict[str, Any]]] = []
    try:
        for index, event in enumerate(events):
            flat = _flatten_dict(event)
            seconds = _event_seconds(flat)
            if seconds is None:
                return [], "A sequence needs the time of each event, and at least one event has no readable time (timestamp, @timestamp, time or event_time)."
            timed.append((seconds, index, flat, event))
        timed.sort(key=lambda t: (t[0], t[1]))
        groups: dict[tuple, list[tuple[float, int, dict[str, Any], dict[str, Any]]]] = {}
        for item in timed:
            key = tuple(str(item[2].get(f, "")) for f in by_fields)
            if by_fields and any(part == "" for part in key):
                continue  # an event that lacks a ``by`` value cannot be told apart from another machine's
            groups.setdefault(key, []).append(item)
        matched_index: set[int] = set()
        for items in groups.values():
            for first_pos, first in enumerate(items):
                if not (_category_ok(steps[0][0], first[2]) and _kql_match(steps[0][1], first[2])):
                    continue
                chain = [first]
                for item in items[first_pos + 1:]:
                    if span is not None and item[0] - first[0] > span:
                        break
                    want = steps[len(chain)]
                    if _category_ok(want[0], item[2]) and _kql_match(want[1], item[2]):
                        chain.append(item)
                        if len(chain) == len(steps):
                            break
                if len(chain) == len(steps):
                    matched_index.update(c[1] for c in chain)
    except ValueError as exc:
        return [], f"Could not read the query: {exc}"
    return [item[3] for item in timed if item[1] in matched_index], None  # in the order they happened


def _run_eql(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """EQL: a single-event condition (``process where process.name == "cmd.exe" and ...``) or a ``sequence`` of steps seen in order (see ``_run_eql_sequence``)."""
    body = rule_body.strip()
    if re.match(r"^sequence\b", body, re.IGNORECASE):
        return _run_eql_sequence(body, events)
    body = _EQL_PREFIX.sub("", body, count=1)
    return _run_kql(body, events)


# ─── Lucene Query Matcher ─────────────────────────────────────────────────────


def _lucene_match(query: str, event: dict[str, Any]) -> bool:
    """Simple Lucene query evaluator for field:value pairs."""
    flat = _flatten_dict(event)
    flat_str = " ".join(f"{k}:{v}" for k, v in flat.items()).lower()
    return query.lower() in flat_str


def _flatten_dict(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict to dot-notation keys."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}".lstrip(".") if prefix else k
        key_lower = key.lower()
        if isinstance(v, dict):
            result.update(_flatten_dict(v, key_lower))
        else:
            result[key_lower] = v
    return result


# ─── Main Execute Function ────────────────────────────────────────────────────


def _rule_runners():
    """Language -> runner map shared by execute_rule + backtest."""
    return {
        "sigma": _run_sigma,
        "yara": _run_yara,
        "kql": _run_kql,
        "eql": _run_eql,
        "lucene": lambda body, evts: (_run_kql(body, evts)[0], None),
        "regex": _run_regex,
    }


def evaluate_rule_over_events(
    rule_language: str,
    rule_body: str,
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str | None]:
    """Return (ALL matched events, error) for a rule over events.

    Unlike :func:`execute_rule` (which returns a bool + caps samples at 10),
    this exposes the full match list so a backtest can report an exact count of
    how many historical events a candidate rule would have fired on.
    """
    runner = _rule_runners().get(rule_language.lower())
    if runner is None:
        return [], f"Unsupported rule language: {rule_language}"
    return runner(rule_body, events)


def execute_rule(
    rule_id: str,
    rule_name: str,
    rule_language: str,
    rule_body: str,
    severity: str,
    events: list[dict[str, Any]],
) -> RuleMatch:
    """
    Execute a detection rule against a list of events.
    Returns a RuleMatch with matched events and metadata.
    """
    start = time.monotonic()

    lang = rule_language.lower()
    runners = _rule_runners()

    runner = runners.get(lang)
    if runner is None:
        return RuleMatch(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_language=rule_language,
            severity=severity,
            matched=False,
            error=f"Unsupported rule language: {rule_language}",
            execution_time_ms=(time.monotonic() - start) * 1000,
        )

    matched_events, error = runner(rule_body, events)
    elapsed_ms = (time.monotonic() - start) * 1000

    return RuleMatch(
        rule_id=rule_id,
        rule_name=rule_name,
        rule_language=rule_language,
        severity=severity,
        matched=len(matched_events) > 0,
        match_details={"matched_events": matched_events[:10]},  # cap to 10 for response size
        score=_severity_score(severity) if matched_events else 0.0,
        error=error,
        execution_time_ms=elapsed_ms,
    )


def _run_regex(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """Regex-based rule runner."""
    try:
        pattern = re.compile(rule_body, re.IGNORECASE | re.MULTILINE)
        matched = []
        for event in events:
            payload = json.dumps(event)
            if pattern.search(payload):
                matched.append(event)
        return matched, None
    except re.error as exc:
        return [], str(exc)


def _severity_score(severity: str) -> float:
    mapping = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
    return mapping.get(severity.lower(), 0.5)


# ─── Hunt Runner ─────────────────────────────────────────────────────────────


async def run_hunt(
    tenant_id: str,
    rules: list[dict[str, Any]],
    events: list[dict[str, Any]],
    hunt_id: str | None = None,
) -> HuntResult:
    """
    Run threat hunt: execute multiple detection rules against a set of events.
    """
    hunt_id = hunt_id or str(uuid.uuid4())
    start = time.monotonic()

    matched_events: list[dict[str, Any]] = []
    match_summary: list[dict[str, Any]] = []
    errors: list[str] = []
    rules_matched = 0

    for rule in rules:
        result = execute_rule(
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("name", ""),
            rule_language=rule.get("rule_language", "sigma"),
            rule_body=rule.get("rule_body", ""),
            severity=rule.get("severity", "medium"),
            events=events,
        )

        if result.error:
            errors.append(f"{result.rule_name}: {result.error}")

        if result.matched:
            rules_matched += 1
            matched_events.extend(result.match_details.get("matched_events", []))
            match_summary.append(
                {
                    "rule_id": result.rule_id,
                    "rule_name": result.rule_name,
                    "severity": result.severity,
                    "match_count": len(result.match_details.get("matched_events", [])),
                    "score": result.score,
                    "execution_time_ms": result.execution_time_ms,
                }
            )

    elapsed_ms = (time.monotonic() - start) * 1000

    return HuntResult(
        hunt_id=hunt_id,
        tenant_id=tenant_id,
        rules_evaluated=len(rules),
        rules_matched=rules_matched,
        total_events_scanned=len(events),
        matched_events=matched_events[:100],  # Cap response size
        match_summary=match_summary,
        execution_time_ms=elapsed_ms,
        errors=errors,
    )
