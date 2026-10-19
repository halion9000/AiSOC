"""KQL and EQL rules mean what they say: every condition counts, not just the first."""

from app.services.rule_engine import _run_eql, _run_kql

EVENTS = [
    {"id": 1, "process": {"name": "powershell.exe", "args": "-enc AAA"}, "user": "alice", "host": "ws-1"},
    {"id": 2, "process": {"name": "powershell.exe", "args": "-File ok.ps1"}, "user": "bob", "host": "ws-2"},
    {"id": 3, "process": {"name": "cmd.exe", "args": "/c dir"}, "user": "alice", "host": "ws-1"},
]


def ids(result):
    matched, error = result
    assert error is None, error
    return [e["id"] for e in matched]


def test_and_requires_every_condition():
    assert ids(_run_kql("process.name:powershell.exe and user:alice", EVENTS)) == [1]


def test_or_takes_either():
    assert ids(_run_kql("user:bob or process.name:cmd.exe", EVENTS)) == [2, 3]


def test_not_excludes_and_binds_tighter_than_and():
    assert ids(_run_kql("process.name:powershell.exe and not user:alice", EVENTS)) == [2]


def test_and_binds_tighter_than_or_and_parentheses_override():
    assert ids(_run_kql("user:bob or user:alice and host:ws-1", EVENTS)) == [1, 2, 3]
    assert ids(_run_kql("(user:bob or user:alice) and process.name:cmd.exe", EVENTS)) == [3]


def test_wildcards_match_the_whole_value_and_quoted_values_with_spaces_work():
    assert ids(_run_kql("process.name:power*", EVENTS)) == [1, 2]
    assert ids(_run_kql('process.args:"-enc AAA"', EVENTS)) == [1]
    assert ids(_run_kql('process.args: "-File ok.ps1"', EVENTS)) == [2]


def test_free_text_still_searches_every_field():
    assert ids(_run_kql("ws-2", EVENTS)) == [2]


def test_a_query_that_cannot_be_read_is_an_error_and_matches_nothing():
    for bad in ("(user:alice", "user:alice)", "user:alice and"):
        matched, error = _run_kql(bad, EVENTS)
        assert matched == [] and error and "Could not read the query" in error


def test_eql_single_event_conditions_with_where_prefix():
    assert ids(_run_eql('process where process.name == "powershell.exe" and user != "bob"', EVENTS)) == [1]
    assert ids(_run_eql('any where user == "alice"', EVENTS)) == [1, 3]


def test_a_sequence_over_events_that_carry_no_time_is_an_error_not_a_guess():
    matched, error = _run_eql('sequence by host [process where process.name == "cmd.exe"] [process where user == "bob"]', EVENTS)
    assert matched == [] and error and "time" in error

# ---- EQL sequences ----------------------------------------------------------------------------------------------------------------------------------------

from app.services.rule_engine import _run_eql_sequence  # noqa: E402


def ev(i, ts, host, **fields):
    return {"id": i, "timestamp": ts, "host": host, **fields}


SEQ = 'sequence by host with maxspan=5m [process where process.name == "cmd.exe"] [network where dst == "1.2.3.4"]'


def test_a_sequence_matches_steps_seen_in_order_on_the_same_host_within_the_span():
    events = [
        ev(1, "2026-10-18T12:00:00Z", "A", process={"name": "cmd.exe"}, category="process"),
        ev(2, "2026-10-18T12:02:00Z", "A", dst="1.2.3.4", category="network"),
        ev(3, "2026-10-18T12:03:00Z", "B", dst="1.2.3.4", category="network"),
    ]
    assert ids(_run_eql(SEQ, events)) == [1, 2]


def test_the_wrong_order_a_different_host_or_too_long_a_gap_is_not_a_match():
    reverse = [ev(1, "2026-10-18T12:00:00Z", "A", dst="1.2.3.4", category="network"), ev(2, "2026-10-18T12:01:00Z", "A", process={"name": "cmd.exe"}, category="process")]
    assert ids(_run_eql(SEQ, reverse)) == []
    other_host = [ev(1, "2026-10-18T12:00:00Z", "A", process={"name": "cmd.exe"}, category="process"), ev(2, "2026-10-18T12:01:00Z", "B", dst="1.2.3.4", category="network")]
    assert ids(_run_eql(SEQ, other_host)) == []
    slow = [ev(1, "2026-10-18T12:00:00Z", "A", process={"name": "cmd.exe"}, category="process"), ev(2, "2026-10-18T12:06:00Z", "A", dst="1.2.3.4", category="network")]
    assert ids(_run_eql(SEQ, slow)) == [], "six minutes is past the five minute span"


def test_input_order_does_not_matter_events_are_ordered_by_their_time():
    shuffled = [ev(2, "2026-10-18T12:02:00Z", "A", dst="1.2.3.4", category="network"), ev(1, "2026-10-18T12:00:00Z", "A", process={"name": "cmd.exe"}, category="process")]
    assert ids(_run_eql(SEQ, shuffled)) == [1, 2]


def test_three_steps_and_no_span_and_no_by_work():
    body = "sequence [any where a == 1] [any where b == 2] [any where c == 3]"
    events = [ev(1, 100, "A", a=1), ev(2, 200, "B", b=2), ev(3, 300, "C", c=3), ev(4, 50, "Z", c=3)]
    assert ids(_run_eql(body, events)) == [1, 2, 3]


def test_every_completed_sequence_contributes_its_events_once():
    events = [ev(1, 1, "A", a=1), ev(2, 2, "A", b=2), ev(3, 3, "A", a=1), ev(4, 4, "A", b=2)]
    assert ids(_run_eql("sequence by host [any where a == 1] [any where b == 2]", events)) == [1, 2, 3, 4]


def test_a_named_category_must_match_the_events_own_category_when_it_has_one():
    events = [ev(1, 1, "A", a=1, category="file"), ev(2, 2, "A", b=2, category="network")]
    assert ids(_run_eql("sequence by host [process where a == 1] [network where b == 2]", events)) == [], "the first event is a file event, not a process"
    assert ids(_run_eql("sequence by host [file where a == 1] [network where b == 2]", events)) == [1, 2]


def test_events_without_a_readable_time_or_a_by_value_are_handled_honestly():
    matched, error = _run_eql(SEQ, [{"id": 1, "host": "A"}])
    assert matched == [] and error and "time" in error
    no_host = [{"id": 1, "timestamp": 1, "process": {"name": "cmd.exe"}}, {"id": 2, "timestamp": 2, "dst": "1.2.3.4"}]
    assert ids(_run_eql(SEQ, no_host)) == [], "without the by field they cannot be tied to one machine"


def test_unreadable_sequences_are_errors_not_guesses():
    for bad in ("sequence [process where a == 1]", "sequence by host [process where a == 1", "sequence [not a step] [process where a == 1]", "sequence by host with maxspan=5x [any where a == 1] [any where b == 2]"):
        matched, error = _run_eql(bad, [ev(1, 1, "A", a=1)])
        assert matched == [] and error, bad


def test_epoch_seconds_and_milliseconds_are_both_understood():
    events = [ev(1, 1_760_000_000, "A", a=1), ev(2, 1_760_000_030_000, "A", b=2)]  # seconds, then milliseconds, 30 seconds later
    assert ids(_run_eql("sequence by host with maxspan=1m [any where a == 1] [any where b == 2]", events)) == [1, 2]


def test_a_single_event_condition_still_works():
    assert ids(_run_eql('process where process.name == "cmd.exe"', [ev(1, 1, "A", process={"name": "cmd.exe"}), ev(2, 2, "A", process={"name": "x"})])) == [1]
