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


def test_eql_sequences_are_refused_not_approximated():
    matched, error = _run_eql('sequence by host [process where process.name == "cmd.exe"] [process where user == "bob"]', EVENTS)
    assert matched == [] and error and "sequence" in error
