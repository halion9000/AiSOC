"""A lake CONNECTION failure must not put the backend's host and port in the response; an error the SERVER reports about the analyst's
query still must.

Found by fuzzing the API with ClickHouse not running: `lake backend error: ... Connection refused (localhost:9000)`, the internal address
shown to any caller who can run a lake query. The ClickHouse layer funnelled every driver failure into one `LakeQueryError(f"clickhouse
query failed: {message}")`, mixing two different things: a connection problem (infrastructure: the text names the host and port) and a
`ServerException` (the server's complaint about the analyst's own SQL: useful, and about their own input). The driver is a soft dependency
and is deliberately not imported, so the two are told apart by exception CLASS NAME, the way timeouts were already sniffed by their text.
The schema lookup takes no analyst input at all, so every failure there is infrastructure and the message is generic; the detail goes to
the log in both cases, where an operator needs it.
"""

import logging

import pytest
from app.db import clickhouse
from app.db.clickhouse import LakeQueryError, LakeQueryTimeoutError

INTERNAL = "Code: 210. DB::NetworkException: Connection refused (clickhouse-internal.corp:9000)"
GENERIC_QUERY = "clickhouse query failed: the lake backend could not be reached"


def _named(name, base=Exception):
    """An exception class with the NAME of a driver class (the driver itself is not imported by the code under test)."""
    return type(name, (base,), {})


class _Client:
    def __init__(self, exc):
        self.exc = exc

    def execute(self, *args, **kwargs):
        raise self.exc


@pytest.fixture
def failing(monkeypatch):
    def install(exc):
        async def client():
            return _Client(exc)

        monkeypatch.setattr(clickhouse, "get_clickhouse_client", client)

    return install


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["NetworkError", "SocketTimeoutError", "UnexpectedPacketFromServerError", "UnknownPacketFromServerError"])
async def test_a_driver_connection_failure_is_generic_and_carries_no_host_or_port(failing, name):
    failing(_named(name)(INTERNAL))
    with pytest.raises(LakeQueryError) as raised:
        await clickhouse.execute_lake_query("SELECT 1")
    assert str(raised.value) == GENERIC_QUERY
    assert "clickhouse-internal" not in str(raised.value) and "9000" not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [ConnectionRefusedError(INTERNAL), OSError(INTERNAL)])
async def test_a_socket_level_failure_is_generic_too(failing, exc):
    failing(exc)
    with pytest.raises(LakeQueryError) as raised:
        await clickhouse.execute_lake_query("SELECT 1")
    assert str(raised.value) == GENERIC_QUERY


@pytest.mark.asyncio
async def test_the_detail_goes_to_the_log_for_the_operator_and_stays_on_the_exception_chain(failing, caplog):
    cause = _named("NetworkError")(INTERNAL)
    failing(cause)
    with caplog.at_level(logging.WARNING, logger=clickhouse.logger.name):
        with pytest.raises(LakeQueryError) as raised:
            await clickhouse.execute_lake_query("SELECT 1")
    assert "clickhouse-internal.corp:9000" in caplog.text
    assert raised.value.__cause__ is cause


@pytest.mark.asyncio
async def test_an_error_the_server_reports_about_the_analysts_query_is_still_shown_to_them(failing):
    failing(_named("ServerException")("Code: 62. DB::Exception: Syntax error: failed at position 8 ('FORM')"))
    with pytest.raises(LakeQueryError) as raised:
        await clickhouse.execute_lake_query("SELECT * FORM events")
    assert "Syntax error" in str(raised.value) and str(raised.value) != GENERIC_QUERY


@pytest.mark.asyncio
async def test_a_server_side_timeout_is_still_a_timeout_not_a_connection_failure(failing):
    failing(_named("ServerException")("Code: 159. DB::Exception: Timeout exceeded: TIMEOUT_EXCEEDED"))
    with pytest.raises(LakeQueryTimeoutError):
        await clickhouse.execute_lake_query("SELECT 1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        _named("NetworkError")(INTERNAL),
        _named("ServerException")("Code: 60. DB::Exception: Table system.columns is unavailable (clickhouse-internal.corp)"),
        RuntimeError("anything"),
    ],
)
async def test_every_schema_lookup_failure_is_generic_because_no_analyst_input_reaches_it(failing, exc):
    failing(exc)
    with pytest.raises(LakeQueryError) as raised:
        await clickhouse.fetch_lake_schema()
    assert str(raised.value) == "clickhouse schema lookup failed" and "clickhouse-internal" not in str(raised.value)


@pytest.mark.asyncio
async def test_the_schema_failure_detail_is_logged(failing, caplog):
    failing(_named("NetworkError")(INTERNAL))
    with caplog.at_level(logging.WARNING, logger=clickhouse.logger.name):
        with pytest.raises(LakeQueryError):
            await clickhouse.fetch_lake_schema()
    assert "clickhouse-internal.corp:9000" in caplog.text


def test_the_classifier_knows_the_four_driver_names_and_os_errors_and_nothing_else():
    assert all(clickhouse._is_connection_failure(_named(n)("x")) for n in clickhouse._CONNECTION_FAILURE_NAMES)
    assert clickhouse._is_connection_failure(ConnectionResetError("x")) and clickhouse._is_connection_failure(OSError("x"))
    assert not clickhouse._is_connection_failure(_named("ServerException")("x")) and not clickhouse._is_connection_failure(ValueError("x"))
