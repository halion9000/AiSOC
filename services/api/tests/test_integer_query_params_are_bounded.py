"""Every integer query parameter has an upper bound, so an absurd value is a 422, not an error from the database.

FOUND by fuzzing the OpenAPI spec against a real server: GET /cases?offset=190547863906668642304 reached Postgres, overflowed a 64-bit
integer, and came back as "503 Database error" (and the cases handler logged an unhandled DBAPIError). The audit behind it found that 31 of
the API's 77 integer query parameters had NO upper bound: 16 `offset`, 9 `page`, 4 `limit` (declared as a plain `limit: int = 100`, so not
validated at all: `limit=1000000000` was accepted) and the investigation event cursors `since` and `step`.
They are now bounded (offset 1,000,000; page 100,000; limit 500 or 1000; event seq 1,000,000,000), and this test is derived from the live
OpenAPI schema, so a NEW unbounded integer query parameter fails the build. Unbounded `limit` also lets a caller ask for an arbitrarily
large result set.
"""

import uuid

import pytest
from app.api.v1 import deps
from app.api.v1.deps import CurrentUser
from app.db.rls import get_tenant_db
from app.main import app
from fastapi.testclient import TestClient

SPEC = app.openapi()
COMPONENTS = SPEC["components"]["schemas"]
# Integer query parameters that are DELIBERATELY unbounded, with the reason. Empty: none is.
UNBOUNDED_ALLOWED: dict[tuple[str, str], str] = {}


def _integer_schema(schema):
    schema = schema or {}
    while "$ref" in schema:
        schema = COMPONENTS[schema["$ref"].split("/")[-1]]
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            if option.get("type") == "integer":
                return option
        return _integer_schema(schema["anyOf"][0])
    return schema


def _integer_query_params():
    found = []
    for path, operations in SPEC["paths"].items():
        for method, operation in operations.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            for parameter in operation.get("parameters", []):
                schema = _integer_schema(parameter["schema"])
                if parameter["in"] == "query" and schema.get("type") == "integer":
                    found.append((parameter["name"], method.upper(), path, schema))
    return found


PARAMS = _integer_query_params()


def test_the_scan_sees_the_parameters_it_claims_to():
    """Guards the guard: an empty scan would make the next test pass vacuously."""
    names = {name for name, _, _, _ in PARAMS}
    assert len(PARAMS) >= 70 and {"offset", "page", "limit", "since", "step"} <= names


def test_every_integer_query_parameter_has_an_upper_bound():
    unbounded = [
        (name, f"{method} {path}")
        for name, method, path, schema in PARAMS
        if "maximum" not in schema and "exclusiveMaximum" not in schema and (name, path) not in UNBOUNDED_ALLOWED
    ]
    assert not unbounded, f"integer query parameters with no maximum (an absurd value reaches the database): {unbounded}"


def test_every_integer_query_parameter_has_a_lower_bound_too_except_where_negative_is_meaningful():
    missing = [
        (name, f"{method} {path}")
        for name, method, path, schema in PARAMS
        if name in {"offset", "page", "limit"} and "minimum" not in schema and "exclusiveMinimum" not in schema
    ]
    assert not missing, missing


def test_no_bound_is_so_large_that_the_value_can_still_overflow_a_64_bit_integer():
    too_big = [
        (name, f"{method} {path}", schema.get("maximum")) for name, method, path, schema in PARAMS if (schema.get("maximum") or 0) >= 2**62
    ]
    assert not too_big, too_big


def test_the_bounds_are_wide_enough_for_what_clients_and_cipher_actually_ask_for():
    """CORE's tools page with offset up to 100,000 and limit up to 200; the web console asks for limit 100. None of that may be refused."""
    by_name: dict[str, list[int]] = {}
    for name, _, _, schema in PARAMS:
        if "maximum" in schema:
            by_name.setdefault(name, []).append(schema["maximum"])
    assert min(by_name["offset"]) >= 100_000 and min(by_name["page"]) >= 1000
    assert min(by_name["limit"]) >= 100, by_name["limit"]


def _client():
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="platform_admin", email="p@example.com", scopes=None)

    async def fake_db():
        yield None

    app.dependency_overrides[get_tenant_db] = fake_db
    app.dependency_overrides[deps.get_db] = fake_db
    app.dependency_overrides[deps.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


RUN = uuid.uuid4()
REJECTED = [
    ("/api/v1/cases?offset=190547863906668642304", "the exact value the fuzzer found"),
    ("/api/v1/cases?offset=1000001", "one past the offset bound"),
    ("/api/v1/assets?offset=99999999999999999999", "assets offset"),
    ("/api/v1/threat-intel/iocs?offset=99999999999999999999", "iocs offset"),
    ("/api/v1/alerts?page=99999999999999999999", "alerts page"),
    ("/api/v1/audit?page=100001", "one past the page bound"),
    ("/api/v1/admin/tenants?limit=1000000000", "a plain `limit: int = 200`, previously not validated at all"),
    ("/api/v1/waitlist/entries?limit=1000001", "waitlist limit"),
    ("/api/v1/feedback/overrides?limit=99999999", "feedback limit"),
    ("/api/v1/playbooks/runs?limit=100000", "playbook runs limit"),
    (f"/api/v1/investigations/{RUN}/events?since=99999999999999999999", "event cursor"),
    (f"/api/v1/investigations/{RUN}/explain?step=99999999999999999999", "explain step"),
]


@pytest.fixture(autouse=True)
def _clean():
    yield
    app.dependency_overrides.clear()


@pytest.mark.parametrize("url,why", REJECTED)
def test_an_absurd_value_is_a_422_that_names_the_bound_not_a_database_error(url, why):
    response = _client().get(url)
    assert response.status_code == 422, f"{why}: got {response.status_code} {response.text[:120]}"
    assert "less than or equal to" in response.text, why


@pytest.mark.parametrize(
    "url", ["/api/v1/cases?offset=0&limit=50", "/api/v1/alerts?page=1", "/api/v1/threat-intel/iocs?offset=100000&limit=200"]
)
def test_the_values_clients_really_use_still_pass_validation(url):
    """Validation passes (the request then reaches the handler, which has no database here and answers 500/503, never 422)."""
    assert _client().get(url).status_code != 422
