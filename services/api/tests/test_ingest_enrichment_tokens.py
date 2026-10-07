"""The API sends the ingest and enrichment tokens to those services, and only to them.

Ingest accepted events for ANY tenant named in an X-Tenant-ID header with no authentication; enrichment spends commercial threat-intel
vendor quota for anyone who can reach it. Both now require a bearer token. The API's callers are the enrichment gateway and the graph
WebSocket proxy (which also named a host, `ingest`, that does not exist: the compose service is `ingest-worker`).
"""
import ast
import re
from pathlib import Path

import pytest
import yaml

from app.core.internal_auth import enrichment_service_headers, ingest_service_headers

APP = Path(__file__).resolve().parents[1] / "app"
ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("helper,var", [(ingest_service_headers, "AISOC_INGEST_SERVICE_TOKEN"), (enrichment_service_headers, "AISOC_ENRICHMENT_SERVICE_TOKEN")])
def test_the_helpers_send_a_stripped_bearer_token_or_nothing(monkeypatch, helper, var):
    monkeypatch.setenv(var, "  tok-123\n")
    assert helper() == {"Authorization": "Bearer tok-123"}
    for blank in ("", "   "):
        monkeypatch.setenv(var, blank)
        assert helper() == {}
    monkeypatch.delenv(var)
    assert helper() == {}


def test_each_helper_reads_only_its_own_variable(monkeypatch):
    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", "ingest-tok")
    monkeypatch.setenv("AISOC_ENRICHMENT_SERVICE_TOKEN", "enrich-tok")
    assert ingest_service_headers() == {"Authorization": "Bearer ingest-tok"}
    assert enrichment_service_headers() == {"Authorization": "Bearer enrich-tok"}


def _calls(path, func_name):
    tree = ast.parse((APP / path).read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == func_name]


def test_the_enrichment_gateway_client_sends_the_enrichment_token():
    calls = _calls("api/v1/endpoints/enrichment.py", "httpx.AsyncClient")
    assert calls
    for call in calls:
        assert [ast.unparse(k.value) for k in call.keywords if k.arg == "headers"] == ["enrichment_service_headers()"], call.lineno


def test_the_graph_websocket_proxy_sends_the_ingest_token_and_names_a_real_host():
    calls = _calls("api/v1/endpoints/graph_ws.py", "aconnect_ws")
    assert len(calls) == 1
    assert [ast.unparse(k.value) for k in calls[0].keywords if k.arg == "headers"] == ["ingest_service_headers()"]
    source = (APP / "api/v1/endpoints/graph_ws.py").read_text(encoding="utf-8")
    assert 'ws://ingest-worker:8080/' in source and 'ws://ingest:8080/' not in source


def test_each_token_is_only_ever_sent_by_the_modules_meant_to_send_it():
    """Sending one from some other client would hand the credential to a different host."""
    for helper, allowed in (("ingest_service_headers", {"api/v1/endpoints/graph_ws.py"}), ("enrichment_service_headers", {"api/v1/endpoints/enrichment.py"})):
        users = {str(f.relative_to(APP)) for f in APP.rglob("*.py") if helper in f.read_text(encoding="utf-8")} - {"core/internal_auth.py"}
        assert users == allowed, (helper, users)


# --------------------------------------------------------------------------- compose ----
SERVICES = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]


def _env(name):
    e = SERVICES[name].get("environment") or {}
    return e if isinstance(e, dict) else dict(x.split("=", 1) for x in e if "=" in x)


def _ref(value):
    return re.match(r"\$\{(\w+)", str(value)).group(1)


def test_ingest_token_is_one_secret_shared_by_the_service_and_every_caller():
    names = {_ref(_env(s)["AISOC_INGEST_SERVICE_TOKEN"]) for s in ("ingest-worker", "connectors", "osquery-tls", "api")}
    assert names == {"AISOC_INGEST_SERVICE_TOKEN"}


def test_enrichment_token_is_shared_by_the_service_and_the_api_gateway():
    assert _ref(_env("enrichment")["AISOC_ENRICHMENT_SERVICE_TOKEN"]) == _ref(_env("api")["AISOC_ENRICHMENT_SERVICE_TOKEN"]) == "AISOC_ENRICHMENT_SERVICE_TOKEN"


@pytest.mark.parametrize("name,service", [("ingest", "ingest-worker"), ("enrichment", "enrichment")])
def test_the_ports_callers_use_are_the_ports_the_dockerfiles_expose(name, service):
    port = int(re.search(r"^EXPOSE\s+(\d+)", (ROOT / "services" / name / "Dockerfile").read_text(encoding="utf-8"), re.M).group(1))
    assert any(str(p).split("#")[0].strip().endswith(f":{port}") for p in SERVICES[service]["ports"]), SERVICES[service]["ports"]
    if name == "ingest":
        assert _env("osquery-tls")["AISOC_INGEST_BASE_URL"] == f"http://ingest-worker:{port}"
    else:
        assert _env("api")["ENRICHMENT_URL"] == f"http://enrichment:{port}"
