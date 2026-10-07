"""docker-compose.yml: production secrets come from .env, and paired secrets stay paired.

CORE writes SECRET_KEY, REALTIME_INTERNAL_TOKEN, AISOC_REALTIME_JWT_SECRET (and
JWT_SECRET, METRICS_TOKEN, AISOC_ENVIRONMENT) into .env. Several services must
receive the SAME value or production breaks silently:
  api SECRET_KEY            == ingest-worker JWT_SECRET  (ingest verifies API-signed JWTs)
  api REALTIME_INTERNAL_TOKEN == realtime INTERNAL_TOKEN (realtime accepts anyone if empty)
  api AISOC_REALTIME_JWT_SECRET == realtime AISOC_REALTIME_JWT_SECRET (ticket signing)
"""
import re
from pathlib import Path

import yaml

COMPOSE = Path(__file__).resolve().parents[3] / "docker-compose.yml"


def _env(service: str) -> dict:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    env = services[service].get("environment") or {}
    return env if isinstance(env, dict) else dict(e.split("=", 1) for e in env if "=" in e)


def _source_var(value: str) -> str:
    m = re.fullmatch(r"\$\{(\w+)(?::-[^}]*)?\}", str(value).strip())
    assert m, f"{value!r} must come from .env as ${{VAR}} or ${{VAR:-default}}, not a literal"
    return m.group(1)


def test_paired_secrets_read_the_same_env_var():
    api, ingest, rt, agents = _env("api"), _env("ingest-worker"), _env("realtime"), _env("agents")
    assert _source_var(api["SECRET_KEY"]) == _source_var(ingest["JWT_SECRET"]) == "SECRET_KEY"
    assert _source_var(api["REALTIME_INTERNAL_TOKEN"]) == _source_var(rt["INTERNAL_TOKEN"]) == "REALTIME_INTERNAL_TOKEN"
    # agents: accepts the API's proxied calls and posts to realtime with this token
    assert _source_var(agents["INTERNAL_TOKEN"]) == "REALTIME_INTERNAL_TOKEN"
    assert _source_var(agents["AGENTS_API_TOKEN"]) == "AGENTS_API_TOKEN"
    assert _source_var(api["AISOC_REALTIME_JWT_SECRET"]) == _source_var(rt["AISOC_REALTIME_JWT_SECRET"]) == "AISOC_REALTIME_JWT_SECRET"


def test_environment_is_one_switch_for_all_three():
    for svc, key in (("api", "ENVIRONMENT"), ("ingest-worker", "ENV"), ("realtime", "ENVIRONMENT"), ("agents", "ENVIRONMENT")):
        assert _source_var(_env(svc)[key]) == "AISOC_ENVIRONMENT", f"{svc} {key} must follow AISOC_ENVIRONMENT"


def test_production_secrets_are_never_hardcoded_literals():
    api = _env("api")
    for key in ("SECRET_KEY", "JWT_SECRET", "METRICS_TOKEN", "REALTIME_INTERNAL_TOKEN", "AISOC_REALTIME_JWT_SECRET", "AISOC_CREDENTIAL_KEY"):
        _source_var(api[key])


def test_osquery_internal_token_is_shared_by_the_api_and_the_service():
    """The API calls the osquery service with this token; the service enforces it. They must read the SAME variable."""
    api, osq = _env("api"), _env("osquery-tls")
    assert _source_var(api["AISOC_OSQUERY_TLS_API_TOKEN"]) == _source_var(osq["AISOC_OSQUERY_TLS_API_TOKEN"]) == "AISOC_OSQUERY_TLS_API_TOKEN"


def test_osquery_follows_the_one_environment_switch():
    """If this stayed at its own default, production would still treat the osquery service as development."""
    assert _source_var(_env("osquery-tls")["AISOC_OSQUERY_TLS_ENVIRONMENT"]) == "AISOC_ENVIRONMENT"


def _dockerfile_port(service_dir: str) -> int:
    """The port the container REALLY listens on: the --port in the Dockerfile's CMD (no compose `command:` overrides it)."""
    text = (COMPOSE.parent / "services" / service_dir / "Dockerfile").read_text(encoding="utf-8")
    m = re.search(r'CMD\s*\[[^\]]*"--port",\s*"(\d+)"', text)
    assert m, f"no --port in services/{service_dir}/Dockerfile CMD"
    return int(m.group(1))


def test_osquery_ports_match_what_the_container_really_listens_on():
    """Compose forwarded host 8091 to container 8007 while the Dockerfile started the service on 9001: the
    mapping reached nothing, so agents could not enroll through it and the API could not reach it."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    assert "command" not in services["osquery-tls"] and "entrypoint" not in services["osquery-tls"], "an override would make the Dockerfile port irrelevant"
    real = _dockerfile_port("osquery-tls")
    mapped = [int(str(p).rsplit(":", 1)[1]) for p in services["osquery-tls"]["ports"]]
    assert mapped == [real], f"compose forwards to container port(s) {mapped}, the service listens on {real}"
    assert _env("api")["OSQUERY_TLS_URL"] == f"http://osquery-tls:{real}"
    assert str(services["osquery-tls"]["ports"][0]).startswith("127.0.0.1:8091:"), "the host port agents are documented to use (8091) must not change"


def test_the_enroll_secret_is_read_from_env_not_hardcoded():
    _source_var(_env("osquery-tls")["AISOC_OSQUERY_TLS_ENROLL_SECRET"])


def test_actions_service_token_is_shared_by_the_service_and_its_callers():
    """The actions service has always demanded this token, but compose never gave it one, and the Slack bot read a
    DIFFERENT variable (AISOC_SLACK_ACTIONS_TOKEN) that nothing set on the other side, so the two could never match."""
    actions, slack = _env("actions"), _env("slack-bot")
    assert _source_var(actions["AISOC_ACTIONS_SERVICE_TOKEN"]) == _source_var(slack["AISOC_ACTIONS_SERVICE_TOKEN"]) == "AISOC_ACTIONS_SERVICE_TOKEN"


def test_connectors_token_is_shared_by_the_api_and_the_service():
    """The API sends this token; the connectors service enforces it. They must read the SAME variable."""
    api, conn = _env("api"), _env("connectors")
    assert _source_var(api["AISOC_CONNECTORS_SERVICE_TOKEN"]) == _source_var(conn["AISOC_CONNECTORS_SERVICE_TOKEN"]) == "AISOC_CONNECTORS_SERVICE_TOKEN"


def test_connectors_follows_the_one_environment_switch():
    """If it stayed at its own default, production would still treat the connectors service as development (open)."""
    assert _source_var(_env("connectors")["AISOC_CONNECTORS_ENVIRONMENT"]) == "AISOC_ENVIRONMENT"


def test_the_api_reaches_connectors_on_the_port_the_container_really_listens_on():
    """The API defaulted to http://connectors:8003, which is the FUSION service's port: every API->connectors call
    (case fan-out, federated query, catalog, test-connection, resource config) went to a dead port."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    dockerfile = (COMPOSE.parent / "services" / "connectors" / "Dockerfile").read_text(encoding="utf-8")
    real = int(re.search(r"^EXPOSE\s+(\d+)", dockerfile, re.M).group(1))
    assert [int(str(p).rsplit(":", 1)[1]) for p in services["connectors"]["ports"]] == [real]
    assert _env("api")["CONNECTORS_SERVICE_URL"] == f"http://connectors:{real}"
    fusion = (COMPOSE.parent / "services" / "fusion" / "Dockerfile").read_text(encoding="utf-8")
    fusion_port = int(re.search(r"^EXPOSE\s+(\d+)", fusion, re.M).group(1))
    assert real != fusion_port, f"connectors and fusion cannot share port {real}"
    assert _env("api")["CONNECTORS_SERVICE_URL"] != f"http://connectors:{fusion_port}", "that is the fusion service's port"


def test_threatintel_token_is_shared_by_the_service_and_the_agents_that_call_it():
    ti, agents = _env("threatintel"), _env("agents")
    assert _source_var(ti["AISOC_THREATINTEL_SERVICE_TOKEN"]) == _source_var(agents["AISOC_THREATINTEL_SERVICE_TOKEN"]) == "AISOC_THREATINTEL_SERVICE_TOKEN"
    assert _source_var(ti["ENVIRONMENT"]) == "AISOC_ENVIRONMENT", "an unset environment would leave the service open in production"


def test_fusion_token_is_shared_by_the_service_and_both_callers():
    fusion, agents, api = _env("fusion"), _env("agents"), _env("api")
    names = {_source_var(x["AISOC_FUSION_SERVICE_TOKEN"]) for x in (fusion, agents, api)}
    assert names == {"AISOC_FUSION_SERVICE_TOKEN"}
    assert _source_var(fusion["ENVIRONMENT"]) == "AISOC_ENVIRONMENT"
