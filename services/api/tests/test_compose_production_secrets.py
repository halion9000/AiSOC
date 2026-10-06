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
    api, ingest, rt = _env("api"), _env("ingest-worker"), _env("realtime")
    assert _source_var(api["SECRET_KEY"]) == _source_var(ingest["JWT_SECRET"]) == "SECRET_KEY"
    assert _source_var(api["REALTIME_INTERNAL_TOKEN"]) == _source_var(rt["INTERNAL_TOKEN"]) == "REALTIME_INTERNAL_TOKEN"
    assert _source_var(api["AISOC_REALTIME_JWT_SECRET"]) == _source_var(rt["AISOC_REALTIME_JWT_SECRET"]) == "AISOC_REALTIME_JWT_SECRET"


def test_environment_is_one_switch_for_all_three():
    for svc, key in (("api", "ENVIRONMENT"), ("ingest-worker", "ENV"), ("realtime", "ENVIRONMENT")):
        assert _source_var(_env(svc)[key]) == "AISOC_ENVIRONMENT", f"{svc} {key} must follow AISOC_ENVIRONMENT"


def test_production_secrets_are_never_hardcoded_literals():
    api = _env("api")
    for key in ("SECRET_KEY", "JWT_SECRET", "METRICS_TOKEN", "REALTIME_INTERNAL_TOKEN", "AISOC_REALTIME_JWT_SECRET", "AISOC_CREDENTIAL_KEY"):
        _source_var(api[key])
