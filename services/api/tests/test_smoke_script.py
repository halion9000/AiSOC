"""The smoke script classifies what it sees and exits non-zero when anything fails or is slow."""

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "smoke-api.py"
spec = importlib.util.spec_from_file_location("smoke_api", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
sys.modules["smoke_api"] = smoke
spec.loader.exec_module(smoke)


def test_an_answer_is_ok_slow_or_failed():
    assert smoke.classify(200, 0.4, 8) == "ok"
    assert smoke.classify(200, 12.0, 8) == "slow"
    assert smoke.classify(500, 0.1, 8) == "failed"
    assert smoke.classify(401, 0.1, 8) == "failed"
    assert smoke.classify(None, 60.0, 8) == "failed", "no answer at all is a failure, however long it took"


def test_run_asks_every_endpoint_once_with_the_token_and_reports_each():
    asked = []

    def fake(base, path, token, timeout):
        asked.append((base, path, token))
        return (500, 0.2, "db down") if path.endswith("/rollup") else (200, 0.1, "")

    results = smoke.run("http://x", "tok", 8, 5, endpoints=[("a", "/api/v1/a"), ("rollup", "/api/v1/devices/rollup")], get=fake)
    assert asked == [("http://x", "/api/v1/a", "tok"), ("http://x", "/api/v1/devices/rollup", "tok")]
    assert [(r["name"], r["verdict"]) for r in results] == [("a", "ok"), ("rollup", "failed")]
    assert results[1]["detail"] == "db down"


def test_the_exit_status_is_zero_only_when_everything_answered_well(capsys, monkeypatch):
    monkeypatch.setattr(smoke, "ENDPOINTS", [("a", "/a")])
    monkeypatch.setattr(smoke, "fetch", lambda *a: (200, 0.1, ""))
    monkeypatch.setattr(smoke, "run", lambda base, token, slow, timeout: [{"name": "a", "path": "/a", "status": 200, "seconds": 0.1, "detail": "", "verdict": "ok"}])
    assert smoke.main(["--token", "t"]) == 0
    monkeypatch.setattr(smoke, "run", lambda base, token, slow, timeout: [{"name": "a", "path": "/a", "status": 500, "seconds": 0.1, "detail": "boom", "verdict": "failed"}])
    assert smoke.main(["--token", "t"]) == 1
    assert "Look at: a" in capsys.readouterr().out


def test_without_a_token_it_says_so_and_never_prints_one(capsys, monkeypatch):
    monkeypatch.delenv("AISOC_SMOKE_TOKEN", raising=False)
    assert smoke.main([]) == 2
    assert "token" in capsys.readouterr().err.lower()


def test_every_listed_endpoint_is_a_get_path_under_the_api():
    for name, path in smoke.ENDPOINTS:
        assert path.startswith("/api/v1/") and " " not in path, name


def test_every_listed_endpoint_is_a_real_get_route_of_the_api():
    """The list must not drift from the API: a path that no longer exists would report 404 as a failure forever."""
    import re

    from app.main import app

    routes = [(re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", p) + "$"), ops) for p, ops in app.openapi()["paths"].items() if "get" in ops]
    missing = []
    for name, path in smoke.ENDPOINTS:
        bare = path.split("?")[0]
        if not any(rx.match(bare) for rx, _ in routes):
            missing.append(f"{name}: {bare}")
    assert not missing, f"not GET routes of the API: {missing}"
