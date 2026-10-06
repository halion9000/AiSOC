"""Background graph/fusion calls use the agents service's own key when no user token is given."""
from app.tools import fusion, graph


def test_falls_back_to_the_service_key(monkeypatch):
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    for mod in (graph, fusion):
        assert mod._headers(None) == {"Authorization": "Bearer aisoc_service_key"}
        assert mod._headers("") == {"Authorization": "Bearer aisoc_service_key"}


def test_callers_own_token_wins(monkeypatch):
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    for mod in (graph, fusion):
        assert mod._headers("user-jwt") == {"Authorization": "Bearer user-jwt"}


def test_no_token_anywhere_sends_nothing(monkeypatch):
    monkeypatch.delenv("AGENTS_API_TOKEN", raising=False)
    for mod in (graph, fusion):
        assert mod._headers(None) == {}
