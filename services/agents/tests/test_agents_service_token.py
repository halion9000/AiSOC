"""Background graph/fusion calls use the agents service's own key when no user token is given."""
from app.tools import fusion, graph


def test_graph_falls_back_to_the_service_key(monkeypatch):
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    assert graph._headers(None) == {"Authorization": "Bearer aisoc_service_key"}
    assert graph._headers("") == {"Authorization": "Bearer aisoc_service_key"}


def test_callers_own_token_wins_for_the_graph(monkeypatch):
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    assert graph._headers("user-jwt") == {"Authorization": "Bearer user-jwt"}


def test_graph_no_token_anywhere_sends_nothing(monkeypatch):
    monkeypatch.delenv("AGENTS_API_TOKEN", raising=False)
    assert graph._headers(None) == {}


# ---- fusion is a DIFFERENT service: it gets its own token and never an API credential ----
def test_fusion_gets_the_fusion_token(monkeypatch):
    monkeypatch.setenv("AISOC_FUSION_SERVICE_TOKEN", "fusion-token")
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    assert fusion._headers(None) == {"Authorization": "Bearer fusion-token"}


def test_fusion_never_receives_an_api_credential(monkeypatch):
    monkeypatch.setenv("AGENTS_API_TOKEN", "aisoc_service_key")
    monkeypatch.delenv("AISOC_FUSION_SERVICE_TOKEN", raising=False)
    assert fusion._headers("a-users-api-jwt") == {}, "neither the caller's token nor AGENTS_API_TOKEN may be sent to fusion"
    monkeypatch.setenv("AISOC_FUSION_SERVICE_TOKEN", "fusion-token")
    assert "a-users-api-jwt" not in str(fusion._headers("a-users-api-jwt")) and "aisoc_service_key" not in str(fusion._headers("a-users-api-jwt"))


def test_fusion_no_token_configured_sends_nothing(monkeypatch):
    monkeypatch.delenv("AISOC_FUSION_SERVICE_TOKEN", raising=False)
    assert fusion._headers(None) == {}
