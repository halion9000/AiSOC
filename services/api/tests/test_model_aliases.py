"""The API service's task role -> gateway alias mapping."""

import pytest
from app.services.model_aliases import ROLES, resolve_model_alias


@pytest.mark.parametrize("role", sorted(ROLES))
def test_every_role_maps_to_its_aisoc_alias_by_default(role, monkeypatch):
    monkeypatch.delenv(f"AISOC_MODEL_PIN_{role.upper()}", raising=False)
    assert resolve_model_alias(role) == f"aisoc-{role}"


def test_a_pin_replaces_the_alias_for_that_role_only(monkeypatch):
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "anthropic/claude-test")
    monkeypatch.delenv("AISOC_MODEL_PIN_SUMMARY", raising=False)
    assert resolve_model_alias("triage") == "anthropic/claude-test"
    assert resolve_model_alias("summary") == "aisoc-summary"


def test_a_blank_pin_is_no_pin_and_whitespace_around_one_is_trimmed(monkeypatch):
    monkeypatch.setenv("AISOC_MODEL_PIN_NL", "   ")
    assert resolve_model_alias("nl") == "aisoc-nl"
    monkeypatch.setenv("AISOC_MODEL_PIN_NL", "  openai/gpt-test \n")
    assert resolve_model_alias("nl") == "openai/gpt-test"


def test_the_role_is_looked_up_case_insensitively_in_the_variable_name(monkeypatch):
    monkeypatch.setenv("AISOC_MODEL_PIN_COPILOT", "pinned")
    assert resolve_model_alias("copilot") == "pinned"


def test_the_roles_are_the_ones_the_endpoints_ask_for():
    assert {"triage", "summary", "nl", "report"} <= ROLES
