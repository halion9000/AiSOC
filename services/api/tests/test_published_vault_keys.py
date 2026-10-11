"""A vault key that was committed to this repository must not be accepted in production.

A history scan (gitleaks over 1,429 commits) found that `.env.example` carried a VALID Fernet key as `AISOC_CREDENTIAL_KEY` in two commits
on 2026-05-13/14 (replaced by a placeholder in 14b10e15), and that two unit tests carried another until 77517e91. Anyone who copied
`.env.example` to `.env` in that window runs with a key anyone can read in the git history, and the vault accepts it because it is a valid
key. `PUBLISHED_FERNET_DIGESTS` holds their SHA-256 digests (not the keys, so the code does not publish them again) and
`warn_if_insecure_defaults` flags the primary key when it matches; `enforce_secure_defaults` then refuses to boot in production.
THESE TESTS MUST NOT CONTAIN THE REAL KEYS (that would re-publish them and trip the secret scanner), so the mechanism is tested with
freshly generated keys and a patched digest set; a separate test checks that the two real digests really are the historical values by
reading them from git, and is skipped where history is not available (a shallow clone).
"""

import hashlib
import re
import subprocess
import warnings
from pathlib import Path

import pytest
from app.core import config
from app.core.config import InsecureProductionDefaultsError, Settings, enforce_secure_defaults, warn_if_insecure_defaults
from cryptography.fernet import Fernet

REPO = Path(__file__).resolve().parents[3]
PUBLISHED = "published in this repository's git history"


def _settings(**overrides) -> Settings:
    base = {
        "ENVIRONMENT": "production",
        "SECRET_KEY": "a" * 64,
        "METRICS_TOKEN": "long-random-token",
        "PLUGIN_TRUST_MODE": "strict",
        "AISOC_CREDENTIAL_KEY": Fernet.generate_key().decode(),
        "JWT_SECRET": "b" * 64,
        "REALTIME_INTERNAL_TOKEN": "c" * 64,
        "AISOC_REALTIME_JWT_SECRET": "d" * 64,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def _messages(settings: Settings) -> list[str]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return warn_if_insecure_defaults(settings)


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@pytest.fixture
def published(monkeypatch):
    """A freshly generated key that this test run declares 'published'."""
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(config, "PUBLISHED_FERNET_DIGESTS", config.PUBLISHED_FERNET_DIGESTS | {_digest(key)})
    return key


def test_a_healthy_production_baseline_has_no_messages_at_all():
    """Guards the guard: if the baseline already warned about something else, the tests below could not tell their own message apart."""
    assert _messages(_settings()) == []


def test_a_published_key_as_the_primary_is_flagged_in_production(published):
    messages = _messages(_settings(AISOC_CREDENTIAL_KEY=published))
    assert len(messages) == 1 and PUBLISHED in messages[0]
    assert "AISOC_CREDENTIAL_KEY_ROTATION_FROM" in messages[0], "the message says how to rotate away from it"


def test_and_the_production_boot_is_refused(published):
    with pytest.raises(InsecureProductionDefaultsError, match="published"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            enforce_secure_defaults(_settings(AISOC_CREDENTIAL_KEY=published))


def test_the_message_never_contains_the_key_itself(published):
    assert published not in _messages(_settings(AISOC_CREDENTIAL_KEY=published))[0]


def test_whitespace_around_the_key_does_not_hide_it(published):
    assert PUBLISHED in _messages(_settings(AISOC_CREDENTIAL_KEY=f"  {published}\n"))[0]


def test_moving_a_published_key_to_the_rotation_setting_is_what_rotating_looks_like_and_is_allowed(published):
    assert _messages(_settings(AISOC_CREDENTIAL_KEY=Fernet.generate_key().decode(), AISOC_CREDENTIAL_KEY_ROTATION_FROM=published)) == []


@pytest.mark.parametrize("environment", ["development", "test"])
def test_a_developer_environment_is_not_refused(published, environment):
    assert not [m for m in _messages(_settings(ENVIRONMENT=environment, AISOC_CREDENTIAL_KEY=published)) if PUBLISHED in m]


def test_a_fresh_key_is_not_flagged():
    assert not [m for m in _messages(_settings()) if PUBLISHED in m]


def test_an_empty_key_gets_only_the_existing_message_not_this_one():
    messages = _messages(_settings(AISOC_CREDENTIAL_KEY=""))
    assert any("is empty" in m for m in messages) and not any(PUBLISHED in m for m in messages)


def test_the_placeholder_in_env_example_is_not_this_checks_business():
    """It is not a valid Fernet key, so the vault itself refuses it; this check is for keys that are valid but public."""
    assert not config._is_published_fernet_key("replace-me-with-a-freshly-generated-fernet-key")


def test_the_digest_set_is_well_formed():
    assert len(config.PUBLISHED_FERNET_DIGESTS) == 2
    assert all(re.fullmatch(r"[0-9a-f]{64}", d) for d in config.PUBLISHED_FERNET_DIGESTS)


def _git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=30)


def _historical(rev, path):
    result = _git("show", f"{rev}:{path}")
    return result.stdout if result.returncode == 0 else None


def test_the_real_digests_are_the_historical_values_read_from_git():
    """The link between the digests in the code and the keys that were actually published. Skipped where the history is not there."""
    env_example = _historical("d8397a0b", ".env.example")
    tests_before = _historical("77517e91^", "services/api/tests/test_security_defaults.py")
    if env_example is None or tests_before is None:
        pytest.skip("the git history that contains the published keys is not available (shallow clone)")
    env_key = next(line.partition("=")[2].strip() for line in env_example.splitlines() if line.startswith("AISOC_CREDENTIAL_KEY="))
    test_key = re.search(r'"AISOC_CREDENTIAL_KEY": "([^"]+)"', tests_before).group(1)
    Fernet(env_key)
    Fernet(test_key)
    assert {_digest(env_key), _digest(test_key)} == set(config.PUBLISHED_FERNET_DIGESTS)
    assert config._is_published_fernet_key(env_key) and config._is_published_fernet_key(test_key)
