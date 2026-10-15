"""Which indicators on an alert become Threat Intel entries."""

from app.services.iocs_from_alerts import indicators_for_alert

SHA = "a" * 63 + "B"


def test_public_ips_and_sha256_only():
    got = indicators_for_alert(
        ["8.8.8.8", "10.1.2.3", "127.0.0.1", "169.254.1.1", "192.168.0.9", "not-an-ip", "2001:4860:4860::8888", 7],
        {"file": {"sha256": SHA}},
    )
    assert got == [("ip", "8.8.8.8"), ("ip", "2001:4860:4860::8888"), ("file_hash_sha256", SHA.lower())]


def test_repeats_collapse_and_odd_hashes_are_ignored():
    got = indicators_for_alert(["8.8.8.8", " 8.8.8.8 "], {"a": SHA, "b": SHA.lower(), "short": "abc123", "long": "f" * 65})
    assert got == [("ip", "8.8.8.8"), ("file_hash_sha256", SHA.lower())]


def test_nothing_in_nothing_out():
    assert indicators_for_alert(None, None) == []
    assert indicators_for_alert([], {"source": "huntress"}) == []
