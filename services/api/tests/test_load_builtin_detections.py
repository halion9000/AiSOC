"""The built-in detection loader reads AiSOC's shipped rule files correctly (no database needed; the database behaviour is in test_load_builtin_detections_postgres.py)."""

from pathlib import Path

from app.scripts.load_builtin_detections import detections_dir, normalise, read_rules

RULE = """id: det-test-001
name: Test rule
description: A rule.
version: 2.1.0
severity: high
tags:
- mitre.attack.t1562.001
- mitre.attack.defense-evasion
- tlp.white
category: endpoint
log_source: {product: edr, service: process-create}
detection:
  condition: |
    image_basename == "powershell.exe"
enabled: true
"""


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_a_rule_file_becomes_the_expected_columns():
    row = normalise(RULE, "endpoint/test.yaml")
    assert row is not None
    assert row["source_id"] == "det-test-001" and row["name"] == "Test rule"
    assert row["severity"] == "high" and row["status"] == "active" and row["version"] == 2
    assert row["mitre_techniques"] == ["T1562.001"], "technique ids are upper-cased and kept with their sub-technique"
    assert row["mitre_tactics"] == ["defense-evasion"], "a tactic tag is kept; the generic 'tlp' tags are not mistaken for one"
    assert (
        row["provenance"]["source"] == "aisoc-builtin"
        and row["provenance"]["source_id"] == "det-test-001"
        and row["provenance"]["file"] == "endpoint/test.yaml"
    )
    assert (
        row["provenance"]["sha256"] != normalise(RULE + "# edited\n", "endpoint/test.yaml")["provenance"]["sha256"]
    ), "a changed file has a different fingerprint"
    assert row["rule_body"] == RULE, "the file text is stored unchanged"


def test_a_disabled_rule_is_loaded_as_disabled_not_active():
    row = normalise(RULE.replace("enabled: true", "enabled: false"), "x.yaml")
    assert row is not None and row["status"] == "disabled"


def test_files_that_are_not_rules_are_skipped_not_loaded():
    assert normalise("id: pb-1\nname: A playbook\ntrigger: {}\nsteps: []\n", "p.yaml") is None, "a playbook has no detection block"
    assert normalise("just: [unclosed", "bad.yaml") is None, "unparseable YAML is skipped, never raises"
    assert normalise("detection: {condition: x}\n", "noid.yaml") is None, "a rule needs an id and a name"


def test_imported_quarantined_and_fixture_trees_are_not_first_party(tmp_path):
    _write(tmp_path, "endpoint/own.yaml", RULE)
    _write(tmp_path, "sigma-imports/endpoint/up.yaml", RULE.replace("det-test-001", "det-up-1"))
    _write(tmp_path, "endpoint/_quarantine/q.yaml", RULE.replace("det-test-001", "det-q-1"))
    _write(tmp_path, "fixtures/f.yaml", RULE.replace("det-test-001", "det-f-1"))
    rules, skipped = read_rules(tmp_path)
    assert [r["source_id"] for r in rules] == ["det-test-001"]
    assert skipped == [], "excluded trees are not even counted as skipped; only first-party non-rules are"


def test_a_repeated_id_is_loaded_once():
    # two files claiming the same id must not become two rows
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write(root, "a/one.yaml", RULE)
        _write(root, "b/two.yaml", RULE)
        rules, skipped = read_rules(root)
        assert len(rules) == 1 and len(skipped) == 1


def test_the_shipped_rules_all_load():
    """The real folder: every first-party rule file is read, with valid values, and only the non-rule files are skipped."""
    root = detections_dir()
    assert root is not None, "run from a checkout (or set AISOC_DETECTIONS_DIR)"
    rules, skipped = read_rules(root)
    assert len(rules) >= 800, f"expected the shipped rule set, got {len(rules)}"
    assert len({r["source_id"] for r in rules}) == len(rules)
    assert all(r["severity"] in {"low", "medium", "high", "critical"} for r in rules)
    assert all(r["name"] and r["category"] and r["rule_body"] for r in rules)
    assert any(r["mitre_techniques"] for r in rules), "technique ids are being extracted from the shipped tags"
    assert len(skipped) < 100


def test_finding_the_folder_does_not_crash_when_the_script_is_only_a_few_folders_deep(tmp_path, monkeypatch):
    """Found live: in the container the script is /app/app/scripts/load_builtin_detections.py, where the checkout-relative fallback (four folders up) does not exist.
    Looking for the folder raised IndexError before it ever tried /app/detections."""
    monkeypatch.delenv("AISOC_DETECTIONS_DIR", raising=False)
    found = detections_dir(Path("/app/app/scripts/load_builtin_detections.py"))  # must not raise, whatever it finds
    assert found is None or found.is_dir()


def test_the_environment_override_is_used_even_from_a_shallow_location(tmp_path, monkeypatch):
    monkeypatch.setenv("AISOC_DETECTIONS_DIR", str(tmp_path))
    assert detections_dir(Path("/app/app/scripts/load_builtin_detections.py")) == tmp_path
