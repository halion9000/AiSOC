"""Qdrant point ids for ATT&CK techniques must be the same in every process.

``abs(hash(t.id))`` uses Python's per-process randomised string hash, so each restart minted different ids and re-embedding inserted a duplicate of every technique instead of replacing it.
"""

from __future__ import annotations

import os
import subprocess
import sys

from app.tools.mitre_full import technique_point_id


def test_point_id_is_a_stable_non_negative_63_bit_int():
    pid = technique_point_id("T1059.001")
    assert isinstance(pid, int) and 0 <= pid < 2**63
    assert pid == technique_point_id("T1059.001")
    assert pid != technique_point_id("T1059.002")


def test_point_id_is_identical_in_a_fresh_process_with_a_different_hash_seed():
    code = "from app.tools.mitre_full import technique_point_id as f; print(f('T1059.001'))"
    outs = {
        subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "PYTHONHASHSEED": seed}, check=True).stdout.strip()
        for seed in ("1", "2")
    }
    assert len(outs) == 1 and outs == {str(technique_point_id("T1059.001"))}
