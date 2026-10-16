#!/usr/bin/env python3
"""Prove the widened cross-runtime differential detects one disagreement."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys

import differential


def main() -> int:
    here = Path(__file__).resolve().parent
    corpus = json.loads((here.parent / "conformance" / "fixtures.json").read_text(encoding="utf-8"))
    inputs = differential.comparison_inputs(corpus, here / "public_suffix_rules.tsv")
    for probe in differential.PROBES:
        assert probe in inputs, f"missing normalization probe {probe!r}"
    assert len(inputs) > 50000, len(inputs)
    print(f"PASS artifact-derived differential sweep contains {len(inputs)} unique cases and all five probe classes")

    audit = (
        here.parent / "amino-deliverability-audit" / "skills"
        / "amino-deliverability-audit" / "scripts" / "audit.py"
    )
    probe_inputs = differential.PROBES[1:]
    probe_results = differential.command_results(
        [sys.executable, str(here / "adapters" / "skill.py"), str(audit)],
        probe_inputs,
    )
    expected_probes = [None, "0x7f.1", None, None, None]
    assert probe_results == expected_probes, (probe_inputs, probe_results)
    print("PASS Python skill implements the five documented normalization boundaries")

    healthy = [None] * len(inputs)
    assert differential.compare_results(inputs, healthy, list(healthy)) == []
    print("PASS differential healthy control accepts identical result streams")

    injected = list(healthy)
    target = inputs.index("xn--.com")
    injected[target] = "injected-disagreement"
    diagnostic = io.StringIO()
    disagreements = differential.compare_results(inputs, healthy, injected, stream=diagnostic)
    line = diagnostic.getvalue().strip()
    assert disagreements == [("xn--.com", None, "injected-disagreement")], disagreements
    assert "PSL DIFFERENTIAL FAIL: input='xn--.com'" in line, line
    print(f"PASS injected disagreement turns the detector red by name: {line}")
    print("PSL DIFFERENTIAL CANARY PASS: 4/4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
