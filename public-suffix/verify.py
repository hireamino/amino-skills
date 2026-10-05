#!/usr/bin/env python3
"""Offline integrity and official-vector gate for the pinned PSL artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from run_vectors import ReferenceLookup, load_cases


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(root: Path, artifact: Path | None = None) -> list[str]:
    artifact = artifact or root / "public_suffix_rules.tsv"
    provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    data = artifact.read_bytes()
    problems = []
    if digest(data) != provenance.get("artifact_sha256"):
        problems.append(
            "artifact SHA-256 does not match provenance: "
            f"got {digest(data)}, expected {provenance.get('artifact_sha256')}"
        )
    counts = {"ICANN": 0, "PRIVATE": 0}
    for number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw or raw.startswith("//"):
            continue
        fields = raw.split("\t")
        if len(fields) != 2 or fields[0] not in counts:
            problems.append(f"invalid tagged artifact row {number}: {raw!r}")
            continue
        if not fields[1].isascii():
            problems.append(f"artifact row {number} is not A-label ready: {fields[1]!r}")
        counts[fields[0]] += 1
    expected_counts = {
        section: details["rule_count"] for section, details in provenance.get("sections", {}).items()
    }
    if counts != expected_counts:
        problems.append(f"section counts differ: got {counts}, expected {expected_counts}")
    if sum(counts.values()) != provenance.get("total_rule_count"):
        problems.append(
            f"total rule count differs: got {sum(counts.values())}, "
            f"expected {provenance.get('total_rule_count')}"
        )
    converted = provenance.get("alabel_converted_rule_count")
    if not isinstance(converted, int) or not 0 <= converted <= sum(counts.values()):
        problems.append(
            f"invalid converted-rule count in provenance: {converted!r}"
        )
    return problems


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=here)
    parser.add_argument("--artifact", type=Path)
    args = parser.parse_args()
    try:
        problems = verify(args.root, args.artifact)
        if problems:
            for problem in problems:
                print(f"PSL INTEGRITY FAIL: {problem}", file=sys.stderr)
            return 1
        cases = load_cases(args.root / "test_psl.txt")
        lookup = ReferenceLookup(args.artifact or args.root / "public_suffix_rules.tsv")
        failures = [case for case in cases if lookup(case.domain) != case.expected]
        if failures:
            for case in failures:
                print(
                    f"PSL VECTOR FAIL: {case.domain!r} -> {lookup(case.domain)!r} "
                    f"(expected {case.expected!r})",
                    file=sys.stderr,
                )
            return 1
        record = json.loads((args.root / "provenance.json").read_text(encoding="utf-8"))
        print(
            "PSL INTEGRITY PASS: "
            f"{record['total_rule_count']} tagged A-label rules, "
            f"sha256={record['artifact_sha256']}"
        )
        print(f"PSL OFFICIAL VECTORS PASS: {len(cases)}/{len(cases)}")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"PSL VERIFY ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
