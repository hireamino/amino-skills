#!/usr/bin/env python3
"""Offline generator, provenance, and mutation checks."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import generate
import verify


def sample(rule: str = "公司.cn", *, version: bool = True, complete: bool = True) -> bytes:
    header = generate.MPL_NOTICE
    if version:
        header += "// VERSION: 2099-01-01_TEST\n// COMMIT: " + "a" * 40 + "\n"
    body = (
        "\n// ===BEGIN ICANN DOMAINS===\n"
        f"{rule}\n"
        "// ===END ICANN DOMAINS===\n"
        "// ===BEGIN PRIVATE DOMAINS===\n"
        "github.io\n"
    )
    if complete:
        body += "// ===END PRIVATE DOMAINS===\n"
    return (header + body).encode("utf-8")


def expect_refused(name: str, source: bytes, needle: str) -> None:
    try:
        generate.parse_source(source, enforce_production_floor=False)
    except generate.GenerationError as exc:
        assert needle in str(exc), (name, exc)
        print(f"PASS generator refuses {name}: {exc}")
        return
    raise AssertionError(f"generator accepted {name}")


def main() -> int:
    parsed = generate.parse_source(sample(), enforce_production_floor=False)
    assert parsed.rules["ICANN"] == ("xn--55qx5d.cn",)
    assert parsed.converted_rule_count == 1
    print("PASS generator A-labels Unicode rules before shipping")

    first = generate.artifact_bytes(parsed)
    second = generate.artifact_bytes(generate.parse_source(sample(), enforce_production_floor=False))
    assert first == second
    stamp = "2099-01-02T03:04:05Z"
    assert generate.provenance_bytes(generate.provenance(parsed, first, stamp)) == generate.provenance_bytes(
        generate.provenance(parsed, second, stamp)
    )
    print("PASS generator is deterministic for identical source bytes and fetch timestamp")

    expect_refused("missing VERSION/COMMIT", sample(version=False), "VERSION")
    expect_refused("truncated download", sample(complete=False), "truncated")
    expect_refused("unencodable rule", sample(rule="a" * 64 + ".cn"), "cannot A-label encode rule")

    root = Path(__file__).resolve().parent
    assert not verify.verify(root)
    with tempfile.TemporaryDirectory(prefix="amino-psl-hand-edit-") as temporary:
        changed = Path(temporary) / "public_suffix_rules.tsv"
        artifact = (root / "public_suffix_rules.tsv").read_bytes()
        anchor = b"ICANN\tcom\n"
        assert artifact.count(anchor) == 1
        changed.write_bytes(artifact.replace(anchor, b"ICANN\texample\n", 1))
        problems = verify.verify(root, changed)
        assert any("SHA-256 does not match provenance" in problem for problem in problems), problems
        print("PASS provenance detects a hand-edited artifact")

    print("PSL GENERATOR CANARIES PASS: 6/6")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
