#!/usr/bin/env python3
"""Offline generator, provenance, and mutation checks."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
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


def freshness_source(root: Path, section: str) -> bytes:
    rules = {"ICANN": [], "PRIVATE": []}
    for raw in (root / "public_suffix_rules.tsv").read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("//"):
            continue
        name, rule = raw.split("\t", 1)
        rules[name].append(rule)
    rules[section].append(f"whi-311-{section.lower()}.example")
    lines = [
        generate.MPL_NOTICE.rstrip("\n"),
        "// VERSION: 2099-01-01_TEST",
        "// COMMIT: " + "b" * 40,
        "// " + "padding" * 35_000,
    ]
    for name in ("ICANN", "PRIVATE"):
        lines.append(generate.BEGIN[name])
        lines.extend(rules[name])
        lines.append(generate.END[name])
    return ("\n".join(lines) + "\n").encode("utf-8")


def run_freshness(root: Path, source: Path, provenance: Path, now: str, *, alarm: bool) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(root / "freshness.py"),
        "--source-file", str(source),
        "--artifact", str(root / "public_suffix_rules.tsv"),
        "--provenance", str(provenance),
        "--now", now,
    ]
    if alarm:
        command.append("--alarm-policy")
    return subprocess.run(command, text=True, capture_output=True, check=False)


def require_freshness(result: subprocess.CompletedProcess[str], code: int, needle: str, label: str) -> None:
    output = result.stdout + result.stderr
    assert result.returncode == code and needle in output, (label, result.returncode, output)
    print(f"PASS {label}: exit {code}, {needle}")


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
    expect_refused(
        "wildcard outside the leftmost label",
        sample(rule="mail.*.example"),
        "outside the leftmost label",
    )
    expect_refused(
        "more than one wildcard",
        sample(rule="*.mail.*.example"),
        "more than one wildcard",
    )

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

    with tempfile.TemporaryDirectory(prefix="amino-psl-wildcard-edit-") as temporary:
        changed = Path(temporary) / "public_suffix_rules.tsv"
        artifact = (root / "public_suffix_rules.tsv").read_bytes()
        anchor = b"ICANN\tcom\n"
        assert artifact.count(anchor) == 1
        changed.write_bytes(artifact.replace(anchor, b"ICANN\tmail.*.example\n", 1))
        problems = verify.verify(root, changed)
        assert any("invalid wildcard shape" in problem for problem in problems), problems
        print("PASS verifier refuses a synthetic invalid wildcard artifact row")

    with tempfile.TemporaryDirectory(prefix="amino-psl-freshness-") as temporary:
        temporary_root = Path(temporary)
        icann = temporary_root / "icann.dat"
        private = temporary_root / "private.dat"
        provenance = temporary_root / "provenance.json"
        icann.write_bytes(freshness_source(root, "ICANN"))
        private.write_bytes(freshness_source(root, "PRIVATE"))
        record = json.loads((root / "provenance.json").read_text(encoding="utf-8"))

        record["fetched_at"] = "2026-10-14T00:00:00Z"
        provenance.write_text(json.dumps(record), encoding="utf-8")
        require_freshness(
            run_freshness(root, private, provenance, "2026-10-24T00:00:00Z", alarm=False),
            1,
            "artifact is stale",
            "K1 exact comparison rejects PRIVATE drift",
        )
        require_freshness(
            run_freshness(root, icann, provenance, "2026-10-24T00:00:00Z", alarm=True),
            1,
            "ICANN drift (1 added, 0 removed)",
            "K5 ICANN drift is red",
        )
        require_freshness(
            run_freshness(root, private, provenance, "2026-10-24T00:00:00Z", alarm=True),
            0,
            "`PRIVATE` `whi-311-private.example`",
            "K5 fresh PRIVATE drift is green with the full report",
        )
        record["fetched_at"] = "2026-09-08T00:00:00Z"
        provenance.write_text(json.dumps(record), encoding="utf-8")
        require_freshness(
            run_freshness(root, private, provenance, "2026-10-24T00:00:00Z", alarm=True),
            1,
            "pin age 46.0 days exceeds 45 days",
            "K5 stale PRIVATE drift is red",
        )
        require_freshness(
            run_freshness(root, temporary_root / "missing.dat", provenance, "2026-10-24T00:00:00Z", alarm=True),
            2,
            "PUBLIC SUFFIX FRESHNESS ERROR",
            "K5 network or source failure stays an error",
        )

    print("PSL GENERATOR AND FRESHNESS CANARIES PASS: 14/14")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
