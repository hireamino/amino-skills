#!/usr/bin/env python3
"""Build the reviewed WHI-215 measurement report from runner JSON outputs."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import generate


REVISIONS = {
    "skill": "amino-skills 24faecb4f0db092bfd853319b6cf66b5834073d2",
    "engine": "amino-audit-engine 41abd12470ccaa43564f8d8c9c1e350fed9d922c",
    "monitor": "amino-monitor 91faa30bdc4b7f0721b81d9a2b7123175223cf01",
}


def gz_size(data: bytes) -> int:
    return len(gzip.compress(data, compresslevel=9, mtime=0))


def shown(value) -> str:
    if value is None:
        return "`null`"
    if isinstance(value, str):
        return f"`{value}`"
    return f"`{json.dumps(value, sort_keys=True)}`"


def cause(case: int) -> str:
    if case in {1, 5, 6, 7, 8}:
        return "invalid/null input boundary"
    if 61 <= case <= 78:
        return "IDN / A-label rule"
    if case in {44, 45}:
        return "exception rule"
    if case in {*range(26, 30), *range(41, 44), *range(46, 52)}:
        return "wildcard rule"
    if case in {*range(21, 25), *range(33, 41), *range(55, 61)}:
        return "missing multi-label suffix"
    return "public-suffix boundary"


def section_payload(artifact: bytes, section: str) -> bytes:
    rows = [
        line
        for line in artifact.splitlines(keepends=True)
        if line.startswith((section + "\t").encode("ascii"))
    ]
    return b"".join(rows)


def source_rule_payload(parsed: generate.ParsedSource, section: str) -> bytes:
    return ("\n".join(parsed.rules[section]) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--monitor", type=Path, required=True)
    parser.add_argument("--canonical-source", type=Path, required=True)
    parser.add_argument("--action-engine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reports = {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in (("skill", args.skill), ("engine", args.engine), ("monitor", args.monitor))
    }
    artifact_path = Path(__file__).resolve().parent / generate.ARTIFACT_NAME
    artifact = artifact_path.read_bytes()
    record = json.loads((artifact_path.parent / generate.PROVENANCE_NAME).read_text(encoding="utf-8"))
    source = args.canonical_source.read_bytes()
    parsed = generate.parse_source(source)
    action = args.action_engine.read_bytes()

    lines = [
        "# WHI-215 Step 1 — measured baseline",
        "",
        "This is a report, not an adoption. The generated artifact is not imported by any",
        "shipping surface in this change.",
        "",
        "## Canonical input",
        "",
        f"- URL: `{generate.SOURCE_URL}`",
        f"- VERSION: `{parsed.version}`",
        f"- COMMIT: `{parsed.commit}`",
        f"- Source SHA-256: `{parsed.source_sha256}`",
        f"- Artifact SHA-256: `{record['artifact_sha256']}`",
        f"- Rules: {len(parsed.rules['ICANN'])} ICANN + {len(parsed.rules['PRIVATE'])} PRIVATE = {record['total_rule_count']} total",
        f"- Rules converted from Unicode to A-label form: {record['alabel_converted_rule_count']}",
        "",
        "The canonical source advanced after the Product Lead's September 24 measurement:",
        "the earlier source was 334,786 bytes / 10,334 rules; the fetched October 1 source",
        f"is {len(source):,} bytes / {record['total_rule_count']:,} rules. The generator therefore pins the",
        "newer canonical VERSION and COMMIT rather than silently reproducing a stale snapshot.",
        "",
        "## Official-vector score of the three existing hand-written tables",
        "",
        "| Existing implementation | Revision | Passed | Failed |",
        "|---|---|---:|---:|",
    ]
    for name in ("skill", "engine", "monitor"):
        report = reports[name]
        lines.append(f"| {name} | `{REVISIONS[name]}` | {report['passed']} | {report['failed']} |")

    for name in ("skill", "engine", "monitor"):
        grouped: dict[str, list[str]] = {}
        for row in reports[name]["rows"]:
            if row["passed"]:
                continue
            grouped.setdefault(cause(row["case"]), []).append(shown(row["domain"]))
        lines.extend(["", f"### {name} failures", ""])
        for label, inputs in grouped.items():
            lines.append(f"- **{label} ({len(inputs)}):** " + ", ".join(inputs))

    lines.extend(["", "### Disagreements between today's implementations", ""])
    disagreements = []
    for rows in zip(*(reports[name]["rows"] for name in ("skill", "engine", "monitor"))):
        actual = {name: row["actual"] for name, row in zip(("skill", "engine", "monitor"), rows)}
        serial = {json.dumps(value, sort_keys=True, ensure_ascii=False) for value in actual.values()}
        if len(serial) > 1:
            disagreements.append((rows[0]["case"], rows[0]["domain"], actual))
    if disagreements:
        lines.extend(
            [
                "| Case | Input | Skill | Engine | Monitor |",
                "|---:|---|---|---|---|",
            ]
        )
        for case_number, domain, actual in disagreements:
            lines.append(
                f"| {case_number} | {shown(domain)} | {shown(actual['skill'])} | "
                f"{shown(actual['engine'])} | {shown(actual['monitor'])} |"
            )
    else:
        lines.append("None.")

    icann = section_payload(artifact, "ICANN")
    private = section_payload(artifact, "PRIVATE")
    source_icann = source_rule_payload(parsed, "ICANN")
    source_private = source_rule_payload(parsed, "PRIVATE")
    lines.extend(
        [
            "",
            "## Size measurement",
            "",
            "Gzip uses level 9 with `mtime=0`. Section rows are the exact tagged A-label rows",
            "inside the shipped artifact; the combined row is the complete artifact including",
            "its MPL notice and provenance-identifying header.",
            "",
            "| Payload | Bytes | Gzip bytes |",
            "|---|---:|---:|",
            f"| ICANN tagged A-label rows | {len(icann):,} | {gz_size(icann):,} |",
            f"| PRIVATE tagged A-label rows | {len(private):,} | {gz_size(private):,} |",
            f"| Shipped combined artifact | {len(artifact):,} | {gz_size(artifact):,} |",
            f"| Canonical full upstream source (comments included) | {len(source):,} | {gz_size(source):,} |",
            f"| Current Action vendored engine | {len(action):,} | {gz_size(action):,} |",
            "",
            "For comparison, the converted rule text without section tags is",
            f"{len(source_icann):,} bytes ICANN and {len(source_private):,} bytes PRIVATE.",
            f"If the public Action later vendors this artifact as a separate file, its raw",
            f"payload grows by {len(artifact):,} bytes, from {len(action):,} to {len(action) + len(artifact):,}",
            f"bytes before other package overhead (gzip delta: {gz_size(artifact):,} bytes when compressed separately).",
            "The full list is intentional: excluding PRIVATE rules would allow a claim such as",
            "`foo.github.io` to collapse to `github.io`, which violates the one-registrable-root invariant.",
            "",
            "## Measurement method",
            "",
            "`run_vectors.py` parsed all 78 active upstream cases without filtering. The skill",
            "adapter imported the reviewed Python `org_base`; the engine adapter executed the",
            "private `orgBase` from the 1.5.0 artifact; and the monitor adapter extracted the one",
            "`regDomain` function from Watchtower main. The reference lookup built from the new",
            "artifact passed 78/78, including longest-match, wildcard, exception, Unicode, and",
            "A-label cases. The score above records errors as outputs rather than normalizing them.",
        ]
    )
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"MEASURED REPORT WRITTEN: skill={reports['skill']['passed']}/78 "
        f"engine={reports['engine']['passed']}/78 monitor={reports['monitor']['passed']}/78 "
        f"disagreements={len(disagreements)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
