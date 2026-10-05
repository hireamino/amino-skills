#!/usr/bin/env python3
"""Network-isolated freshness reporter for the weekly PSL workflow."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

import generate


def tagged_rules(path: Path) -> set[tuple[str, str]]:
    result = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("//"):
            continue
        section, rule = raw.split("\t", 1)
        result.add((section, rule))
    return result


def render(rows: list[tuple[str, str]], limit: int = 100) -> list[str]:
    shown = [f"- `{section}` `{rule}`" for section, rule in rows[:limit]]
    if len(rows) > limit:
        shown.append(f"- …and {len(rows) - limit} more")
    return shown or ["- none"]


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", type=Path, help="offline dry-run source")
    parser.add_argument("--artifact", type=Path, default=here / "public_suffix_rules.tsv")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        source = generate.read_source(args.source_file)
        parsed = generate.parse_source(source)
        current = tagged_rules(args.artifact)
        upstream = {
            (section, rule)
            for section, rules in parsed.rules.items()
            for rule in rules
        }
        added = sorted(upstream - current)
        removed = sorted(current - upstream)
        lines = [
            "# Public Suffix List freshness",
            "",
            f"Pinned rules: **{len(current)}**",
            f"Upstream rules: **{len(upstream)}**",
            f"Added: **{len(added)}** · Removed: **{len(removed)}**",
            "",
            "## Added",
            *render(added),
            "",
            "## Removed",
            *render(removed),
            "",
            f"Upstream VERSION: `{parsed.version}`",
            f"Upstream COMMIT: `{parsed.commit}`",
        ]
        report = "\n".join(lines) + "\n"
        print(report, end="")
        if args.report:
            args.report.write_text(report, encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(report)
        if added or removed:
            print(
                f"::error::public-suffix artifact is stale: {len(added)} added, {len(removed)} removed",
                file=sys.stderr,
            )
            return 1
        print("PUBLIC SUFFIX FRESHNESS PASS: pinned artifact matches canonical upstream")
        return 0
    except (OSError, UnicodeError, ValueError, generate.GenerationError) as exc:
        print(f"PUBLIC SUFFIX FRESHNESS ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
