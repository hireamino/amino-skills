#!/usr/bin/env python3
"""Network-isolated freshness reporter for the weekly PSL workflow."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
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


MAX_PIN_AGE_DAYS = 45


def render(rows: list[tuple[str, str]]) -> list[str]:
    return [f"- `{section}` `{rule}`" for section, rule in rows] or ["- none"]


def timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} is not an ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", type=Path, help="offline dry-run source")
    parser.add_argument("--artifact", type=Path, default=here / "public_suffix_rules.tsv")
    parser.add_argument("--provenance", type=Path, default=here / "provenance.json")
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--alarm-policy",
        action="store_true",
        help="red only for ICANN drift or a pin older than 45 days",
    )
    parser.add_argument("--now", help="policy evaluation time (UTC ISO-8601; tests only)")
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
        icann_added = [row for row in added if row[0] == "ICANN"]
        icann_removed = [row for row in removed if row[0] == "ICANN"]
        policy_lines: list[str] = []
        alarm_reasons: list[str] = []
        if args.alarm_policy:
            provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
            pinned_at = timestamp(provenance.get("fetched_at"), "provenance fetched_at")
            now = timestamp(args.now, "--now") if args.now else datetime.now(timezone.utc)
            age_seconds = (now - pinned_at).total_seconds()
            if age_seconds < 0:
                raise ValueError("provenance fetched_at is in the future")
            age_days = age_seconds / 86_400
            if icann_added or icann_removed:
                alarm_reasons.append(
                    f"ICANN drift ({len(icann_added)} added, {len(icann_removed)} removed)"
                )
            if age_days > MAX_PIN_AGE_DAYS:
                alarm_reasons.append(
                    f"pin age {age_days:.1f} days exceeds {MAX_PIN_AGE_DAYS} days"
                )
            policy_lines = [
                "",
                "## Alarm policy",
                f"ICANN changes: **{len(icann_added)} added** · **{len(icann_removed)} removed**",
                f"Pin age: **{age_days:.1f} days** · Limit: **{MAX_PIN_AGE_DAYS} days**",
                f"Decision: **{'RED' if alarm_reasons else 'GREEN'}**",
            ]
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
            *policy_lines,
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
        if args.alarm_policy and alarm_reasons:
            reason = "; ".join(alarm_reasons)
            print(f"::error::public-suffix freshness alarm: {reason}", file=sys.stderr)
            return 1
        if not args.alarm_policy and (added or removed):
            print(
                f"::error::public-suffix artifact is stale: {len(added)} added, {len(removed)} removed",
                file=sys.stderr,
            )
            return 1
        if added or removed:
            print("PUBLIC SUFFIX FRESHNESS PASS: drift is PRIVATE-only and pin age is within policy")
        else:
            print("PUBLIC SUFFIX FRESHNESS PASS: pinned artifact matches canonical upstream")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, generate.GenerationError) as exc:
        print(f"PUBLIC SUFFIX FRESHNESS ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
