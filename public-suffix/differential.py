#!/usr/bin/env python3
"""Compare the shipping Python and JavaScript registrable-domain lookups."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import TextIO

from run_vectors import command_results


PROBES = [
    None,
    "a" * 64 + ".com",       # overlong label
    "0x7f.1",                # URL-style IPv4 numeric shortcut
    "ex ample.com",          # whitespace
    "xn--.com",              # invalid punycode
    "食狮。公司.cn",          # alternate Unicode separator
]


def artifact_domains(path: Path) -> list[str]:
    """Build a deterministic five-shape sweep from every pinned PSL rule."""
    domains = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("//"):
            continue
        _section, rule = raw.split("\t", 1)
        suffix = rule[1:] if rule.startswith("!") else rule[2:] if rule.startswith("*.") else rule
        domains.extend((suffix, f"x.{suffix}", f"a.b.{suffix}", suffix.upper(), f"{suffix}."))
    return domains


def comparison_inputs(corpus: dict, artifact: Path) -> list[str | None]:
    domains = [fixture.get("input", {}).get("domain") for fixture in corpus["fixtures"]]
    domains.extend(artifact_domains(artifact))
    domains.extend(PROBES)
    unique = []
    seen = set()
    for domain in domains:
        key = (type(domain).__name__, domain)
        if key not in seen:
            seen.add(key)
            unique.append(domain)
    return unique


def compare_results(
    domains: list[str | None],
    python_results: list[object],
    engine_results: list[object],
    *,
    stream: TextIO = sys.stderr,
) -> list[tuple[str | None, object, object]]:
    if len(python_results) != len(domains) or len(engine_results) != len(domains):
        raise ValueError("differential result counts do not match the input count")
    disagreements = []
    for domain, python_value, engine_value in zip(domains, python_results, engine_results):
        if python_value != engine_value:
            disagreements.append((domain, python_value, engine_value))
            print(
                f"PSL DIFFERENTIAL FAIL: input={domain!r} "
                f"python={python_value!r} engine={engine_value!r}",
                file=stream,
            )
    return disagreements


def main() -> int:
    here = Path(__file__).resolve().parent
    root = here.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument(
        "--python",
        dest="python_audit",
        type=Path,
        default=root / "amino-deliverability-audit" / "skills" / "amino-deliverability-audit" / "scripts" / "audit.py",
    )
    args = parser.parse_args()
    corpus = json.loads((root / "conformance" / "fixtures.json").read_text(encoding="utf-8"))
    unique = comparison_inputs(corpus, here / "public_suffix_rules.tsv")

    python_results = command_results(
        [sys.executable, str(here / "adapters" / "skill.py"), str(args.python_audit)], unique
    )
    engine_results = command_results(
        ["node", str(here / "adapters" / "engine.mjs"), str(args.engine.resolve())], unique
    )
    disagreements = compare_results(unique, python_results, engine_results)
    print(
        f"PSL DIFFERENTIAL SUMMARY: {len(unique)} cases, "
        f"{len(disagreements)} disagreements"
    )
    return int(bool(disagreements))


if __name__ == "__main__":
    raise SystemExit(main())
