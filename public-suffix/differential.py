#!/usr/bin/env python3
"""Compare the shipping Python and JavaScript registrable-domain lookups."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from run_vectors import command_results


GENERATED = [
    None,
    "com",
    "example",
    "a.b.example.co.uk",
    "a.b.c.mm",
    "www.city.kobe.jp",
    "food.github.io",
    "WwW.Example.COM",
    "www.example.com.",
    "食狮.公司.cn",
    "www.食狮.中国",
    "xn--85x722f.xn--55qx5d.cn",
]


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
    domains = [fixture.get("input", {}).get("domain") for fixture in corpus["fixtures"]]
    domains.extend(GENERATED)
    unique = []
    seen = set()
    for domain in domains:
        key = (type(domain).__name__, domain)
        if key not in seen:
            seen.add(key)
            unique.append(domain)

    python_results = command_results(
        [sys.executable, str(here / "adapters" / "skill.py"), str(args.python_audit)], unique
    )
    engine_results = command_results(
        ["node", str(here / "adapters" / "engine.mjs"), str(args.engine.resolve())], unique
    )
    disagreements = []
    for domain, python_value, engine_value in zip(unique, python_results, engine_results):
        if python_value != engine_value:
            disagreements.append((domain, python_value, engine_value))
            print(
                f"PSL DIFFERENTIAL FAIL: input={domain!r} "
                f"python={python_value!r} engine={engine_value!r}",
                file=sys.stderr,
            )
    print(
        f"PSL DIFFERENTIAL SUMMARY: {len(unique)} cases, "
        f"{len(disagreements)} disagreements"
    )
    return int(bool(disagreements))


if __name__ == "__main__":
    raise SystemExit(main())
