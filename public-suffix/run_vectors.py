#!/usr/bin/env python3
"""Run the official PSL vectors against the artifact or any JSON adapter command.

Adapter protocol: read one JSON array of domains from stdin and write one JSON
array of results to stdout.  A result is a string, null, or an error object.  The
protocol is language-neutral; adapters for the current Python and JavaScript
implementations live in adapters/.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys


CASE_RE = re.compile(r"^checkPublicSuffix\((null|'(?:[^'\\]|\\.)*'), (null|'(?:[^'\\]|\\.)*')\);$")


@dataclass(frozen=True)
class Case:
    domain: str | None
    expected: str | None


def js_literal(value: str) -> str | None:
    return None if value == "null" else ast.literal_eval(value)


def load_cases(path: Path) -> list[Case]:
    cases = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line.startswith("checkPublicSuffix("):
            continue
        match = CASE_RE.fullmatch(line)
        if not match:
            raise ValueError(f"unparsed active vector at {path}:{line_number}: {line}")
        cases.append(Case(js_literal(match.group(1)), js_literal(match.group(2))))
    if len(cases) != 78:
        raise ValueError(f"official vector count is {len(cases)}, expected 78")
    return cases


class ReferenceLookup:
    def __init__(self, artifact: Path):
        self.exact: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        for line_number, raw in enumerate(artifact.read_text(encoding="utf-8").splitlines(), 1):
            if not raw or raw.startswith("//"):
                continue
            try:
                section, rule = raw.split("\t", 1)
            except ValueError as exc:
                raise ValueError(f"invalid artifact row {line_number}") from exc
            if section not in {"ICANN", "PRIVATE"} or not rule.isascii():
                raise ValueError(f"invalid artifact row {line_number}: {raw!r}")
            if rule.startswith("!"):
                self.exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self.wildcards.add(rule[2:])
            else:
                self.exact.add(rule)

    @staticmethod
    def _alabels(labels: list[str]) -> list[str] | None:
        try:
            return [label.encode("idna").decode("ascii").lower() for label in labels]
        except UnicodeError:
            return None

    def __call__(self, domain: str | None) -> str | None:
        if domain is None or domain.startswith("."):
            return None
        normalized = domain.rstrip(".").lower()
        if not normalized:
            return None
        display = normalized.split(".")
        if any(not label for label in display):
            return None
        labels = self._alabels(display)
        if labels is None:
            return None

        exception_length = 0
        match_length = 1  # prevailing default rule: *
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            length = len(labels) - index
            if candidate in self.exceptions:
                exception_length = max(exception_length, length)
            if candidate in self.exact:
                match_length = max(match_length, length)
            if index + 1 < len(labels) and ".".join(labels[index + 1 :]) in self.wildcards:
                match_length = max(match_length, length)

        public_suffix_length = exception_length - 1 if exception_length else match_length
        if len(labels) <= public_suffix_length:
            return None
        return ".".join(display[-(public_suffix_length + 1) :])


def command_results(command: list[str], domains: list[str | None]) -> list[object]:
    completed = subprocess.run(
        command,
        input=json.dumps(domains, ensure_ascii=False),
        text=True,
        capture_output=True,
    )
    if completed.returncode:
        raise RuntimeError(
            f"adapter exited {completed.returncode}: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"adapter did not emit JSON: {completed.stdout[:200]!r}") from exc
    if not isinstance(result, list) or len(result) != len(domains):
        raise RuntimeError(f"adapter emitted {len(result) if isinstance(result, list) else type(result)} results")
    return result


def run(cases: list[Case], actual: list[object], name: str) -> dict:
    rows = []
    for index, (case, got) in enumerate(zip(cases, actual), 1):
        passed = got == case.expected
        rows.append(
            {
                "case": index,
                "domain": case.domain,
                "expected": case.expected,
                "actual": got,
                "passed": passed,
            }
        )
        marker = "PASS" if passed else "FAIL"
        print(
            f"{marker} {name} #{index}: input={case.domain!r} "
            f"expected={case.expected!r} actual={got!r}"
        )
    passed_count = sum(row["passed"] for row in rows)
    print(f"VECTOR SUMMARY {name}: {passed_count} passed / {len(rows) - passed_count} failed / {len(rows)} total")
    return {"implementation": name, "passed": passed_count, "failed": len(rows) - passed_count, "rows": rows}


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, default=here / "test_psl.txt")
    parser.add_argument("--artifact", type=Path, default=here / "public_suffix_rules.tsv")
    parser.add_argument("--name", default="reference")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="adapter command after --")
    args = parser.parse_args()
    try:
        cases = load_cases(args.vectors)
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if command:
            actual = command_results(command, [case.domain for case in cases])
        else:
            lookup = ReferenceLookup(args.artifact)
            actual = [lookup(case.domain) for case in cases]
        report = run(cases, actual, args.name)
        if args.json_out:
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return int(report["failed"] != 0)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"VECTOR ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
