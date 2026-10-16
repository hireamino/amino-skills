#!/usr/bin/env python3
"""Closed-world contract for the published batch_score.py TSV surface."""

import contextlib
import io
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SCRIPTS = (
    HERE.parent / "amino-deliverability-audit" / "skills"
    / "amino-deliverability-audit" / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

import audit  # noqa: E402
import batch_score  # noqa: E402


def install(fixture):
    domain = fixture["domain"]
    existence = fixture["existenceStatus"]
    critical = fixture["criticalStatus"]

    def dig(name, rrtype="A", *args, **kwargs):
        return []

    def dns_meta(name, rrtype):
        if name == domain and rrtype in existence:
            status = existence[rrtype]
        elif name == domain and rrtype == "TXT":
            status = critical["TXT"]
        elif name == f"_dmarc.{domain}" and rrtype == "TXT":
            status = critical["DMARC_TXT"]
        elif name == domain and rrtype == "MX":
            status = critical["MX"]
        else:
            status = 0
        return {"status": status, "error": status not in (0, 3)}

    audit.dig = dig
    audit.dns_meta = dns_meta
    batch_score.dig = dig
    batch_score.resolves = audit.resolves
    batch_score.inconclusive_state = audit.inconclusive_state
    batch_score.score = lambda _domain: (dict(fixture["score"]), fixture["note"])


def run_row(fixture):
    install(fixture)
    old_argv = sys.argv
    output = io.StringIO()
    try:
        sys.argv = [str(SCRIPTS / "batch_score.py"), fixture["domain"]]
        with contextlib.redirect_stdout(output):
            batch_score.main()
    finally:
        sys.argv = old_argv
    lines = output.getvalue().rstrip("\n").splitlines()
    if len(lines) != 2:
        raise AssertionError(f"{fixture['id']}.execution: expected header + row, got {lines!r}")
    header = lines[0].split("\t")
    values = lines[1].split("\t")
    if len(header) != len(values):
        raise AssertionError(
            f"{fixture['id']}.execution: header has {len(header)} fields, row has {len(values)}"
        )
    if "Gap" in header:
        raise AssertionError(f"{fixture['id']}.header: blended Gap column must not exist")
    return dict(zip(header, values))


def main():
    document = json.loads((HERE / "batch-fixtures.json").read_text(encoding="utf-8"))
    failures = []
    for fixture in document["fixtures"]:
        try:
            actual = run_row(fixture)
            for field, expected in fixture["expect"].items():
                if actual.get(field) != expected:
                    failures.append(
                        f"{fixture['id']}.{field}: expected {expected!r}, got {actual.get(field)!r}"
                    )
        except Exception as error:  # a runner error is never a passing verdict
            failures.append(f"{fixture['id']}.execution: {error}")
    if failures:
        for failure in failures:
            print("FAIL", failure)
        print(f"BATCH CONTRACT: {len(document['fixtures']) - len(failures)} passed, {len(failures)} failed")
        return 1
    print(f"BATCH CONTRACT: {len(document['fixtures'])} passed, 0 failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
