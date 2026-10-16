#!/usr/bin/env python3
"""Mutation canaries for the WHI-246 published batch-output contract."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "amino-deliverability-audit" / "skills" / "amino-deliverability-audit" / "scripts" / "batch_score.py"
AUDIT = SCRIPT.with_name("audit.py")


def replace_once(path, before, after, name):
    source = path.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise AssertionError(f"{name}: mutation anchor must occur exactly once, found {count}")
    path.write_text(source.replace(before, after, 1), encoding="utf-8")


def execute(repository):
    return subprocess.run(
        [sys.executable, str(repository / "conformance" / "batch_contract.py")],
        cwd=repository, text=True, capture_output=True, check=False,
    )


def mutate(name, path_suffix, before, after, expected):
    with tempfile.TemporaryDirectory(prefix="amino-whi246-canary-") as temporary:
        repository = Path(temporary) / "repository"
        shutil.copytree(ROOT, repository, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        target = repository / path_suffix
        replace_once(target, before, after, name)
        result = execute(repository)
    output = result.stdout + result.stderr
    if result.returncode == 0 or expected not in output or ".execution:" in output:
        print(f"FAIL {name}\nexit={result.returncode}\n{output.strip()}")
        return False
    print(f"PASS {name} — {expected}")
    return True


def main():
    healthy = execute(ROOT)
    if healthy.returncode != 0:
        print("FAIL healthy batch contract\n" + healthy.stdout + healthy.stderr)
        return 1
    script = SCRIPT.relative_to(ROOT)
    audit = AUDIT.relative_to(ROOT)
    cases = [
        (
            "BIMI moved into outbound lane", script,
            '    "BIMI": "brand_optional",\n', '    "BIMI": "outbound_auth",\n',
            "bimi-is-brand-only.Outbound_gaps: expected '0', got '1'",
        ),
        (
            "null-MX inbound N/A rendered as zero", script,
            '        result[column] = None if all(cell == "—" for cell in cells) else cells.count("N")\n',
            '        result[column] = cells.count("N")\n',
            "null-mx-inbound-not-applicable.Inbound_gaps: expected '—', got '0'",
        ),
        (
            "SERVFAIL mislabelled as NR", audit,
            '    return not all(not row.get("error") and row.get("status") == 3\n'
            '                   for row in metadata)\n',
            '    return False  # WHI-246 broken existence classifier\n',
            "servfail-is-scored-and-unconfirmed.Outbound_gaps: expected '0', got 'NR'",
        ),
        (
            "Unconfirmed reason blanked", script,
            '                        + [reason or "—", highlight]))\n',
            '                        + ["—", highlight]))\n',
            "servfail-is-scored-and-unconfirmed.Unconfirmed: expected 'TXT servfail.invalid: SERVFAIL/REFUSED', got '—'",
        ),
        (
            "unlabelled clean highlight restored", script,
            '        highlight = "none" if note == "clean" else note\n',
            '        highlight = note\n',
            "clean-highlight-is-named-none.Highlights: expected 'none', got 'clean'",
        ),
    ]
    passed = sum(mutate(*case) for case in cases)
    print(f"BATCH CANARIES: {passed}/{len(cases)} passed")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
