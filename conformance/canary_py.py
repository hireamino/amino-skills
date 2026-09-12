#!/usr/bin/env python3
"""Mutation canaries for the published-skill conformance runner."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run_py.py"
CHECK = HERE / "check.py"
SCRIPTS = (
    HERE.parent
    / "amino-deliverability-audit"
    / "skills"
    / "amino-deliverability-audit"
    / "scripts"
)
PASSED = 0
FAILED = 0


def replace_exactly_once(source, old, new, name):
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"{name}: mutation anchor must occur exactly once, found {count}")
    return source.replace(old, new, 1)


def execute(extra_env=None):
    env = {
        **os.environ,
        "CONFORMANCE_FIXTURE": "dkim-revoked-empty-p",
        "PYTHONDONTWRITEBYTECODE": "1",
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, str(RUNNER)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def execute_check(extra_env=None):
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, str(CHECK)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def expect_red(name, result, expected):
    global PASSED, FAILED
    output = result.stdout + result.stderr
    ok = result.returncode != 0 and expected in output
    if ok:
        print(f"PASS  {name} — {expected}")
        PASSED += 1
    else:
        print(f"FAIL  {name}\n  exit={result.returncode}\n  {output.strip()}")
        FAILED += 1


try:
    with tempfile.TemporaryDirectory(prefix="amino-whi8-skill-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            'F.append(dict(area="SPF", severity="high", title="No SPF record",',
            'F.append(dict(area="SPF", severity="low", title="No SPF record",',
            "severity",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "A high→low severity",
            execute({"AUDIT_SCRIPTS": str(target)}),
            "dkim-revoked-empty-p.findings[SPF|No SPF record].severity: "
            "expected 'high', got 'low'",
        )

    expect_red(
        "G unpatched score lookup hits the network kill switch",
        execute({"CONFORMANCE_CANARY_NETWORK_LOOKUP": "1"}),
        "dkim-revoked-empty-p.execution: threw external network disabled: "
        "DNS lookup attempted for ex.com MX",
    )

    with tempfile.TemporaryDirectory(prefix="amino-whi50-skill-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        score_path = target / "batch_score.py"
        source = score_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '    if null_mx:\n        r["MTA_STS"] = None',
            '    if False:  # WHI-50 null-MX exemption canary\n        r["MTA_STS"] = None',
            "null-MX score exemption",
        )
        score_path.write_text(source, encoding="utf-8")
        expect_red(
            "H removed null-MX score exemption",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "null-mx-not-applicable",
            }),
            "null-mx-not-applicable.score.MTA_STS: expected None, got False",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi50-verify-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        verify_path = target / "verify.py"
        source = verify_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '    if null_mx:\n        r["MTA_STS"] = None',
            '    if False:  # WHI-50 verifier-wiring canary\n        r["MTA_STS"] = None',
            "independent verifier null-MX wiring",
        )
        verify_path.write_text(source, encoding="utf-8")
        expect_red(
            "I removed independent-verifier wiring",
            execute_check({"AUDIT_SCRIPTS": str(target)}),
            "WHI-50 verifier wires null MX into N/A buckets -> "
            "(False, False, False) (exp (None, None, None))",
        )
except Exception as error:
    print(f"FAIL  canary setup — {error}")
    FAILED += 1

print(f"\nCanaries (skill): {PASSED} passed, {FAILED} failed; expected 4 cases.")
if PASSED + FAILED != 4:
    print(f"FAIL  canary count: expected 4, got {PASSED + FAILED}", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if FAILED else 0)
