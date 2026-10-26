#!/usr/bin/env python3
"""Mutation canaries for the WHI-12 rule-evaluation contract."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
AUDIT = Path(
    "amino-deliverability-audit/skills/amino-deliverability-audit/scripts/audit.py"
)


CASES = (
    (
        "DANE keeps TLSA as a declared input",
        AUDIT,
        'row[2] in {"MX", "TLSA"}',
        'row[2] in {"MX"}',
        [sys.executable, "conformance/run_py.py"],
        {"CONFORMANCE_FIXTURE": "rule-evaluation-tlsa-servfail"},
        "rule-evaluation-tlsa-servfail",
    ),
    (
        "DNS reads stay single-flight",
        AUDIT,
        "if key in _dns_cache:\n            rows, metadata = _dns_cache[key]",
        "if False and key in _dns_cache:\n            rows, metadata = _dns_cache[key]",
        [sys.executable, "conformance/check.py"],
        {},
        "WHI-12 1.11 one DNS read per name/type",
    ),
    (
        "missing DNS metadata fails closed",
        AUDIT,
        'if not metadata or status is None:\n        return f"{rrtype} {name}: metadata unavailable"',
        'if not metadata or status is None:\n        return None',
        [sys.executable, "conformance/run_py.py"],
        {"CONFORMANCE_FIXTURE": "rule-evaluation-no-dns-meta"},
        "rule-evaluation-no-dns-meta",
    ),
    (
        "external DMARC authorization stays source-exact",
        AUDIT,
        'candidates = [row for row in candidates if "._report._dmarc." not in row[1]]\n'
        '        elif rule == "tls_rpt.present":',
        'candidates = list(candidates)\n'
        '        elif rule == "tls_rpt.present":',
        [sys.executable, "conformance/run_py.py"],
        {"CONFORMANCE_FIXTURE": "rule-evaluation-dmarc-report-auth-servfail"},
        "rule-evaluation-dmarc-report-auth-servfail",
    ),
    (
        "DMARC missing keeps the ancestor walk",
        AUDIT,
        '"dmarc.unauthorized_report_destination",\n}',
        '"dmarc.unauthorized_report_destination", "dmarc.missing",\n}',
        [sys.executable, "conformance/run_py.py"],
        {"CONFORMANCE_FIXTURE": "rule-evaluation-dmarc-parent-servfail"},
        "rule-evaluation-dmarc-parent-servfail",
    ),
    (
        "forward DNS does not contaminate PTR existence",
        AUDIT,
        'with _evaluation_scope("rdns_forward"):',
        'with _evaluation_scope("rdns"):',
        [sys.executable, "conformance/run_py.py"],
        {"CONFORMANCE_FIXTURE": "rule-evaluation-ptr-forward-servfail"},
        "rule-evaluation-ptr-forward-servfail",
    ),
    (
        "source declarations remain closed-world",
        AUDIT,
        'RULE_INPUTS["transport.ptr_not_fcrdns"] = ("rdns", "rdns_forward")',
        'RULE_INPUTS.pop("caa.missing")',
        [sys.executable, "conformance/check.py"],
        {},
        "WHI-12 1.11 every engine rule declares inputs",
    ),
)


def main():
    passed = 0
    for name, path, old, new, command, extra_env, diagnostic in CASES:
        with tempfile.TemporaryDirectory(prefix="amino-rule-evaluation-canary-") as temporary:
            copy = Path(temporary) / "repo"
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            target = copy / path
            source = target.read_text(encoding="utf-8")
            if source.count(old) != 1:
                print(f"FAIL {name}: mutation anchor count {source.count(old)} (expected 1)")
                continue
            target.write_text(source.replace(old, new, 1), encoding="utf-8")
            result = subprocess.run(
                command, cwd=copy,
                env={**os.environ, **extra_env, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True, text=True,
            )
            output = result.stdout + result.stderr
            if result.returncode == 0 or diagnostic not in output:
                print(
                    f"FAIL {name}: rc={result.returncode}, "
                    f"diagnostic={diagnostic!r} present={diagnostic in output}"
                )
                continue
            passed += 1
            print(f"PASS {name} -> {diagnostic}")
    print(f"Rule-evaluation canaries: {passed}/{len(CASES)}")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
