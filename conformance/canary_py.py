#!/usr/bin/env python3
"""Mutation canaries for the published-skill conformance runner."""

import json
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


def execute(extra_env=None, runner=RUNNER):
    env = {
        **os.environ,
        "CONFORMANCE_FIXTURE": "dkim-revoked-empty-p",
        "PYTHONDONTWRITEBYTECODE": "1",
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, str(runner)],
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

    with tempfile.TemporaryDirectory(prefix="amino-whi10-detail-nullmx-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            "A null MX (0 .) declares under RFC 7505 that this domain accepts no inbound mail. That is good hygiene for a domain not meant to receive mail. It says nothing about whether the domain sends — outbound authentication is assessed separately.",
            "A null MX (0 .) correctly signals this domain neither sends nor receives mail, which helps receivers reject spoofed mail from it. Good hygiene for a non-mail domain.",
            "null-MX detail",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "J reverted null-MX detail",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "null-mx-not-applicable",
            }),
            "null-mx-not-applicable.findings[Transport|Null MX (RFC 7505) — domain declares no mail].detail: "
            "expected 'A null MX (0 .) declares under RFC 7505 that this domain accepts no inbound mail. That is good hygiene for a domain not meant to receive mail. It says nothing about whether the domain sends — outbound authentication is assessed separately.', "
            "got 'A null MX (0 .) correctly signals this domain neither sends nor receives mail, which helps receivers reject spoofed mail from it. Good hygiene for a non-mail domain.'",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi10-action-nomx-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            'if t == "no mx records":\n            return "Confirm whether this domain should receive mail"',
            'if t == "no mx records":\n            return "Confirm STARTTLS on the mail server"',
            "No-MX action",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "K restored STARTTLS action",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "no-mx-not-exempt",
            }),
            "no-mx-not-exempt.findings[Transport|No MX records].action: "
            "expected 'Confirm whether this domain should receive mail', "
            "got 'Confirm STARTTLS on the mail server'",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi10-fix-nomx-") as temporary:
        target = Path(temporary)
        runner = target / "run_py.py"
        shutil.copyfile(RUNNER, runner)
        corpus = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
        no_mx_fixture = next(
            fixture for fixture in corpus["fixtures"]
            if fixture["id"] == "no-mx-not-exempt"
        )
        no_mx_finding = next(
            finding for finding in no_mx_fixture["expect"]["findings"]
            if finding["area"] == "Transport" and finding["title"] == "No MX records"
        )
        if no_mx_finding["fixIncludes"] is None:
            raise AssertionError("No-MX corpus fix: expected a non-null fixture anchor")
        no_mx_finding["fixIncludes"] = None
        (target / "fixtures.json").write_text(json.dumps(corpus), encoding="utf-8")
        expect_red(
            "L restored null No-MX corpus fix",
            execute({
                "AUDIT_SCRIPTS": str(SCRIPTS),
                "CONFORMANCE_FIXTURE": "no-mx-not-exempt",
            }, runner=runner),
            "no-mx-not-exempt.findings[Transport|No MX records].fix: "
            "non-pass finding must declare a non-null fixIncludes",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi10-value-bimi-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            'if a == "BIMI":\n        return ("high", "low")',
            'if a == "BIMI":\n        return ("high", "high")',
            "BIMI value",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "M restored BIMI high value",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "bimi-present-without-vmc",
            }),
            "bimi-present-without-vmc.findings[BIMI|BIMI present without a VMC].value: "
            "expected 'low', got 'high'",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi10-detail-nomx-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            "No MX record is published. SMTP then treats the domain as if it had an implicit MX pointing to itself and resolves that host's address records, so this does not show that the domain receives no mail — a null MX (0 .) is what says that explicitly. This may be intentional for a send-only or parked domain.",
            "No inbound mail servers (may be intentional for a send-only/parked domain).",
            "No-MX detail",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "N reverted No-MX detail",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "no-mx-not-exempt",
            }),
            "no-mx-not-exempt.findings[Transport|No MX records].detail: "
            'expected "No MX record is published. SMTP then treats the domain as if it had an implicit MX pointing to itself and resolves that host\'s address records, so this does not show that the domain receives no mail — a null MX (0 .) is what says that explicitly. This may be intentional for a send-only or parked domain.", '
            "got 'No inbound mail servers (may be intentional for a send-only/parked domain).'",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-lane-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '    "SPF": "outbound_auth",\n',
            "    # WHI-79 removed SPF lane canary\n",
            "SPF lane assignment",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "O removed one area lane",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "dkim-revoked-empty-p",
            }),
            "dkim-revoked-empty-p.execution: threw unknown finding area has no lane: SPF",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-observation-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        observations["mta_sts_policy"] = observation\n',
            '        observations["mta_sts_policy"] = "unavailable"  # WHI-79 conflation canary\n',
            "MTA-STS observation assignment",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "P conflated absent with unavailable",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "mta-sts-policy-absent",
            }),
            "mta-sts-policy-absent.observations: expected {'mta_sts_policy': 'checked', "
            "'robots': 'checked', 'rdap': 'checked'}, got {'mta_sts_policy': 'unavailable', "
            "'robots': 'checked', 'rdap': 'checked'}",
        )
except Exception as error:
    print(f"FAIL  canary setup — {error}")
    FAILED += 1

print(f"\nCanaries (skill): {PASSED} passed, {FAILED} failed; expected 11 cases.")
if PASSED + FAILED != 11:
    print(f"FAIL  canary count: expected 11, got {PASSED + FAILED}", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if FAILED else 0)
