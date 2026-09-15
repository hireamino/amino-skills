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
ROOT = HERE.parent
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


def execute_check(extra_env=None, checker=CHECK):
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, str(checker)],
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


def copy_repository_tree(destination):
    """Copy the checked repository without VCS or interpreter-generated state."""
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store"),
    )


def detector_deletion_is_proven(result, expected, companion=None):
    """Accept only a normally completed checker that lost the deleted verdict source."""
    output = result.stdout + result.stderr
    padded_output = f"\n{output}\n"
    reached_normal_end = (
        (result.returncode == 0 and "\nALL PASS\n" in padded_output)
        or (result.returncode != 0 and "\nSOME FAILED\n" in padded_output)
    )
    return (
        reached_normal_end
        and expected not in output
        and (companion is None or companion in output)
    )


def prove_detector_required(name, scripts, expected, detector_id, companion=None):
    """Delete one named assertion in a repository copy and prove it was load-bearing."""
    begin = f"# CANARY-DETECTOR-BEGIN: {detector_id}\n"
    end = f"# CANARY-DETECTOR-END: {detector_id}\n"
    with tempfile.TemporaryDirectory(prefix="amino-whi79-detector-") as temporary:
        repository = Path(temporary) / "repository"
        copy_repository_tree(repository)
        checker = repository / "conformance" / "check.py"
        source = checker.read_text(encoding="utf-8")
        if source.count(begin) != 1 or source.count(end) != 1:
            raise AssertionError(f"{name}: detector anchors must each occur exactly once")
        prefix, remainder = source.split(begin, 1)
        _removed, suffix = remainder.split(end, 1)
        checker.write_text(prefix + suffix, encoding="utf-8")
        copied_scripts = (
            repository
            / "amino-deliverability-audit"
            / "skills"
            / "amino-deliverability-audit"
            / "scripts"
        )
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(scripts / filename, copied_scripts / filename)
        result = execute_check(checker=checker)
    if not detector_deletion_is_proven(result, expected, companion):
        output = result.stdout + result.stderr
        raise AssertionError(
            f"{name}: deleted assertion was not proved load-bearing\n"
            f"exit={result.returncode}\n{output.strip()}"
        )
    print(
        f"PASS    detector-of-detector {name} — deleted assertion rejects canary "
        "predicate after normal checker completion"
    )


def prove_crashing_checker_rejected():
    """A checker crash must never satisfy the detector-of-detector predicate."""
    global PASSED, FAILED
    expected = "FAIL WHI-79 detector _http_get blocks a private address"
    companion = "FAIL WHI-79 shipping _http_get address guard"
    with tempfile.TemporaryDirectory(prefix="amino-whi79-crashing-checker-") as temporary:
        repository = Path(temporary) / "repository"
        copy_repository_tree(repository)
        checker = repository / "conformance" / "check.py"
        copied_audit = (
            repository
            / "amino-deliverability-audit"
            / "skills"
            / "amino-deliverability-audit"
            / "scripts"
            / "audit.py"
        )
        audit_source = copied_audit.read_text(encoding="utf-8")
        audit_source = replace_exactly_once(
            audit_source,
            '        ips = host_public_ips(host)\n'
            '        if not ips:\n'
            '            return None, None  # SSRF guard: refuse private/loopback/link-local/reserved\n',
            '        ips = dig(host, "A") + dig(host, "AAAA")  # WHI-79 crashing-checker canary\n'
            '        if not ips:\n'
            '            return None, None\n',
            "crashing checker shipping mutation",
        )
        copied_audit.write_text(audit_source, encoding="utf-8")
        source = checker.read_text(encoding="utf-8")
        begin = "# CANARY-DETECTOR-BEGIN: http-get-guard\n"
        end = "# CANARY-DETECTOR-END: http-get-guard\n"
        if source.count(begin) != 1 or source.count(end) != 1:
            raise AssertionError("AC: T detector anchors must each occur exactly once")
        prefix, remainder = source.split(begin, 1)
        _removed, suffix = remainder.split(end, 1)
        source = prefix + suffix
        source = replace_exactly_once(
            source,
            "# CANARY-DETECTOR-END: mx-guard\n",
            "# CANARY-DETECTOR-END: mx-guard\n"
            'raise RuntimeError("WHI-79 deliberate crashing checker")\n',
            "crashing checker insertion",
        )
        checker.write_text(source, encoding="utf-8")
        result = execute_check(checker=checker)
    output = result.stdout + result.stderr
    ok = (
        result.returncode != 0
        and "WHI-79 deliberate crashing checker" in output
        and companion in output
        and expected not in output
        and not detector_deletion_is_proven(result, expected, companion)
    )
    if ok:
        print("PASS  AC crashing temporary checker is rejected — normal final summary required")
        PASSED += 1
    else:
        print(f"FAIL  AC crashing temporary checker was accepted\n  exit={result.returncode}\n  {output.strip()}")
        FAILED += 1


def remove_fixture_address(corpus, fixture_id, host):
    matches = [fixture for fixture in corpus["fixtures"] if fixture["id"] == fixture_id]
    if len(matches) != 1:
        raise AssertionError(
            f"{fixture_id}: fixture mutation anchor must occur exactly once, found {len(matches)}"
        )
    entry = matches[0]["input"]["dns"].get(host)
    if not isinstance(entry, dict) or entry.get("A") != ["93.184.216.34"]:
        raise AssertionError(f"{fixture_id}: expected the reviewed public-address anchor")
    del entry["A"]


def replace_fixture_addresses(corpus, fixture_id, host, expected, replacement):
    matches = [fixture for fixture in corpus["fixtures"] if fixture["id"] == fixture_id]
    if len(matches) != 1:
        raise AssertionError(
            f"{fixture_id}: fixture mutation anchor must occur exactly once, found {len(matches)}"
        )
    entry = matches[0]["input"]["dns"].get(host)
    if not isinstance(entry, dict) or entry.get("A") != expected:
        raise AssertionError(f"{fixture_id}: expected the reviewed address-list anchor")
    entry["A"] = replacement


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

    with tempfile.TemporaryDirectory(prefix="amino-whi79-lane-compare-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '    "SPF": "outbound_auth",\n',
            '    "SPF": "inbound_transport",  # WHI-79 valid-wrong-lane canary\n',
            "SPF valid wrong lane",
        )
        audit_path.write_text(source, encoding="utf-8")
        expect_red(
            "Q valid wrong lane reaches runner comparison",
            execute({
                "AUDIT_SCRIPTS": str(target),
                "CONFORMANCE_FIXTURE": "dkim-revoked-empty-p",
            }),
            "dkim-revoked-empty-p.findings[SPF|No SPF record].lane: "
            "expected 'outbound_auth', got 'inbound_transport'",
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

    with tempfile.TemporaryDirectory(prefix="amino-whi79-robots-reachability-") as temporary:
        target = Path(temporary)
        runner = target / "run_py.py"
        shutil.copyfile(RUNNER, runner)
        corpus = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
        remove_fixture_address(corpus, "robots-absent", "robots-absent.invalid")
        (target / "fixtures.json").write_text(
            json.dumps(corpus, indent=2) + "\n", encoding="utf-8"
        )
        expect_red(
            "R removed robots fixture public address",
            execute({
                "AUDIT_SCRIPTS": str(SCRIPTS),
                "CONFORMANCE_FIXTURE": "robots-absent",
            }, runner=runner),
            "robots-absent.observations: expected {'mta_sts_policy': 'not_applicable', "
            "'robots': 'checked', 'rdap': 'checked'}, got {'mta_sts_policy': "
            "'not_applicable', 'robots': 'unavailable', 'rdap': 'checked'}",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-mta-sts-reachability-") as temporary:
        target = Path(temporary)
        runner = target / "run_py.py"
        shutil.copyfile(RUNNER, runner)
        corpus = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
        remove_fixture_address(
            corpus,
            "mta-sts-policy-absent",
            "mta-sts.mta-sts-policy-absent.invalid",
        )
        (target / "fixtures.json").write_text(
            json.dumps(corpus, indent=2) + "\n", encoding="utf-8"
        )
        expect_red(
            "S removed MTA-STS fixture public address",
            execute({
                "AUDIT_SCRIPTS": str(SCRIPTS),
                "CONFORMANCE_FIXTURE": "mta-sts-policy-absent",
            }, runner=runner),
            "mta-sts-policy-absent.observations: expected {'mta_sts_policy': 'checked', "
            "'robots': 'checked', 'rdap': 'checked'}, got {'mta_sts_policy': 'unavailable', "
            "'robots': 'checked', 'rdap': 'checked'}",
        )

    # WHI-79 Phase A.2 — mutate each shipping guard independently. Each expected
    # diagnostic belongs to a dedicated assertion in check.py; removing that assertion
    # makes the canary predicate fail, proving exceptions or adjacent checks are not the
    # verdict source.
    with tempfile.TemporaryDirectory(prefix="amino-whi79-http-guard-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        ips = host_public_ips(host)\n'
            '        if not ips:\n'
            '            return None, None  # SSRF guard: refuse private/loopback/link-local/reserved\n',
            '        ips = dig(host, "A") + dig(host, "AAAA")  # WHI-79 deleted HTTP guard canary\n'
            '        if not ips:\n'
            '            return None, None\n',
            "_http_get shipping address guard",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector _http_get blocks a private address"
        expect_red("T deleted _http_get address guard", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required(
            "T _http_get",
            target,
            diagnostic,
            "http-get-guard",
            "FAIL WHI-79 shipping _http_get address guard",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-mta-guard-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        ips = host_public_ips(mhost)\n'
            '        if not ips:\n'
            '            raise OSError("mta-sts host does not resolve to a public IP")  # SSRF guard\n',
            '        ips = dig(mhost, "A") + dig(mhost, "AAAA")  # WHI-79 deleted MTA-STS guard canary\n'
            '        if not ips:\n'
            '            raise OSError("mta-sts host does not resolve")\n',
            "MTA-STS shipping address guard",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector MTA-STS blocks a private address"
        expect_red("U deleted MTA-STS address guard", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required(
            "U MTA-STS",
            target,
            diagnostic,
            "mta-sts-guard",
            "FAIL WHI-79 shipping MTA-STS address guard",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-mx-guard-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        ips = host_public_ips(host)\n'
            '        if not ips:\n'
            '            raise OSError("MX does not resolve to a public IP")  # SSRF guard\n',
            '        ips = dig(host, "A") + dig(host, "AAAA")  # WHI-79 deleted MX guard canary\n'
            '        if not ips:\n'
            '            raise OSError("MX does not resolve")\n',
            "MX shipping address guard",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector MX STARTTLS blocks a private address"
        expect_red("V deleted MX STARTTLS address guard", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required(
            "V MX STARTTLS",
            target,
            diagnostic,
            "mx-guard",
            "FAIL WHI-79 shipping MX STARTTLS address guard",
        )

    with tempfile.TemporaryDirectory(prefix="amino-whi79-whole-host-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        if any(candidate.version == network.version and candidate in network\n'
            '               for network in _CONTRACT_NON_PUBLIC_NETWORKS):\n'
            '            return []\n',
            '        if any(candidate.version == network.version and candidate in network\n'
            '               for network in _CONTRACT_NON_PUBLIC_NETWORKS):\n'
            '            continue  # WHI-79 public-subset canary\n',
            "whole-host refusal",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector mixed address refuses whole host"
        expect_red("W kept the public subset", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required("W public subset", target, diagnostic, "public-subset")

    with tempfile.TemporaryDirectory(prefix="amino-whi79-shared-space-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '    ipaddress.ip_network("100.64.0.0/10"),\n',
            '    # WHI-79 removed shared-address range canary\n',
            "100.64.0.0/10 contract range",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector 100.64 shared address refuses host"
        expect_red("X removed 100.64.0.0/10", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required("X shared space", target, diagnostic, "shared-space")

    with tempfile.TemporaryDirectory(prefix="amino-whi79-mapped-address-") as temporary:
        target = Path(temporary)
        for filename in ("audit.py", "batch_score.py", "resolver.py", "verify.py"):
            shutil.copyfile(SCRIPTS / filename, target / filename)
        audit_path = target / "audit.py"
        source = audit_path.read_text(encoding="utf-8")
        source = replace_exactly_once(
            source,
            '        candidate = (address.ipv4_mapped\n'
            '                     if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped\n'
            '                     else address)\n',
            '        candidate = address  # WHI-79 removed IPv4-mapped unwrap canary\n',
            "IPv4-mapped address unwrap",
        )
        audit_path.write_text(source, encoding="utf-8")
        diagnostic = "FAIL WHI-79 detector mapped 100.64 address refuses host"
        expect_red("Y removed IPv4-mapped unwrap", execute_check({"AUDIT_SCRIPTS": str(target)}), diagnostic)
        prove_detector_required("Y mapped address", target, diagnostic, "mapped-address")

    # Corpus reachability canaries: make each configured response reachable and require
    # the closed-world observation comparison to expose the change.
    _reachability_cases = (
        (
            "Z removed private address from mixed robots fixture",
            "robots-mixed-address-refused",
            "robots-mixed-address-refused.invalid",
            ["93.184.216.34", "10.0.0.5"],
            ["93.184.216.34"],
            "robots-mixed-address-refused.observations: expected {'mta_sts_policy': "
            "'not_applicable', 'robots': 'unavailable', 'rdap': 'checked'}, got "
            "{'mta_sts_policy': 'not_applicable', 'robots': 'checked', 'rdap': 'checked'}",
        ),
        (
            "AA removed shared address from robots fixture",
            "robots-shared-address-refused",
            "robots-shared-address-refused.invalid",
            ["100.64.0.1"],
            [],
            "robots-shared-address-refused.observations: expected {'mta_sts_policy': "
            "'not_applicable', 'robots': 'unavailable', 'rdap': 'checked'}, got "
            "{'mta_sts_policy': 'not_applicable', 'robots': 'checked', 'rdap': 'checked'}",
        ),
        (
            "AB removed private address from mixed MTA-STS fixture",
            "mta-sts-host-mixed-address-refused",
            "mta-sts.mta-sts-host-mixed-address-refused.invalid",
            ["93.184.216.34", "10.0.0.5"],
            ["93.184.216.34"],
            "mta-sts-host-mixed-address-refused.observations: expected {'mta_sts_policy': "
            "'unavailable', 'robots': 'checked', 'rdap': 'checked'}, got "
            "{'mta_sts_policy': 'checked', 'robots': 'checked', 'rdap': 'checked'}",
        ),
    )
    for name, fixture_id, host, expected_addresses, replacement, diagnostic in _reachability_cases:
        with tempfile.TemporaryDirectory(prefix="amino-whi79-address-fixture-") as temporary:
            target = Path(temporary)
            runner = target / "run_py.py"
            shutil.copyfile(RUNNER, runner)
            corpus = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
            replace_fixture_addresses(corpus, fixture_id, host, expected_addresses, replacement)
            (target / "fixtures.json").write_text(
                json.dumps(corpus, indent=2) + "\n", encoding="utf-8"
            )
            expect_red(
                name,
                execute({
                    "AUDIT_SCRIPTS": str(SCRIPTS),
                    "CONFORMANCE_FIXTURE": fixture_id,
                }, runner=runner),
                diagnostic,
            )

    prove_crashing_checker_rejected()
except Exception as error:
    print(f"FAIL  canary setup — {error}")
    FAILED += 1

print(f"\nCanaries (skill): {PASSED} passed, {FAILED} failed; expected 24 cases.")
if PASSED + FAILED != 24:
    print(f"FAIL  canary count: expected 24, got {PASSED + FAILED}", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if FAILED else 0)
