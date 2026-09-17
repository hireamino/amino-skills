#!/usr/bin/env python3
"""Closed-world conformance runner for the published Python skill.

The runner calls audit.main() itself so it exercises the exact finding composition
used by the shipping skill. DNS is fixture-backed, every socket/DNS fallback is
blocked, and batch_score's import-time bindings are redirected to the same fixture.
Selected findings also assert exact detail and effort/value placement.
"""
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(__file__)
DEFAULT_SCRIPTS = os.path.join(
    HERE, "..", "amino-deliverability-audit", "skills",
    "amino-deliverability-audit", "scripts",
)
SCRIPTS = os.path.abspath(DEFAULT_SCRIPTS)
sys.path.insert(0, SCRIPTS)

import resolver  # noqa: E402
from socket_fixture import SocketTlsFixture, http_response  # noqa: E402


NETWORK_ATTEMPTS = []
HTTP_CALLS = {}
HTTP_REJECTS = []
CONTRACT_MODES = {"dns-engine", "http-observation"}
LANES = {
    "outbound_auth", "inbound_transport", "domain_posture",
    "brand_optional", "outside_sending_posture",
}
OBSERVATION_KEYS = {"mta_sts_policy", "robots", "rdap"}
OBSERVATION_STATES = {"checked", "unavailable", "not_applicable"}


def _blocked_dns(name, rtype):
    message = f"external network disabled: DNS lookup attempted for {name} {rtype}"
    NETWORK_ATTEMPTS.append(message)
    raise AssertionError(message)


def _blocked_socket(*args, **kwargs):
    message = f"external network disabled: socket lookup attempted for {args!r}"
    NETWORK_ATTEMPTS.append(message)
    raise AssertionError(message)


# Fail closed before importing the shipping modules. Any binding the fixture
# substitution misses points at a backend that raises instead of reaching real DNS.
resolver.set_backend(_blocked_dns)

import audit  # noqa: E402
import batch_score  # noqa: E402

REAL_TIME = audit.time.time
audit.socket.create_connection = _blocked_socket
audit.socket.getaddrinfo = _blocked_socket
audit.socket.gethostbyaddr = _blocked_socket
audit.time.sleep = lambda _seconds: None


def _norm(name):
    return name.rstrip(".").lower()


def install_resolver(dns):
    """Install one fixture's DNS in audit and every batch_score import binding."""
    records = {_norm(name): value for name, value in (dns or {}).items()}

    def recs(name, rtype="A", *args, **kwargs):
        name = _norm(name)
        # rdap.org is the shipping code's fixed public bootstrap host. The old
        # runner bypassed this guard by replacing _http_get; keep the real guard
        # in the path without requiring every fixture to repeat trusted-host DNS.
        if name == "rdap.org" and rtype == "A":
            return ["93.184.216.36"]
        if name in records and rtype in records[name]:
            return records[name][rtype]
        for key, value in records.items():
            if key.startswith("*._domainkey.") and name.endswith(key[1:]) and rtype in value:
                return value[rtype]
        return []

    def first_txt(name, prefix):
        for row in recs(name, "TXT"):
            if row.lower().startswith(prefix.lower()):
                return row
        return None

    def dns_meta(name, rtype):
        entry = records.get(_norm(name), {})
        return resolver.normalized_meta(entry.get("status", 0), entry.get("ad", False))

    audit.dig = recs
    audit.query_fresh = recs
    audit.first_txt = first_txt
    audit.confirm_txt = lambda name, prefix: first_txt(name, prefix)
    audit.dns_meta = dns_meta

    # batch_score imports these names from audit at module load. Rebind every one
    # so the scorer cannot silently escape the fixture resolver.
    for name in (
        "first_txt", "count_spf_lookups", "effective_terminator", "resolves",
        "dkim_lookup", "mx_providers",
    ):
        setattr(batch_score, name, getattr(audit, name))
    batch_score.dig = recs
    return recs


def _fixture_http_name(domain, host):
    if host == f"mta-sts.{domain}":
        return "mta_sts_policy"
    if host == domain:
        return "robots"
    if host == "rdap.org":
        return "rdap"
    return None


def install_http(domain, http):
    """Stub sockets/TLS while the shipping HTTP functions parse raw responses."""
    spec = http or {}

    def entry(name):
        value = spec.get(name, "unavailable")
        return None if value == "unavailable" else value

    def response_for_host(host):
        name = _fixture_http_name(domain, host)
        if name is None:
            HTTP_REJECTS.append(host)
            raise AssertionError(f"fixture has no HTTP response for host {host}")
        HTTP_CALLS[name] = HTTP_CALLS.get(name, 0) + 1
        value = entry(name)
        if value is None:
            raise OSError(f"fixture HTTP unavailable for {host}")
        if "contentType" in value:
            return http_response(
                value.get("status"),
                value.get("body", ""),
                content_type=value["contentType"],
            )
        return http_response(value.get("status"), value.get("body", ""))

    fixture = SocketTlsFixture(response_for_host)
    audit.socket.create_connection = fixture.create_connection
    audit.ssl.create_default_context = fixture.create_default_context
    return fixture


def unexpected_http_host_is_refused():
    """Exercise the runner's exact host map with a public but unconfigured hostname."""
    install_resolver({
        "expected.invalid": {"A": ["93.184.216.34"]},
        "unexpected.invalid": {"A": ["93.184.216.34"]},
    })
    install_http("expected.invalid", {
        "robots": {"status": 204, "body": "runner host-map canary"},
    })
    HTTP_REJECTS.clear()
    result = audit._http_get("unexpected.invalid", "/robots.txt")
    return result == (None, None) and HTTP_REJECTS == ["unexpected.invalid"]


def run_shipping_audit(domain):
    """Execute audit.main(), capturing its public JSON result."""
    old_argv = sys.argv
    output = io.StringIO()
    try:
        sys.argv = [audit.__file__, domain]
        with contextlib.redirect_stdout(output):
            audit.main()
    finally:
        sys.argv = old_argv
    return json.loads(output.getvalue())


def run_score(domain):
    buckets, note = batch_score.score(domain)
    return {**buckets, "gap": batch_score.gap_of(buckets), "note": note}


def finding_key(finding):
    return finding["area"], finding["title"]


def finding_label(finding):
    return f"{finding.get('area')}|{finding.get('title')}"


def expected_findings(fx):
    findings = fx.get("expect", {}).get("findings")
    if not isinstance(findings, list):
        raise AssertionError(f"{fx['id']}.expect.findings must be a reviewed closed list")
    expected = []
    not_applicable = 0
    for finding in findings:
        for field in ("area", "title", "severity", "lane", "action", "fixIncludes"):
            if field not in finding:
                raise AssertionError(f"{fx['id']}.expect.findings missing {field}")
        if finding["lane"] not in LANES:
            raise AssertionError(
                f"{fx['id']}.findings[{finding_label(finding)}].lane: "
                f"unknown contract value {finding['lane']!r}"
            )
        if finding["severity"] != "pass" and finding["fixIncludes"] is None:
            raise AssertionError(
                f"{fx['id']}.findings[{finding_label(finding)}].fix: "
                "non-pass finding must declare a non-null fixIncludes"
            )
        if "detail" in finding and not isinstance(finding["detail"], str):
            raise AssertionError(
                f"{fx['id']}.findings[{finding_label(finding)}].detail: "
                "expected an exact string"
            )
        if ("effort" in finding) != ("value" in finding):
            raise AssertionError(
                f"{fx['id']}.findings[{finding_label(finding)}].effort/value: "
                "must be declared together"
            )
        surfaces = finding.get("surfaces", ["skill", "web", "action"])
        if "skill" in surfaces:
            expected.append(finding)
        else:
            reason = finding.get("notApplicable", {}).get("skill")
            if not reason:
                raise AssertionError(
                    f"{fx['id']}.expect.findings[{finding_label(finding)}] "
                    "omits skill without a notApplicable reason"
                )
            not_applicable += 1
    return expected, not_applicable


def compare_legacy(fx, findings):
    problems = []
    titles = [f"{finding['area']}:{finding['title']}" for finding in findings]
    for present in fx["expect"].get("present", []):
        if not any(
            finding["area"] == present["area"]
            and present["includes"] in finding["title"]
            for finding in findings
        ):
            problems.append(
                f"legacy.present[{present['area']}~{present['includes']!r}]: missing"
            )
    for absent in fx["expect"].get("absent", []):
        if any(absent in title for title in titles):
            problems.append(f"legacy.absent[{absent!r}]: unexpected match")
    return problems


def compare_contract(fx, result, score, ledger):
    problems = []
    findings = result.get("findings", [])
    expected, _ = expected_findings(fx)
    actual_by_key = {}
    for actual in findings:
        key = finding_key(actual)
        if key in actual_by_key:
            problems.append(
                f"findings[{finding_label(actual)}].identity: duplicate actual finding"
            )
        else:
            actual_by_key[key] = actual

    expected_keys = set()
    for wanted in expected:
        for field in ("identity", "severity", "action", "fix", "lane"):
            ledger[field] += 1
        if "detail" in wanted:
            ledger["detail"] += 1
        if "effort" in wanted:
            ledger["effort"] += 1
            ledger["value"] += 1
        key = finding_key(wanted)
        if key in expected_keys:
            problems.append(
                f"findings[{finding_label(wanted)}].identity: duplicate expectation"
            )
            continue
        expected_keys.add(key)
        actual = actual_by_key.get(key)
        if actual is None:
            problems.append(
                f"findings[{finding_label(wanted)}].identity: expected finding, got missing"
            )
            continue
        if actual.get("severity") != wanted["severity"]:
            problems.append(
                f"findings[{finding_label(wanted)}].severity: "
                f"expected {wanted['severity']!r}, got {actual.get('severity')!r}"
            )
        if actual.get("lane") != wanted["lane"]:
            problems.append(
                f"findings[{finding_label(wanted)}].lane: "
                f"expected {wanted['lane']!r}, got {actual.get('lane')!r}"
            )
        if "detail" in wanted:
            if actual.get("detail") != wanted["detail"]:
                problems.append(
                    f"findings[{finding_label(wanted)}].detail: "
                    f"expected {wanted['detail']!r}, got {actual.get('detail')!r}"
                )
        if "effort" in wanted:
            if actual.get("effort") != wanted["effort"]:
                problems.append(
                    f"findings[{finding_label(wanted)}].effort: "
                    f"expected {wanted['effort']!r}, got {actual.get('effort')!r}"
                )
            if actual.get("value") != wanted["value"]:
                problems.append(
                    f"findings[{finding_label(wanted)}].value: "
                    f"expected {wanted['value']!r}, got {actual.get('value')!r}"
                )
        actual_action = actual.get("action")
        if actual_action != wanted["action"]:
            problems.append(
                f"findings[{finding_label(wanted)}].action: "
                f"expected {wanted['action']!r}, got {actual_action!r}"
            )
        actual_fix = actual.get("fix")
        if wanted["fixIncludes"] is None:
            if actual_fix is not None:
                problems.append(
                    f"findings[{finding_label(wanted)}].fix: expected None, got {actual_fix!r}"
                )
        elif not isinstance(actual_fix, str) or wanted["fixIncludes"] not in actual_fix:
            problems.append(
                f"findings[{finding_label(wanted)}].fix: "
                f"expected substring {wanted['fixIncludes']!r}, got {actual_fix!r}"
            )

    ledger["closedWorld"] += 1
    for actual in findings:
        if finding_key(actual) not in expected_keys:
            problems.append(
                f"findings[{finding_label(actual)}].identity: unexpected finding"
            )

    wanted_score = fx["expect"].get("score")
    if not isinstance(wanted_score, dict):
        problems.append("score: missing reviewed score object")
        return problems
    ledger["scoreFields"] += len(wanted_score)
    if sorted(score) != sorted(wanted_score):
        problems.append(
            f"score.keys: expected {sorted(wanted_score)!r}, got {sorted(score)!r}"
        )
    for field, wanted in wanted_score.items():
        actual = score.get(field)
        if actual != wanted:
            problems.append(
                f"score.{field}: expected {wanted!r}, got {actual!r}"
            )
    wanted_observations = fx["expect"].get("observations")
    if not isinstance(wanted_observations, dict) or set(wanted_observations) != OBSERVATION_KEYS:
        problems.append("observations: expected the closed mta_sts_policy/robots/rdap map")
    elif any(state not in OBSERVATION_STATES for state in wanted_observations.values()):
        problems.append("observations: fixture contains an unknown contract state")
    actual_observations = result.get("observations")
    ledger["observations"] += 1
    if actual_observations != wanted_observations:
        problems.append(
            f"observations: expected {wanted_observations!r}, got {actual_observations!r}"
        )
    return problems


def assertion_plan(fixtures):
    plan = {
        "identity": 0, "severity": 0, "action": 0, "fix": 0, "lane": 0,
        "detail": 0, "effort": 0, "value": 0,
        "scoreFields": 0, "closedWorld": 0, "observations": 0,
    }
    for fx in fixtures:
        if fx.get("mode") not in CONTRACT_MODES:
            continue
        expected, _ = expected_findings(fx)
        for field in ("identity", "severity", "action", "fix", "lane"):
            plan[field] += len(expected)
        plan["detail"] += sum("detail" in finding for finding in expected)
        plan["effort"] += sum("effort" in finding for finding in expected)
        plan["value"] += sum("value" in finding for finding in expected)
        plan["scoreFields"] += len(fx.get("expect", {}).get("score", {}))
        plan["closedWorld"] += 1
        plan["observations"] += 1
    return plan


def run():
    with open(os.path.join(HERE, "fixtures.json"), encoding="utf-8") as handle:
        fixtures = json.load(handle)["fixtures"]
    only = os.environ.get("CONFORMANCE_FIXTURE")
    if only:
        fixtures = [fx for fx in fixtures if fx["id"] == only]
        if not fixtures:
            print(f"unknown CONFORMANCE_FIXTURE: {only}", file=sys.stderr)
            return 2

    if not unexpected_http_host_is_refused():
        print("FAIL runner HTTP host map refuses unexpected host")
        return 1
    print("PASS runner HTTP host map refuses unexpected host")

    passed = failed = skipped = not_applicable = 0
    failures = []
    ledger = {
        "identity": 0, "severity": 0, "action": 0, "fix": 0, "lane": 0,
        "detail": 0, "effort": 0, "value": 0,
        "scoreFields": 0, "closedWorld": 0, "observations": 0,
    }

    for fx in fixtures:
        if fx.get("mode") not in CONTRACT_MODES:
            skipped += 1
            print(
                f"  SKIP  {fx['id']} ({fx['invariant']}) — "
                f"{fx.get('skip_reason', fx.get('mode'))}"
            )
            continue

        NETWORK_ATTEMPTS.clear()
        HTTP_CALLS.clear()
        install_resolver(fx["input"].get("dns", {}))
        install_http(fx["input"]["domain"], fx["input"].get("http", {}))
        now_ms = fx["input"].get("nowMs")
        audit.time.time = REAL_TIME if now_ms is None else lambda: now_ms / 1000
        if os.environ.get("CONFORMANCE_CANARY_NETWORK_LOOKUP") == "1":
            batch_score.dig = resolver.query

        try:
            result = run_shipping_audit(fx["input"]["domain"])
            findings = result.get("findings", [])
            score = run_score(fx["input"]["domain"])
            expected, n_a = expected_findings(fx)
            not_applicable += n_a
            if NETWORK_ATTEMPTS:
                raise AssertionError("; ".join(NETWORK_ATTEMPTS))
        except Exception as error:
            failed += 1
            message = f"{fx['id']}.execution: threw {error}"
            failures.append(message)
            print(f"  FAIL  {fx['id']} ({fx['invariant']}) — {message}")
            continue
        finally:
            audit.time.time = REAL_TIME

        problems = [
            *compare_legacy(fx, findings),
            *compare_contract(fx, result, score, ledger),
        ]
        for name, wanted in fx.get("expect", {}).get("httpCalls", {}).items():
            actual = HTTP_CALLS.get(name, 0)
            if actual != wanted:
                problems.append(
                    f"httpCalls.{name}: expected {wanted}, got {actual}"
                )
        if problems:
            failed += 1
            failures.extend(f"{fx['id']}.{problem}" for problem in problems)
            print(
                f"  FAIL  {fx['id']} ({fx['invariant']}) — "
                + "; ".join(problems)
            )
        else:
            passed += 1
            print(f"  PASS  {fx['id']} ({fx['invariant']})")

    plan = assertion_plan(fixtures)
    for field, wanted in plan.items():
        actual = ledger[field]
        if actual != wanted:
            failed += 1
            message = f"runner.assertions.{field}: expected {wanted}, got {actual}"
            failures.append(message)
            print(f"  FAIL  {message}")

    print("\nSurface: skill")
    print(f"Engine: {audit.__file__}")
    print(
        f"Results: {passed} passed, {failed} failed, {skipped} skipped, "
        f"{not_applicable} N/A."
    )
    if failures:
        print("Failures:\n- " + "\n- ".join(failures))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
