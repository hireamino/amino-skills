#!/usr/bin/env python3
"""Conformance check for the Python skill surface (see SPEC.md).

Exercises the parser-level invariants fixed in v1.2 batch 1 against the real
scripts/audit.py functions — no network. Exits non-zero on any violation, so it
runs as a CI gate. The full DNS-driven fixtures (fixtures.json) are consumed by the
cross-surface runner in web-parity/ (WS1); this file guards the pure logic here.
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(__file__)
SCRIPTS = os.environ.get("AUDIT_SCRIPTS") or os.path.join(
    HERE, "..",
    "amino-deliverability-audit", "skills", "amino-deliverability-audit", "scripts",
)
sys.path.insert(0, os.path.abspath(SCRIPTS))
import audit  # noqa: E402
import batch_score  # noqa: E402
import resolver  # noqa: E402
import verify  # noqa: E402

_SHIPPING_CONFIRM_TXT = audit.confirm_txt

ok = True


def chk(name, got, exp):
    global ok
    p = got == exp
    ok = ok and p
    print(("PASS" if p else "FAIL"), name, "->", repr(got), "(exp", repr(exp) + ")")


# I1 — DKIM revoked (empty p=) is never healthy
chk("I1 dkim empty p= -> revoked", audit.parse_dkim("v=DKIM1; k=rsa; p=")[4], "revoked")
# I4 — Ed25519 must decode to exactly 32 bytes
chk("I4 ed25519 bad len -> malformed", audit.parse_dkim("v=DKIM1; k=ed25519; p=QUJD")[4], "malformed-ed25519")
_good_ed = base64.b64encode(b"\x00" * 32).decode()
chk("I4 ed25519 32B -> valid", audit.parse_dkim(f"v=DKIM1; k=ed25519; p={_good_ed}")[4], None)
# I14 — MTA-STS wildcard matches exactly one leftmost label
chk("I14 *.ex.com ~ mx.ex.com", audit._mx_pattern_matches("*.example.com", "mx.example.com"), True)
chk("I14 *.ex.com !~ a.b.ex.com", audit._mx_pattern_matches("*.example.com", "a.b.example.com"), False)
chk("I14 *.ex.com !~ ex.com", audit._mx_pattern_matches("*.example.com", "example.com"), False)
# I11 — SPF qualifier is case-insensitive
chk("I11 spf -ALL -> '-'", audit.spf_qualifier("v=spf1 -ALL"), "-")
chk("I11 spf ~All -> '~'", audit.spf_qualifier("v=spf1 ~All"), "~")
# I10 — org base (eTLD+1) distinguishes multi-label public suffixes
chk("I10 good.co.uk org", audit.org_base("good.co.uk"), "good.co.uk")
chk("I10 evil.co.uk org", audit.org_base("evil.co.uk"), "evil.co.uk")
chk("I10 aspmx.l.google.com org", audit.org_base("aspmx.l.google.com"), "google.com")
# I10 — tree walk: subdomain inherits nearest ancestor policy (mock resolver, no network)
_MOCK = {"_dmarc.example.co.uk": "v=DMARC1; p=reject"}
audit.confirm_txt = lambda name, prefix: _MOCK.get(name.rstrip(".").lower())
_rec, _source, _inherited = audit.discover_dmarc("send.example.co.uk")
chk("I10 treewalk finds ancestor", (_source, _inherited), ("example.co.uk", True))
chk("I10 treewalk returns record", _rec, "v=DMARC1; p=reject")
# I15 — MTA-STS strict field validation (RFC 8461)
chk("I15 valid enforce → no problems", audit.mta_sts_policy_problems("version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx.ex.com\n")[0], [])
chk("I15 enforce missing fields → problems", len(audit.mta_sts_policy_problems("mode: enforce\n")[0]) > 0, True)
chk("I15 max_age out of range → problem", any("max_age" in p for p in audit.mta_sts_policy_problems("version: STSv1\nmode: enforce\nmax_age: 99999999\nmx: a.ex.com")[0]), True)
chk("I15 mode none needs no mx", audit.mta_sts_policy_problems("version: STSv1\nmode: none\nmax_age: 100")[0], [])

# WHI-50 — only an unambiguous null MX exempts inbound-only controls.
chk("WHI-50 null MX is detected", audit.is_null_mx(["0 ."]), True)
chk("WHI-50 no MX is not exempt", audit.is_null_mx([]), False)
chk("WHI-50 null + real MX is ambiguous", audit.is_null_mx(["0 .", "10 mx.example.com."]), False)
_null_score = {bucket: False for bucket in batch_score.BOOL_BUCKETS}
for _bucket in ("MTA_STS", "TLS_RPT", "DANE"):
    _null_score[_bucket] = None
_null_score["DKIM"] = "good"
chk("WHI-50 N/A buckets do not add to gap", batch_score.gap_of(_null_score), 5)
chk("WHI-50 N/A bucket renders as dash", batch_score.disp(_null_score, "MTA_STS"), "—")
chk("WHI-50 verifier detects null MX independently", verify._null_mx_answer(["0 ."]), True)
chk("WHI-50 verifier does not exempt no MX", verify._null_mx_answer([]), False)
chk("WHI-50 verifier does not exempt ambiguous MX",
    verify._null_mx_answer(["0 .", "10 mx.example.com."]), False)
chk("WHI-50 verifier renders N/A as dash", verify.cell(None), "—")
_verify_doh, _verify_txt = verify.doh, verify.txt_starting
try:
    verify.txt_starting = lambda *_args, **_kwargs: None
    verify.doh = lambda name, rrtype, resolver="google": ["0 ."] if (name, rrtype) == ("d", "MX") else []
    _independent_null = verify.independent("d")[0]
    chk("WHI-50 verifier wires null MX into N/A buckets",
        tuple(_independent_null[b] for b in ("MTA_STS", "TLS_RPT", "DANE")),
        (None, None, None))
    verify.doh = lambda *_args, **_kwargs: []
    _independent_no_mx = verify.independent("d")[0]
    chk("WHI-50 verifier wiring does not exempt no MX",
        tuple(_independent_no_mx[b] for b in ("MTA_STS", "TLS_RPT", "DANE")),
        (False, False, False))
finally:
    verify.doh, verify.txt_starting = _verify_doh, _verify_txt

# WHI-125 — exercise the shipping dig backend, metadata side channel, finding,
# observation, and scorer. The subprocess seam is stubbed; no alternate classifier
# is introduced in the checker. Cache and metadata state are cleared between cases.
_resolver_run = resolver.subprocess.run
_resolver_sleep = resolver.time.sleep
_resolver_backend = resolver._BACKEND
_audit_dns_bindings = (
    audit.dig, audit.query_fresh, audit.confirm_txt, audit.dns_meta,
)
_audit_policy_fetch = audit._fetch_mta_sts_policy


def _dig_reply(status=None, name="lookup.invalid", rrtype="TXT", answers=()):
    header = "" if status is None else (
        f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n"
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n"
    )
    if not answers:
        return header
    rows = "\n".join(f"{name}. 60 IN {rrtype} {answer}" for answer in answers)
    return header + f";; ANSWER SECTION:\n{rows}\n\n"


def _result(stdout):
    return type("DigResult", (), {"stdout": stdout})()


try:
    resolver.time.sleep = lambda _seconds: None
    _terminal_rows = (
        ("SERVFAIL", "SERVFAIL", {"status": 2, "ad": False, "error": True}),
        ("REFUSED", "REFUSED", {"status": 5, "ad": False, "error": True}),
        ("no status", None, {"status": None, "ad": False, "error": True}),
        ("timeout", "timeout", {"status": None, "ad": False, "error": True}),
        ("NXDOMAIN", "NXDOMAIN", {"status": 3, "ad": False, "error": False}),
        ("NOERROR empty", "NOERROR", {"status": 0, "ad": False, "error": False}),
    )
    for _label, _status, _expected_meta in _terminal_rows:
        resolver.cache_clear()
        if _status == "timeout":
            def _stub_run(*_args, **_kwargs):
                raise resolver.subprocess.TimeoutExpired("dig", resolver.DNS_TIMEOUT)
        else:
            def _stub_run(*_args, _status=_status, **_kwargs):
                return _result(_dig_reply(_status))
        resolver.subprocess.run = _stub_run
        chk(f"WHI-125 resolver terminal {_label} answers", resolver._dig_backend(
            "_mta-sts.lookup.invalid", "TXT"), [])
        chk(f"WHI-125 resolver terminal {_label} meta", resolver.meta(
            "_mta-sts.lookup.invalid", "TXT"), _expected_meta)

    chk("WHI-125 dig and DoH SERVFAIL normalize identically",
        resolver.normalized_meta("SERVFAIL"), resolver.normalized_meta(2))
    chk("WHI-125 dig and DoH NXDOMAIN normalize identically",
        resolver.normalized_meta("NXDOMAIN"), resolver.normalized_meta(3))
    resolver.cache_clear()
    resolver.record_meta("_mta-sts.record-meta.invalid", "TXT", 2, False)
    chk("WHI-125 record_meta normalizes numeric DoH failure",
        resolver.meta("_mta-sts.record-meta.invalid", "TXT"),
        {"status": 2, "ad": False, "error": True})
    resolver.record_meta("_mta-sts.record-meta.invalid", "TXT", "NXDOMAIN", False)
    chk("WHI-125 record_meta normalizes named authoritative absence",
        resolver.meta("_mta-sts.record-meta.invalid", "TXT"),
        {"status": 3, "ad": False, "error": False})

    def _shipping_lookup(status):
        domain = "whi125-resolver.invalid"
        lookup_calls = []
        policy_fetches = []

        def _stub_run(args, **_kwargs):
            rrtype, name = args[-2:]
            if (name, rrtype) == (domain, "MX"):
                return _result(_dig_reply(
                    "NOERROR", domain, "MX", ("10 mx.whi125-resolver.invalid.",),
                ))
            if (name, rrtype) == (f"_mta-sts.{domain}", "TXT"):
                lookup_calls.append(status)
                return _result(_dig_reply(status, name, rrtype))
            return _result(_dig_reply("NOERROR", name, rrtype))

        resolver.cache_clear()
        resolver.subprocess.run = _stub_run
        resolver.set_backend(resolver._dig_backend)
        audit.dig = resolver.query
        audit.query_fresh = resolver.query_fresh
        audit.confirm_txt = _SHIPPING_CONFIRM_TXT
        audit.dns_meta = resolver.meta
        audit._fetch_mta_sts_policy = lambda _domain: (
            policy_fetches.append(_domain) or ("checked", "unexpected policy")
        )
        findings, observations = [], {}
        audit.check_mta_sts(domain, findings, observations)
        check_lookup_calls = len(lookup_calls)
        buckets, _note = batch_score.score(domain)
        return findings, observations, buckets, check_lookup_calls, policy_fetches

    (_failed_findings, _failed_observations, _failed_buckets,
     _failed_lookup_calls, _failed_policy_fetches) = _shipping_lookup("SERVFAIL")
    _failed_finding = next((finding for finding in _failed_findings
                            if finding["area"] == "MTA-STS"), None)
    chk("WHI-125 real SERVFAIL finding area",
        _failed_finding and _failed_finding.get("area"), "MTA-STS")
    chk("WHI-125 real SERVFAIL finding severity",
        _failed_finding and _failed_finding.get("severity"), "low")
    chk("WHI-125 real SERVFAIL finding title",
        _failed_finding and _failed_finding.get("title"),
        "Unable to confirm MTA-STS policy")
    chk("WHI-125 real SERVFAIL finding detail",
        _failed_finding and _failed_finding.get("detail"),
        "The DNS lookup for the _mta-sts record failed, so we could not tell whether an MTA-STS policy is published. This is not a finding that the policy is missing.")
    chk("WHI-125 real SERVFAIL finding fix",
        _failed_finding and _failed_finding.get("fix"),
        "Re-run the check. If it keeps failing, confirm your DNS provider answers TXT queries for _mta-sts.<domain>.")
    chk("WHI-125 real SERVFAIL finding action",
        _failed_finding and audit.action(_failed_finding),
        "Re-check the MTA-STS DNS record")
    chk("WHI-125 real SERVFAIL finding priority",
        _failed_finding and audit.priority(_failed_finding), ("high", "low"))
    chk("WHI-125 real SERVFAIL observation",
        _failed_observations.get("mta_sts_policy"), "unavailable")
    chk("WHI-125 real SERVFAIL score excludes MTA-STS",
        _failed_buckets["MTA_STS"], None)
    chk("WHI-125 real SERVFAIL exhausts backend and confirmation retries",
        _failed_lookup_calls, 9)
    chk("WHI-125 real SERVFAIL does not fetch the policy",
        _failed_policy_fetches, [])

    (_absent_findings, _absent_observations, _absent_buckets,
     _absent_lookup_calls, _absent_policy_fetches) = _shipping_lookup("NXDOMAIN")
    _absent_finding = next((finding for finding in _absent_findings
                            if finding["area"] == "MTA-STS"), None)
    chk("WHI-125 real NXDOMAIN finding title",
        _absent_finding and _absent_finding.get("title"), "No MTA-STS policy")
    chk("WHI-125 real NXDOMAIN observation",
        _absent_observations.get("mta_sts_policy"), "not_applicable")
    chk("WHI-125 real NXDOMAIN score remains a gap",
        _absent_buckets["MTA_STS"], False)
    chk("WHI-125 real NXDOMAIN completes all confirmation queries",
        _absent_lookup_calls, 3)
    chk("WHI-125 real NXDOMAIN does not fetch the policy",
        _absent_policy_fetches, [])
finally:
    resolver.subprocess.run = _resolver_run
    resolver.time.sleep = _resolver_sleep
    resolver.set_backend(_resolver_backend)
    audit.dig, audit.query_fresh, audit.confirm_txt, audit.dns_meta = _audit_dns_bindings
    audit._fetch_mta_sts_policy = _audit_policy_fetch

# WHI-10 — brand/optional findings never occupy a high-value quadrant.
chk("WHI-10 No BIMI priority", audit.priority({
    "area": "BIMI", "severity": "low", "title": "No BIMI",
}), ("high", "low"))
chk("WHI-10 BIMI without VMC priority", audit.priority({
    "area": "BIMI", "severity": "low", "title": "BIMI present without a VMC",
}), ("high", "low"))
chk("WHI-10 No CAA priority", audit.priority({
    "area": "CAA", "severity": "low", "title": "No CAA records",
}), ("low", "low"))

# WHI-79 — lanes and HTTP observation states are closed output-contract enums.
_EXPECTED_AREA_LANES = {
    "SPF": "outbound_auth", "DKIM": "outbound_auth", "DMARC": "outbound_auth",
    "MTA-STS": "inbound_transport", "TLS-RPT": "inbound_transport",
    "Transport": "inbound_transport", "MX": "inbound_transport",
    "BIMI": "brand_optional", "CAA": "brand_optional",
    "DNSSEC": "outside_sending_posture",
    "AI visibility": "outside_sending_posture",
    "Reputation": "outside_sending_posture",
}
_EXPECTED_BUCKET_LANES = {
    "SPF": "outbound_auth", "DKIM": "outbound_auth", "DMARC": "outbound_auth",
    "DMARC_enforced": "outbound_auth", "DMARC_rua": "outbound_auth",
    "MTA_STS": "inbound_transport", "TLS_RPT": "inbound_transport",
    "DANE": "inbound_transport", "BIMI": "brand_optional",
}
chk("WHI-79 lane enum is closed", audit.LANES,
    ("outbound_auth", "inbound_transport", "brand_optional", "outside_sending_posture"))
chk("WHI-79 all 12 finding areas have one lane", audit.AREA_LANES, _EXPECTED_AREA_LANES)
chk("WHI-79 reverse-DNS Transport finding is outside sending posture",
    audit.lane_for_finding({"area": "Transport", "title": "Mail server has no reverse DNS (PTR)"}),
    "outside_sending_posture")
chk("WHI-79 DANE Transport finding stays inbound",
    audit.lane_for_finding({"area": "Transport", "title": "No DANE/TLSA"}),
    "inbound_transport")
chk("WHI-79 every scored bucket has one lane", batch_score.BUCKET_LANES,
    _EXPECTED_BUCKET_LANES)
chk("WHI-79 observation enum is closed", audit.OBSERVATION_STATES,
    ("checked", "unavailable", "not_applicable"))
try:
    audit.lane_for_area("Unknown future area")
    _unknown_area_rejected = False
except ValueError:
    _unknown_area_rejected = True
chk("WHI-79 unknown finding area is rejected", _unknown_area_rejected, True)

# WHI-79 Phase A.2 — the Python socket guard uses the same explicit public-address
# contract as the canonical engine. DNS and sockets are stubbed at their lowest seams;
# these checks therefore exercise the shipping helper and all three shipping call sites.
_audit_dig = audit.dig


def _guarded_addresses(ipv4=(), ipv6=()):
    audit.dig = lambda _host, rrtype: list(ipv4 if rrtype == "A" else ipv6 if rrtype == "AAAA" else ())
    return audit.host_public_ips("guard.invalid")


_address_rows = (
    ("9.255.255.255", True), ("10.0.0.0", False),
    ("10.255.255.255", False), ("11.0.0.0", True),
    ("172.15.255.255", True), ("172.16.0.0", False),
    ("172.31.255.255", False), ("172.32.0.0", True),
    ("192.167.255.255", True), ("192.168.0.0", False),
    ("192.169.0.0", True), ("169.253.255.255", True),
    ("169.254.0.0", False), ("169.255.0.0", True),
    ("100.63.255.255", True), ("100.64.0.0", False),
    ("100.127.255.255", False), ("100.128.0.0", True),
    ("126.255.255.255", True), ("127.0.0.1", False),
    ("128.0.0.0", True), ("0.0.0.0", False), ("1.0.0.1", True),
)
for _address, _allowed in _address_rows:
    chk(f"WHI-79 address boundary {_address}",
        _guarded_addresses((_address,)), [_address] if _allowed else [])

_ipv6_rows = (
    ("2606:4700::1111", True), ("::1", False), ("::", False),
    ("fc00::1", False), ("fdff::1", False),
    ("fe80::1", False), ("febf::1", False),
    ("::ffff:127.0.0.1", False), ("::ffff:7f00:1", False),
    ("::ffff:93.184.216.34", True),
)
for _address, _allowed in _ipv6_rows:
    chk(f"WHI-79 address boundary {_address}",
        _guarded_addresses((), (_address,)), [_address] if _allowed else [])

chk("WHI-79 address list mixed public/private refuses host",
    _guarded_addresses(("93.184.216.34", "10.0.0.5")), [])
chk("WHI-79 address list public AAAA/link-local refuses host",
    _guarded_addresses((), ("2606:4700::1111", "fe80::1")), [])
chk("WHI-79 address list unparseable refuses host",
    _guarded_addresses(("93.184.216.34", "not-an-ip")), [])
chk("WHI-79 address list empty refuses host", _guarded_addresses(), [])
chk("WHI-79 address list two public returns both",
    _guarded_addresses(("93.184.216.34", "1.1.1.1")),
    ["93.184.216.34", "1.1.1.1"])
# CANARY-DETECTOR-BEGIN: public-subset
chk("WHI-79 detector mixed address refuses whole host",
    _guarded_addresses(("93.184.216.34", "10.0.0.5")), [])
# CANARY-DETECTOR-END: public-subset
# CANARY-DETECTOR-BEGIN: shared-space
chk("WHI-79 detector 100.64 shared address refuses host",
    _guarded_addresses(("100.64.0.1",)), [])
# CANARY-DETECTOR-END: shared-space
# CANARY-DETECTOR-BEGIN: mapped-address
chk("WHI-79 detector mapped 100.64 address refuses host",
    _guarded_addresses((), ("::ffff:100.64.0.1",)), [])
# CANARY-DETECTOR-END: mapped-address
audit.dig = _audit_dig


def _connection_recorder():
    attempts = []

    def connect(endpoint, _timeout):
        attempts.append(endpoint)
        raise OSError("WHI-79 deliberate socket stop")

    return attempts, connect


def _http_guard_probe(addresses):
    old_dig, old_connect = audit.dig, audit.socket.create_connection
    attempts, connect = _connection_recorder()
    try:
        audit.dig = lambda _host, rrtype: list(addresses if rrtype == "A" else ())
        audit.socket.create_connection = connect
        result = audit._http_get("guard.invalid", "/robots.txt")
        return result, attempts
    finally:
        audit.dig, audit.socket.create_connection = old_dig, old_connect


def _mta_sts_guard_probe(addresses):
    old_dig, old_connect = audit.dig, audit.socket.create_connection
    attempts, connect = _connection_recorder()
    try:
        audit.dig = lambda _host, rrtype: list(addresses if rrtype == "A" else ())
        audit.socket.create_connection = connect
        result = audit._fetch_mta_sts_policy("guard.invalid")
        return result, attempts
    finally:
        audit.dig, audit.socket.create_connection = old_dig, old_connect


def _mx_guard_probe(addresses):
    old_dig, old_meta, old_connect = audit.dig, audit.dns_meta, audit.socket.create_connection
    attempts, connect = _connection_recorder()
    findings = []
    try:
        def fixture_dig(host, rrtype):
            if (host, rrtype) == ("guard.invalid", "MX"):
                return ["10 mx.guard.invalid."]
            if (host, rrtype) == ("mx.guard.invalid", "A"):
                return list(addresses)
            return []

        audit.dig = fixture_dig
        audit.dns_meta = lambda *_args, **_kwargs: {}
        audit.socket.create_connection = connect
        audit.check_transport("guard.invalid", findings)
        unavailable = any(finding["title"] == "Could not establish STARTTLS to primary MX"
                          for finding in findings)
        return unavailable, attempts
    finally:
        audit.dig, audit.dns_meta, audit.socket.create_connection = old_dig, old_meta, old_connect


_refused_hosts = (
    ("none", ()),
    ("private", ("10.0.0.5",)),
    ("mixed", ("93.184.216.34", "10.0.0.5")),
    ("shared", ("100.64.0.1",)),
)
_expected_http = [
    (name, ((None, None), [])) for name, _addresses in _refused_hosts
] + [("allowed", ((None, None), [("93.184.216.34", 443)]))]
_expected_mta = [
    (name, (("unavailable", None), [])) for name, _addresses in _refused_hosts
] + [("allowed", (("unavailable", None), [("93.184.216.34", 443)]))]
_expected_mx = [
    (name, (True, [])) for name, _addresses in _refused_hosts
] + [("allowed", (True, [("93.184.216.34", 25)]))]
_probe_inputs = list(_refused_hosts) + [("allowed", ("93.184.216.34",))]
chk("WHI-79 shipping _http_get address guard",
    [(name, _http_guard_probe(addresses)) for name, addresses in _probe_inputs],
    _expected_http)
chk("WHI-79 shipping MTA-STS address guard",
    [(name, _mta_sts_guard_probe(addresses)) for name, addresses in _probe_inputs],
    _expected_mta)
chk("WHI-79 shipping MX STARTTLS address guard",
    [(name, _mx_guard_probe(addresses)) for name, addresses in _probe_inputs],
    _expected_mx)
# CANARY-DETECTOR-BEGIN: http-get-guard
chk("WHI-79 detector _http_get blocks a private address",
    _http_guard_probe(("10.0.0.5",)), ((None, None), []))
# CANARY-DETECTOR-END: http-get-guard
# CANARY-DETECTOR-BEGIN: mta-sts-guard
chk("WHI-79 detector MTA-STS blocks a private address",
    _mta_sts_guard_probe(("10.0.0.5",)), (("unavailable", None), []))
# CANARY-DETECTOR-END: mta-sts-guard
# CANARY-DETECTOR-BEGIN: mx-guard
chk("WHI-79 detector MX STARTTLS blocks a private address",
    _mx_guard_probe(("10.0.0.5",)), (True, []))
# CANARY-DETECTOR-END: mx-guard

# A non-pass fixture with no remediation would let /audit render an action in its
# plan and "no action needed" in its evidence row for the same finding.
with open(os.path.join(HERE, "fixtures.json"), encoding="utf-8") as _handle:
    _FIXTURES = json.load(_handle)["fixtures"]
_NON_PASS_WITHOUT_FIX = [
    f"{_fixture['id']}:{_finding['area']}|{_finding['title']}"
    for _fixture in _FIXTURES
    for _finding in _fixture.get("expect", {}).get("findings", [])
    if _finding.get("severity") != "pass" and _finding.get("fixIncludes") is None
]
chk("WHI-10 every non-pass fixture finding declares a fix", _NON_PASS_WITHOUT_FIX, [])

# ── DMARC enforcement advice (RFC 9989 §7.4) ────────────────────────────────
# The short action label is the ONLY remediation text some surfaces render, so it
# is asserted BEHAVIOURALLY against the real mapper, not by grepping the source.
# §7.4 scopes both its "SHOULD NOT publish p=reject" and its month-then-month
# staging advice to domains hosting users who might post to mailing lists — so
# neither may be stated here as universal, and the label must not name reject.
_pnone = {"area": "DMARC", "severity": "high", "title": "DMARC policy is p=none (monitor only)"}
chk("§7.4 label is the staged one", audit.action(_pnone), "Review DMARC reports, then stage quarantine")
chk("§7.4 label does not name reject", "reject" in audit.action(_pnone).lower(), False)

_SRC = open(os.path.join(SCRIPTS, "audit.py"), encoding="utf-8").read()
chk("§7.4 reject is not framed as the destination",
    "ramp to p=quarantine" in _SRC, False)
chk("§7.4 no unevidenced provider trust-signal claim",
    "increasingly treat enforced policies as a trust signal" in _SRC, False)
chk("§7.4 mailing-list caution is stated and scoped",
    "users may post to mailing lists not to publish p=reject" in _SRC, True)
chk("§7.4 staging advice is scoped, not universal",
    "for those that still do, it recommends at least a month" in _SRC, True)
chk("§7.4 DKIM-not-SPF-alone prerequisite is stated",
    "DMARC-aligned DKIM rather than relying only on SPF" in _SRC, True)
chk("t=y is offered in place of the removed pct", "use t=y to test an enforcement policy" in _SRC, True)

# ── the DOCS carry claims too, and nothing was reading them ─────────────────
# The np= cousin-domain claim was corrected in all three ENGINES on 2026-07-30 and
# guarded by an assertion that reads engine source — so it survived in FAQ.md, the
# public front door of this skill, for three weeks. A claim guard that only inspects
# code cannot see the docs shipped beside it.
_ROOT = os.path.join(HERE, "..")
_FAQ = open(os.path.join(_ROOT, "FAQ.md"), encoding="utf-8").read()
_SKILL = open(os.path.join(
    _ROOT, "amino-deliverability-audit", "skills", "amino-deliverability-audit", "SKILL.md"
), encoding="utf-8").read()

chk("FAQ: p=reject is not called 'the goal'", "This is the goal" in _FAQ, False)
chk("FAQ: p=none is not called the most common deliverability mistake",
    "most common deliverability mistake" in _FAQ, False)
chk("FAQ: the recommended starting record is p=none with rua",
    "v=DMARC1; p=none; rua=mailto:reports@yourdomain.com" in _FAQ, True)
chk("FAQ: no p=reject record offered as the universal good posture",
    "A strong posture looks like:\n`v=DMARC1; p=reject" in _FAQ, False)
chk("FAQ: the §7.4 mailing-list caveat is stated",
    "SHOULD NOT** publish `p=reject`" in _FAQ, True)
chk("FAQ: np= is not claimed to stop cousin-domain spoofing",
    "cousin-domain spoofing trick" in _FAQ, False)
chk("FAQ: the cousin-domain limit is stated explicitly",
    "no DMARC policy on your domain can reach it" in _FAQ, True)
chk("SKILL: no unevidenced provider trust-signal claim",
    "read enforcement as a trust signal" in _SKILL, False)

# check.py runs ONLY from conformance.yml, and only for the paths that workflow filters
# on. Adding a docs assertion above without widening that filter would have produced a
# guard that never runs for the change it exists to catch — the same "a test file is not
# a test until CI runs it" trap already recorded on /preflight. Assert the coupling.
_WF = open(os.path.join(_ROOT, ".github", "workflows", "conformance.yml"), encoding="utf-8").read()
chk("CI would run this file when FAQ.md alone changes", "- 'FAQ.md'" in _WF, True)
chk("CI would run this file when SKILL.md alone changes",
    "amino-deliverability-audit/SKILL.md'" in _WF, True)
chk("WHI-79 CI runs for corpus/spec/runner changes", "- 'conformance/**'" in _WF, True)
chk("WHI-79 CI runs for Python engine/scorer changes",
    "amino-deliverability-audit/skills/amino-deliverability-audit/scripts/**" in _WF,
    True)
chk("WHI-79 CI includes Python 3.12", "python-version: ['3.12', '3.14']" in _WF, True)
chk("WHI-79 CI includes Python 3.14", "python-version: ['3.12', '3.14']" in _WF, True)
_RUNNER = open(os.path.join(HERE, "run_py.py"), encoding="utf-8").read()
chk("WHI-79 runner routes MTA-STS through shipping address helper",
    'audit.host_public_ips(f"mta-sts.{domain}")' in _RUNNER, True)
chk("WHI-79 runner routes robots through shipping address helper",
    'host != "rdap.org" and not audit.host_public_ips(host)' in _RUNNER, True)
chk("WHI-79 runner keeps fixed rdap.org host exempt",
    'name = "rdap" if host == "rdap.org" else "robots"' in _RUNNER, True)

# ── the OTHER claims corrected in the engines on 2026-07-30 ────────────────
# Same lesson as the np= one directly above: each of these was fixed in audit.py and
# left standing in the docs, because the guards written for them grep engine source.
# Every doc that states a claim is now read here, and every doc read here is listed in
# conformance.yml's path filter (asserted at the end).
_DOCS = {
    "FAQ.md": _FAQ,
    "README.md": open(os.path.join(_ROOT, "README.md"), encoding="utf-8").read(),
    "CONTRIBUTING.md": open(os.path.join(_ROOT, "CONTRIBUTING.md"), encoding="utf-8").read(),
    "SKILL.md": _SKILL,
    "standards-radar.md": open(os.path.join(
        _ROOT, "amino-deliverability-audit", "skills", "amino-deliverability-audit",
        "references", "standards-radar.md"), encoding="utf-8").read(),
}
# Markdown wraps, so a claim can straddle a line break. Normalise whitespace before
# matching — otherwise an assertion fails on reflow rather than on the claim changing,
# and the next person "fixes" it by weakening the assertion.
_flat = lambda t: " ".join(t.split())
_DOCS = {k: _flat(v) for k, v in _DOCS.items()}
_ALL = " ".join(_DOCS.values())

# The scope claim. audit.py fetches the MTA-STS policy over HTTPS (~l.598), RDAP at
# rdap.org (~l.887) and robots.txt (~l.965). "Inspects public DNS" understates what a
# user's domain gets sent to, which makes it a transparency claim, not a detail.
chk("docs: no bare 'inspects public DNS' scope claim",
    "inspects public DNS" in _ALL, False)
for _n in ("FAQ.md", "README.md", "CONTRIBUTING.md", "SKILL.md"):
    chk(f"docs: {_n} names the non-DNS fetches", "RDAP" in _DOCS[_n], True)

# IR 8547 — re-verified at csrc.nist.gov 2026-08-19: still an Initial Public Draft
# (published 2024-11-12, comments closed 2025-01-10, no final publication).
chk("docs: IR 8547 is not presented as settled policy",
    "IR 8547) sets" in _ALL or "IR 8547** sets" in _ALL, False)
chk("docs: IR 8547 draft status is stated in FAQ.md",
    "still an initial public draft" in _DOCS["FAQ.md"], True)
chk("docs: IR 8547 draft status is stated in standards-radar.md",
    "still an initial public draft" in _DOCS["standards-radar.md"], True)

# No standardized PQ-DKIM exists — /cbom already said this correctly while the FAQ
# asserted a migration path, i.e. our own surfaces contradicted each other.
chk("docs: no claimed PQC migration path for DKIM",
    "the migration path is to larger PQC signatures" in _ALL, False)
chk("docs: the absence of a PQ-DKIM path is stated",
    "no standardized post-quantum path" in _ALL, True)

# Google scopes one-click unsubscribe. Verified verbatim: "Marketing messages and
# subscribed messages must support one-click unsubscribe".
chk("docs: one-click unsubscribe is scoped, not blanket",
    "marketing and subscribed messages" in _ALL, True)

# BSI TR-03108, not NIS2, is what actually specifies secure email transport.
chk("docs: MTA-STS compliance cites BSI TR-03108", "TR-03108" in _ALL, True)

# WHI-125 — every user/contributor-facing document preserves the evidence boundary:
# resolver failure is unavailable, while only authoritative absence means missing.
chk("WHI-125 README distinguishes MTA-STS lookup failure",
    "A failed `_mta-sts` TXT lookup is reported as **“Unable to confirm MTA-STS policy”** and excluded from the gap" in _DOCS["README.md"], True)
chk("WHI-125 FAQ distinguishes MTA-STS lookup failure",
    "A resolver failure is not evidence that the policy is missing; re-run the check before changing DNS." in _DOCS["FAQ.md"], True)
chk("WHI-125 CONTRIBUTING forbids failure-as-absence",
    "Never turn resolver failure into an absent-record finding." in _DOCS["CONTRIBUTING.md"], True)
chk("WHI-125 SKILL treats the finding as unavailable evidence",
    "Treat **“Unable to confirm MTA-STS policy”** as unavailable evidence, not as a missing policy" in _DOCS["SKILL.md"], True)
chk("WHI-125 docs do not call resolver failure a missing policy",
    "resolver failure means the mta-sts policy is missing" in _ALL.lower(), False)

# and the coupling: every doc asserted above must be in the workflow's path filter
_PATHS = {"FAQ.md": "- 'FAQ.md'", "README.md": "- 'README.md'",
          "CONTRIBUTING.md": "- 'CONTRIBUTING.md'", "SKILL.md": "SKILL.md'",
          "standards-radar.md": "references/**'"}
for _n, _pat in _PATHS.items():
    chk(f"CI would run this file when {_n} alone changes", _pat in _WF, True)

print("\nALL PASS" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
