#!/usr/bin/env python3
"""Conformance check for the Python skill surface (see SPEC.md).

Exercises the parser-level invariants fixed in v1.2 batch 1 against the real
scripts/audit.py functions — no network. Exits non-zero on any violation, so it
runs as a CI gate. The full DNS-driven fixtures (fixtures.json) are consumed by the
cross-surface runner in web-parity/ (WS1); this file guards the pure logic here.
"""
import base64
import os
import sys

SCRIPTS = os.path.join(
    os.path.dirname(__file__), "..",
    "amino-deliverability-audit", "skills", "amino-deliverability-audit", "scripts",
)
sys.path.insert(0, os.path.abspath(SCRIPTS))
import audit  # noqa: E402
import batch_score  # noqa: E402

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
_ROOT = os.path.join(os.path.dirname(__file__), "..")
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

# and the coupling: every doc asserted above must be in the workflow's path filter
_PATHS = {"FAQ.md": "- 'FAQ.md'", "README.md": "- 'README.md'",
          "CONTRIBUTING.md": "- 'CONTRIBUTING.md'", "SKILL.md": "SKILL.md'",
          "standards-radar.md": "references/**'"}
for _n, _pat in _PATHS.items():
    chk(f"CI would run this file when {_n} alone changes", _pat in _WF, True)

print("\nALL PASS" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
