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

print("\nALL PASS" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
