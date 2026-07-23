#!/usr/bin/env python3
"""
Batch scoring mode for amino-deliverability-audit.

Takes "Company=domain" (or bare domains) and emits a TSV scoring matrix of
Yes/No buckets per prospect plus a Gap score (failing buckets = deliverability
pain = outreach opportunity). Read-only DNS.

Notes:
- DKIM is THREE-STATE: good (modern key) = Y, weak (RSA-1024) = N and counts as a
  gap, unknown (no key at probed selectors) = "—" and is EXCLUDED from the gap
  (DKIM has no discovery mechanism, so absence isn't a confirmed gap).
- Non-resolving domains are reported as Gap "NR" (not a maximally-broken lead).
- DNS is memoized (audit.dig is @lru_cache'd) so shared records aren't re-queried.
"""

import re
import sys
from audit import (dig, first_txt, count_spf_lookups, effective_terminator,
                   resolves, dkim_lookup, mx_providers)

# Deterministic boolean buckets (DKIM is handled separately as a 3-state).
BOOL_BUCKETS = ["SPF", "DMARC", "DMARC_enforced", "DMARC_rua",
                "MTA_STS", "TLS_RPT", "DANE", "BIMI"]
# Output/column order — DKIM stays 2nd to match the Amino Research sheet layout.
OUT_ORDER = ["SPF", "DKIM", "DMARC", "DMARC_enforced", "DMARC_rua",
             "MTA_STS", "TLS_RPT", "DANE", "BIMI"]
BUCKETS = OUT_ORDER  # back-compat alias (verify.py imports this)


def score(domain):
    """Return (r, note). r has the 8 BOOL_BUCKETS plus r['DKIM'] as a 3-state
    string ('good' | 'weak' | 'unknown')."""
    r = {b: False for b in BOOL_BUCKETS}
    note = []

    spf = first_txt(domain, "v=spf1")
    if spf:
        q = effective_terminator(domain)
        lookups, voids = count_spf_lookups(domain)
        r["SPF"] = q in ("-", "~") and lookups <= 10 and voids <= 2
        if q in ("+", "?"):
            note.append(f"SPF {q}all (permissive)")
        elif q is None:
            note.append("SPF no 'all' mechanism")
        if lookups > 10:
            note.append(f"SPF {lookups} lookups")
    else:
        note.append("no SPF")

    dkim_state, dkim_note, _ = dkim_lookup(domain)
    r["DKIM"] = dkim_state
    if dkim_state != "good":
        note.append(dkim_note)

    dmarc = first_txt(f"_dmarc.{domain}", "v=dmarc1")
    if dmarc:
        r["DMARC"] = True
        m = re.search(r"p=\s*(\w+)", dmarc)
        p = m.group(1).lower() if m else ""
        r["DMARC_enforced"] = p in ("quarantine", "reject")
        r["DMARC_rua"] = "rua=" in dmarc.replace(" ", "")
        if p == "none":
            note.append("DMARC p=none")
        if not r["DMARC_rua"]:
            note.append("no rua")
    else:
        note.append("no DMARC")

    r["MTA_STS"] = bool(first_txt(f"_mta-sts.{domain}", "v=stsv1"))
    r["TLS_RPT"] = bool(first_txt(f"_smtp._tls.{domain}", "v=tlsrptv1"))
    mx = dig(domain, "MX")
    if mx:
        host = sorted(mx, key=lambda x: int(x.split()[0]) if x.split()[0].isdigit() else 99)[0].split()[-1].rstrip(".")
        r["DANE"] = bool(dig(f"_25._tcp.{host}", "TLSA"))
    provs = {p for _, _, p in mx_providers(domain)}
    if len(provs) > 1:
        note.append(f"mixed MX ({len(provs)} providers)")
    r["BIMI"] = bool(first_txt(f"default._bimi.{domain}", "v=bimi1"))

    return r, "; ".join(note) if note else "clean"


def gap_of(r):
    """Failing buckets. DKIM contributes ONLY when weak (RSA-1024); unknown is
    excluded so a discovery blind spot never inflates the pain score."""
    g = sum(1 for b in BOOL_BUCKETS if not r[b])
    if r["DKIM"] == "weak":
        g += 1
    return g


def disp(r, k):
    if k == "DKIM":
        return {"good": "Y", "weak": "N", "invalid": "N", "unknown": "—"}[r["DKIM"]]
    return "Y" if r[k] else "N"


def main():
    items = sys.argv[1:]
    if not items:
        print("usage: batch_score.py Company=domain ...", file=sys.stderr)
        sys.exit(1)
    print("\t".join(["Company", "Domain"] + OUT_ORDER + ["Gap", "Highlights"]))
    for it in items:
        company, _, domain = it.partition("=")
        if not domain:
            domain = company
        domain = domain.strip().lower()
        if not resolves(domain):
            print("\t".join([company, domain] + ["—"] * len(OUT_ORDER)
                            + ["NR", "DOMAIN DID NOT RESOLVE (NXDOMAIN/no NS) — verify the domain"]))
            continue
        r, note = score(domain)
        print("\t".join([company, domain] + [disp(r, k) for k in OUT_ORDER] + [str(gap_of(r)), note]))


if __name__ == "__main__":
    main()
