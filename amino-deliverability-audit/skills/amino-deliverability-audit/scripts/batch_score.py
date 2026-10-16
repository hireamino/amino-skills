#!/usr/bin/env python3
"""
Batch scoring mode for amino-deliverability-audit.

Takes "Company=domain" (or bare domains) and emits a TSV scoring matrix of
Yes/No buckets per prospect plus separate outbound, inbound, and brand gap
counts. Read-only DNS.

Notes:
- DKIM is THREE-STATE: good (modern key) = Y, weak (RSA-1024) = N and counts as a
  gap, unknown (no key at probed selectors) = "—" and is EXCLUDED from the gap
  (DKIM has no discovery mechanism, so absence isn't a confirmed gap).
- Authoritative NXDOMAINs are reported as "NR" (not a maximally-broken lead).
- Resolver failures stay in the normal scoring path and the shipping audit's
  shared inconclusive reason is disclosed in the Unconfirmed column.
- DNS is memoized (audit.dig is @lru_cache'd) so shared records aren't re-queried.
"""

import re
import sys
from audit import (dig, first_txt, count_spf_lookups, effective_terminator,
                   resolves, dkim_lookup, mx_providers, is_null_mx,
                   mta_sts_txt_lookup, dmarc_policy_context,
                   inconclusive_state)

# Deterministic boolean buckets (DKIM is handled separately as a 3-state). The
# three inbound-only buckets are None/N/A for a true null-MX domain.
BOOL_BUCKETS = ["SPF", "DMARC", "DMARC_enforced", "DMARC_rua",
                "MTA_STS", "TLS_RPT", "DANE", "BIMI"]
# Output/column order — DKIM stays 2nd to match the Amino Research sheet layout.
OUT_ORDER = ["SPF", "DKIM", "DMARC", "DMARC_enforced", "DMARC_rua",
             "MTA_STS", "TLS_RPT", "DANE", "BIMI"]
BUCKETS = OUT_ORDER  # back-compat alias (verify.py imports this)
BUCKET_LANES = {
    "SPF": "outbound_auth",
    "DKIM": "outbound_auth",
    "DMARC": "outbound_auth",
    "DMARC_enforced": "outbound_auth",
    "DMARC_rua": "outbound_auth",
    "MTA_STS": "inbound_transport",
    "TLS_RPT": "inbound_transport",
    "DANE": "inbound_transport",
    "BIMI": "brand_optional",
}
LANE_GAP_COLUMNS = (
    ("outbound_auth", "Outbound_gaps"),
    ("inbound_transport", "Inbound_gaps"),
    ("brand_optional", "Brand_gaps"),
)


def score(domain):
    """Return (r, note). r has the 8 BOOL_BUCKETS plus r['DKIM'] as a 3-state
    string ('good' | 'weak' | 'unknown') and the closed scored-bucket lane map."""
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

    dmarc_context = dmarc_policy_context(domain)
    dmarc = dmarc_context["record"]
    if dmarc and dmarc_context["relationship"] in ("self", "psd"):
        r["DMARC"] = True
        if dmarc_context["relationship"] == "psd":
            p = dmarc_context["effective"]
        else:
            # Preserve the pre-WHI-251 scorer's exact parsing outside the new PSD case.
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

    mx = dig(domain, "MX")
    null_mx = is_null_mx(mx)
    if null_mx:
        r["MTA_STS"] = None
        r["TLS_RPT"] = None
        r["DANE"] = None
    else:
        mta_sts_txt, mta_sts_lookup_failed = mta_sts_txt_lookup(domain)
        r["MTA_STS"] = None if mta_sts_lookup_failed else bool(mta_sts_txt)
        r["TLS_RPT"] = bool(first_txt(f"_smtp._tls.{domain}", "v=tlsrptv1"))
    real_mx = [row for row in mx if row.split() and row.split()[-1].rstrip(".")]
    if real_mx and not null_mx:
        host = sorted(real_mx, key=lambda x: int(x.split()[0]) if x.split()[0].isdigit() else 99)[0].split()[-1].rstrip(".")
        r["DANE"] = bool(dig(f"_25._tcp.{host}", "TLSA"))
    provs = {p for _, _, p in mx_providers(domain)}
    if len(provs) > 1:
        note.append(f"mixed MX ({len(provs)} providers)")
    r["BIMI"] = bool(first_txt(f"default._bimi.{domain}", "v=bimi1"))

    r["lanes"] = dict(BUCKET_LANES)
    return r, "; ".join(note) if note else "clean"


def gap_of(r):
    """Failing buckets. DKIM contributes ONLY when weak (RSA-1024); unknown is
    excluded so a discovery blind spot never inflates the pain score."""
    g = sum(1 for b in BOOL_BUCKETS if r[b] is False)
    if r["DKIM"] == "weak":
        g += 1
    return g


def disp(r, k):
    if k == "DKIM":
        return {"good": "Y", "weak": "N", "invalid": "N", "unknown": "—"}[r["DKIM"]]
    if r[k] is None:
        return "—"
    return "Y" if r[k] else "N"


def lane_gaps(r):
    """Count only confirmed N cells in each product lane.

    A lane made entirely of N/A cells remains N/A.  In particular, a true
    null-MX domain prints an inbound dash rather than the misleading number 0.
    """
    result = {}
    for lane, column in LANE_GAP_COLUMNS:
        cells = [disp(r, bucket) for bucket in OUT_ORDER
                 if BUCKET_LANES[bucket] == lane]
        result[column] = None if all(cell == "—" for cell in cells) else cells.count("N")
    return result


def display_lane_gap(value):
    return "—" if value is None else str(value)


def main():
    items = sys.argv[1:]
    if not items:
        print("usage: batch_score.py Company=domain ...", file=sys.stderr)
        sys.exit(1)
    gap_columns = [column for _, column in LANE_GAP_COLUMNS]
    print("\t".join(["Company", "Domain"] + OUT_ORDER
                    + gap_columns + ["Unconfirmed", "Highlights"]))
    for it in items:
        company, _, domain = it.partition("=")
        if not domain:
            domain = company
        domain = domain.strip().lower()
        if not resolves(domain):
            print("\t".join([company, domain] + ["—"] * len(OUT_ORDER)
                            + ["NR"] * len(gap_columns)
                            + ["—", "DOMAIN DID NOT RESOLVE (authoritative NXDOMAIN) — verify the domain"]))
            continue
        r, note = score(domain)
        gaps = lane_gaps(r)
        _, reason = inconclusive_state(domain)
        highlight = "none" if note == "clean" else note
        print("\t".join([company, domain] + [disp(r, k) for k in OUT_ORDER]
                        + [display_lane_gap(gaps[column]) for column in gap_columns]
                        + [reason or "—", highlight]))


if __name__ == "__main__":
    main()
