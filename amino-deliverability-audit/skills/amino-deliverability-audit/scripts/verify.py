#!/usr/bin/env python3
"""
Verification harness — cross-checks the scanner (dig via system resolver) against
an INDEPENDENT re-derivation over two authoritative resolvers (Google 8.8.8.8 +
Cloudflare 1.1.1.1), queried with dig over :53 (this env blocks outbound HTTPS, so
DoH-over-443 isn't reachable). Different resolver + different code path = a real
cross-check. Prints scanner vs each resolver per bucket, flagging DIFFs.

Usage: python3 verify.py domain1 domain2 ...
"""

import re
import subprocess
import sys
from batch_score import score as scanner_score, BOOL_BUCKETS, OUT_ORDER
from audit import dkim_candidates, parse_dkim

RESOLVERS = {"google": "8.8.8.8", "cloudflare": "1.1.1.1"}


def doh(name, rrtype, resolver="google"):
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=4", "+tries=1", f"@{RESOLVERS[resolver]}", rrtype, name],
            capture_output=True, text=True, timeout=12,
        ).stdout.strip()
    except Exception:
        return []
    rows = [r.strip() for r in out.splitlines() if r.strip()]
    if rrtype == "TXT":
        return ["".join(re.findall(r'"([^"]*)"', r)) or r for r in rows]
    return rows


def txt_starting(name, prefix, resolver):
    for rec in doh(name, "TXT", resolver):
        if rec.lower().startswith(prefix.lower()):
            return rec
    return None


def spf_terminator(spf):
    m = re.search(r"([-~?+]?)all\b", spf)
    return "none" if not m else (m.group(1) or "+") + "all"


def eff_term(domain, resolver, seen=None, depth=0):
    if seen is None:
        seen = set()
    if depth > 10 or domain in seen:
        return "none"
    seen.add(domain)
    spf = txt_starting(domain, "v=spf1", resolver)
    if not spf:
        return "none"
    t = spf_terminator(spf)
    if t != "none":
        return t
    m = re.search(r"redirect=(\S+)", spf)
    return eff_term(m.group(1).rstrip(";"), resolver, seen, depth + 1) if m else "none"


def count_lookups(domain, resolver, seen=None, depth=0):
    if seen is None:
        seen = set()
    if depth > 12 or domain in seen:
        return 0
    seen.add(domain)
    spf = txt_starting(domain, "v=spf1", resolver)
    if not spf:
        return 0
    n = 0
    for tok in spf.split():
        t = tok.lower()
        if t.startswith(("include:", "a:", "mx:", "ptr", "exists:", "redirect=")):
            n += 1
            if t.startswith("include:"):
                n += count_lookups(tok.split(":", 1)[1], resolver, seen, depth + 1)
            elif t.startswith("redirect="):
                n += count_lookups(tok.split("=", 1)[1], resolver, seen, depth + 1)
        elif t in ("a", "mx"):
            n += 1
    return n


def dkim_state_indep(domain, resolver):
    """Four-state DKIM via the given resolver (mirrors audit.dkim_lookup)."""
    weak = False
    invalid = False
    for sel in dkim_candidates(domain):
        rec = txt_starting(f"{sel}._domainkey.{domain}", "v=dkim1", resolver)
        if not rec:
            rec = next((r for r in doh(f"{sel}._domainkey.{domain}", "TXT", resolver) if "p=" in r), None)
        if rec:
            ktype, pub, bits, _, invalid_reason = parse_dkim(rec)
            if invalid_reason is not None:
                invalid = True
                continue
            if ktype == "rsa" and bits == 1024:
                weak = True
                continue
            return "good"
    if weak:
        return "weak"
    if invalid:
        return "invalid"
    return "unknown"


def independent(domain, resolver="google"):
    r = {b: False for b in BOOL_BUCKETS}
    spf = txt_starting(domain, "v=spf1", resolver)
    term = eff_term(domain, resolver) if spf else "none"
    lookups = count_lookups(domain, resolver) if spf else 0
    r["SPF"] = bool(spf) and (term or "").lower() in ("-all", "~all") and lookups <= 10
    dmarc = txt_starting(f"_dmarc.{domain}", "v=dmarc1", resolver)
    if dmarc:
        r["DMARC"] = True
        p = (re.search(r"p=\s*(\w+)", dmarc, re.I) or [None, ""])[1].lower()
        r["DMARC_enforced"] = p in ("quarantine", "reject")
        r["DMARC_rua"] = "rua=" in dmarc.replace(" ", "")
    r["MTA_STS"] = bool(txt_starting(f"_mta-sts.{domain}", "v=stsv1", resolver))
    r["TLS_RPT"] = bool(txt_starting(f"_smtp._tls.{domain}", "v=tlsrptv1", resolver))
    mx = doh(domain, "MX", resolver)
    if mx:
        host = sorted(mx, key=lambda x: int(x.split()[0]) if x.split()[0].isdigit() else 99)[0].split()[-1].rstrip(".")
        r["DANE"] = bool(doh(f"_25._tcp.{host}", "TLSA", resolver))
    r["BIMI"] = bool(txt_starting(f"default._bimi.{domain}", "v=bimi1", resolver))
    r["DKIM"] = dkim_state_indep(domain, resolver)
    return r, term, lookups


def cell(v):
    if isinstance(v, bool):
        return "Y" if v else "N"
    return {"good": "Y", "weak": "wk", "unknown": "?"}.get(v, v)


def main():
    for d in sys.argv[1:]:
        d = d.strip().lower()
        sc, _ = scanner_score(d)
        g, gterm, glook = independent(d, "google")
        c, _, _ = independent(d, "cloudflare")
        print(f"\n=== {d} ===")
        print(f"  SPF terminator (indep): {gterm}  |  SPF lookups (indep): {glook}")
        print(f"  {'bucket':<16}{'scanner':<9}{'google':<9}{'cloudflare':<11}flag")
        for k in OUT_ORDER:
            flag = "" if (sc[k] == g[k] == c[k]) else "  <-- DIFF"
            print(f"  {k:<16}{cell(sc[k]):<9}{cell(g[k]):<9}{cell(c[k]):<11}{flag}")


if __name__ == "__main__":
    main()
