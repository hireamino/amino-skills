#!/usr/bin/env python3
"""
amino-deliverability-audit — email-trust posture scanner.

Read-only. Inspects a domain's public email-authentication & transport posture
via DNS + a couple of well-known HTTPS endpoints, and emits structured findings
as JSON on stdout. No DNS changes are ever made. Pairs with SKILL.md, which
turns this JSON into an outcome-framed, prioritized remediation report.

Usage:  python3 audit.py example.com
Deps:   `dig` (ships with macOS / most Linux). Pure stdlib otherwise.
"""

import json
import re
import subprocess
import sys
import socket
import ssl
from functools import lru_cache

TIMEOUT = 6        # DNS (dig) — fast, rarely blocked
SOCK_TIMEOUT = 3   # raw socket probes (STARTTLS:25, MTA-STS HTTPS) — these hit
                   # blocked ports on many networks, so fail fast rather than hang

# DKIM has no discovery mechanism (you must know the selector), so we probe.
# Efficiency: probe PROVIDER-SPECIFIC selectors first (inferred from MX/SPF), then
# a curated high-yield common list — and early-exit on the first good key. This
# turns a ~50-query sweep into ~1-2 queries for the common (Google/M365) case.
# A miss is still only "not found via common selectors", never "no DKIM".
# NOTE on coverage vs latency: published selector wordlists run to ~2,000 entries,
# but probing all of them synchronously would blow the ~10-20s scan budget on any
# domain that signs with a custom selector (the early-exit only helps when a key is
# FOUND). So we keep a curated provider-weighted list and lean on provider-first
# ordering for the common case; expanding further is a coverage/latency trade.
DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "default2", "k1", "k2", "k3",
    "mandrill", "dkim", "dkim1", "dkim2", "mail", "smtp", "s1", "s2", "s1024", "s2048",
    "sig1", "cf2024-1", "mxvault", "zoho", "zmail", "pm", "pm-bounces", "scph0", "scph1",
    "sendgrid", "sg", "fd", "fm1", "fm2", "fm3", "mte1", "mte2", "m1", "marketo",
    "amazonses", "ses", "sparkpost", "mailjet", "klaviyo", "hs1", "hs2", "hubspot",
    "protonmail", "protonmail2", "protonmail3", "cm", "mailerlite", "ml",
    "everlytickey1", "key1", "1", "2", "mailo", "turbo-smtp",
]

# Provider fingerprint (substring of MX host / SPF) -> its known selectors.
PROVIDER_SELECTORS = {
    "google": ["google"],
    "outlook": ["selector1", "selector2"],
    "pphosted": ["selector1", "selector2"],   # Proofpoint
    "mimecast": ["mimecast", "selector1"],
    "mandrill": ["mandrill", "k1", "k2", "k3"],
    "sendgrid": ["s1", "s2", "smtp"],
    "mailgun": ["mx", "smtp", "k1", "mailo"],
    "amazonses": ["amazonses", "ses"],
    "zoho": ["zoho", "zmail"],
    "mailchimp": ["k1", "k2", "k3"],
    "sparkpost": ["scph0", "scph1", "sparkpost"],
    "protonmail": ["protonmail", "protonmail2", "protonmail3"],
    "messagingengine": ["fm1", "fm2", "fm3"],  # Fastmail
    "hubspot": ["hs1", "hs2", "hubspot"],
    "klaviyo": ["klaviyo"],
    "mktomail": ["m1", "mte1", "mte2"],         # Marketo
    "sparkpostmail": ["scph0", "scph1"],
    "cloudflare": ["cf2024-1", "cf2025-1"],     # Cloudflare Email Routing
    "mailerlite": ["ml", "mailerlite"],
    "campaignmonitor": ["cm"],
}


def dkim_candidates(domain):
    """Ordered selector candidates: provider-specific (from MX/SPF) first, then the
    common fallback, deduped. Lets the common case early-exit in 1-2 queries."""
    blob = (" ".join(dig(domain, "MX")) + " " + (first_txt(domain, "v=spf1") or "")).lower()
    sels = []
    for fp, slist in PROVIDER_SELECTORS.items():
        if fp in blob:
            sels += slist
    sels += DKIM_SELECTORS
    seen, out = set(), []
    for s in sels:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def dkim_lookup(domain):
    """Three-state DKIM result: ('good'|'weak'|'unknown', note, testing).
    good = key found (Ed25519 / RSA>=2048); weak = RSA-1024 (real gap);
    unknown = no key at any probed selector (a discovery blind spot, NOT a
    confirmed gap). testing = the surfaced key carries t=y (testing mode).
    Early-exits on a good key."""
    weak = None
    weak_testing = False
    for sel in dkim_candidates(domain):
        rec = first_txt(f"{sel}._domainkey.{domain}", "v=dkim1")
        if not rec:
            rec = next((r for r in dig(f"{sel}._domainkey.{domain}", "TXT") if "p=" in r), None)
        if rec:
            ktype, pub, bits, testing = parse_dkim(rec)
            if ktype == "rsa" and bits == 1024:
                weak = weak or f"DKIM {sel}=RSA-1024"
                weak_testing = weak_testing or testing
                continue  # keep looking for a stronger key before concluding
            label = ktype.upper() + (f"-{bits}" if bits else "")
            return ("good", f"DKIM {sel} ({label})", testing)
    return ("weak", weak, weak_testing) if weak else ("unknown", "no DKIM key at common/provider selectors", False)


@lru_cache(maxsize=8192)
def dig(name, rrtype):
    """Return list of answer strings for name/rrtype, or [] on failure."""
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=4", "+tries=1", rrtype, name],
            capture_output=True, text=True, timeout=TIMEOUT,
        ).stdout.strip()
    except Exception:
        return []
    rows = [r.strip() for r in out.splitlines() if r.strip()]
    # TXT answers come back quoted and may be split into 255-byte chunks.
    if rrtype == "TXT":
        joined = []
        for r in rows:
            parts = re.findall(r'"([^"]*)"', r)
            joined.append("".join(parts) if parts else r)
        return joined
    return rows


def resolves(domain):
    """True if the domain exists in DNS at all (has NS/SOA/A). Distinguishes a
    real-but-silent domain from a typo/NXDOMAIN — critical for lead scoring, where
    a non-existent domain must NOT read as a maximally-broken (high-pain) lead."""
    for rr in ("NS", "SOA", "A"):
        if dig(domain, rr):
            return True
    return False


def is_void(name):
    """A 'void' SPF lookup (RFC 7208 §4.6.4) ~ a name that resolves to nothing — a dead
    include/redirect target. Cheap proxy: void only if BOTH TXT and A are empty. TXT is
    already fetched by the recursion for include targets (memoized → free), and the A
    query only runs when TXT is empty (i.e. only on actually-dead targets), so live
    domains add ~0 queries. A live SPF include always publishes a TXT record."""
    if dig(name, "TXT"):
        return False
    return not dig(name, "A")


def first_txt(name, prefix):
    for rec in dig(name, "TXT"):
        if rec.lower().startswith(prefix.lower()):
            return rec
    return None


def org_base(host):
    """Crude registrable base = last two labels (aspmx.l.google.com -> google.com).
    Good enough to tell 'same org' from 'external' for report-destination checks."""
    labels = host.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.rstrip(".").lower()


def count_spf_lookups(domain, seen=None, depth=0):
    """SPF allows max 10 DNS-querying mechanisms (include/a/mx/ptr/exists/redirect);
    exceeding it = PermError = SPF silently fails. RFC 7208 also caps 'void' lookups
    (targets that resolve to nothing) at 2. Returns (lookups, voids), counted recursively."""
    if seen is None:
        seen = set()
    if depth > 12 or domain in seen:
        return (0, 0)
    seen.add(domain)
    spf = first_txt(domain, "v=spf1")
    if not spf:
        return (0, 0)
    n, voids = 0, 0
    for tok in spf.split():
        t = tok.lower()
        if t in ("a", "mx"):
            n += 1
            continue
        if t.startswith(("include:", "a:", "mx:", "ptr", "exists:", "redirect=")):
            n += 1
            sub = None  # only include/redirect have a sub-record to recurse + void-check
            if t.startswith("include:"):
                sub = tok.split(":", 1)[1]
            elif t.startswith("redirect="):
                sub = tok.split("=", 1)[1].rstrip(";")
            if sub:
                if is_void(sub):
                    voids += 1
                sn, sv = count_spf_lookups(sub, seen, depth + 1)
                n += sn
                voids += sv
    return (n, voids)


def spf_qualifier(spf):
    """The qualifier on the `all` mechanism. Bare `all` defaults to `+` (RFC 7208).
    Returns one of -/~/?/+ , or None if there's no `all` mechanism at all."""
    m = re.search(r"([-~?+]?)all\b", spf)
    return None if not m else (m.group(1) or "+")


def effective_terminator(domain, seen=None, depth=0):
    """The qualifier that actually applies, following redirect= to the target's SPF."""
    if seen is None:
        seen = set()
    if depth > 10 or domain in seen:
        return None
    seen.add(domain)
    spf = first_txt(domain, "v=spf1")
    if not spf:
        return None
    q = spf_qualifier(spf)
    if q is not None:
        return q
    m = re.search(r"redirect=(\S+)", spf)
    if m:
        return effective_terminator(m.group(1).rstrip(";"), seen, depth + 1)
    return None


def check_spf(domain, F):
    spf = first_txt(domain, "v=spf1")
    if not spf:
        F.append(dict(area="SPF", severity="high", title="No SPF record",
                      detail="No v=spf1 TXT record at the apex. Receivers can't verify which hosts may send for this domain; alignment-based DMARC pass via SPF is impossible.",
                      fix='Add a TXT record at the apex: "v=spf1 include:<your-ESP> -all" (replace include with your sending providers; end with -all once confident).'))
        return
    q = effective_terminator(domain)  # -/~/?/+ or None
    if q is None:
        F.append(dict(area="SPF", severity="medium", title="SPF has no `all` mechanism",
                      detail="Without a terminating all qualifier, SPF gives receivers no default disposition.",
                      fix='End the SPF record with -all (hard fail) or at least ~all (soft fail).'))
    elif q in ("+", "?"):
        F.append(dict(area="SPF", severity="high", title=f"SPF terminates in `{q}all` (permissive)",
                      detail=f"`{q}all` makes no fail assertion — anything not listed is treated as pass/neutral, so SPF gives effectively no protection against spoofing (`+all` literally authorizes any host).",
                      fix="Change the terminating qualifier to -all (or ~all while testing)."))
    n, voids = count_spf_lookups(domain)
    if n > 10:
        F.append(dict(area="SPF", severity="high", title=f"SPF exceeds 10 DNS lookups ({n})",
                      detail="Over 10 DNS-querying mechanisms triggers a PermError and SPF silently fails at many receivers — a classic invisible deliverability drain.",
                      fix="Flatten or consolidate includes; remove unused senders. Target <=8 to leave headroom."))
    if voids > 2:
        F.append(dict(area="SPF", severity="high", title=f"SPF exceeds the void-lookup limit ({voids})",
                      detail="More than 2 SPF mechanisms point at names that resolve to nothing (RFC 7208 caps 'void' lookups at 2). This trips a PermError and SPF silently fails — usually a dead/retired include nobody removed.",
                      fix="Find and remove the dead include/redirect/a/mx targets (the ones that no longer resolve)."))
    # ptr is deprecated (RFC 7208 §5.5) — slow and discouraged.
    if re.search(r"(?:^|\s)[-~?+]?ptr\b", spf.lower()):
        F.append(dict(area="SPF", severity="low", title="SPF uses the deprecated `ptr` mechanism",
                      detail="The ptr mechanism is slow, unreliable, and explicitly discouraged by RFC 7208 §5.5; some receivers ignore it entirely.",
                      fix="Remove ptr and authorize senders via include:/a/mx/ip4/ip6 instead."))
    # duplicate include — wastes lookups, sign of copy-paste drift.
    incs = re.findall(r"include:(\S+)", spf.lower())
    dupes = {i for i in incs if incs.count(i) > 1}
    if dupes:
        F.append(dict(area="SPF", severity="low", title="SPF has duplicate include(s)",
                      detail=f"The record repeats include(s): {', '.join(sorted(dupes))}. Each duplicate still burns one of the 10 DNS lookups for no benefit.",
                      fix="Remove the repeated include entries."))
    F.append(dict(area="SPF", severity="pass", title="SPF present",
                  detail=f"Record found; effective terminator: {q}all; ~{n} DNS lookups, {voids} void.",
                  fix=None, record=spf))


def parse_dkim(rec):
    """Returns (ktype, pub, bits, testing). testing = t=y flag (key not enforced)."""
    kv = dict(re.findall(r"(\w+)=([^;]+)", rec))
    ktype = kv.get("k", "rsa").strip().lower()
    pub = kv.get("p", "").strip()
    flags = kv.get("t", "").strip().lower()
    testing = "y" in [x.strip() for x in flags.split(":")] if flags else False
    bits = None
    if ktype == "rsa" and pub:
        # crude DER length -> approx modulus size estimate from base64 length
        approx_bytes = len(pub) * 3 // 4
        bits = 1024 if approx_bytes < 200 else (2048 if approx_bytes < 400 else 4096)
    return ktype, pub, bits, testing


def check_dkim(domain, F):
    state, note, testing = dkim_lookup(domain)
    if state == "good":
        F.append(dict(area="DKIM", severity="pass", title=f"DKIM present ({note})",
                      detail="A modern DKIM key was found at a probed selector.", fix=None))
    elif state == "weak":
        F.append(dict(area="DKIM", severity="high", title="DKIM key is RSA-1024 (legacy)",
                      detail="RSA-1024 is below current strength guidance and is being phased out; some receivers discount it, and it's the first thing a PQC/crypto-hygiene review flags.",
                      fix="Rotate the selector to RSA-2048 (or Ed25519): publish the new key, let it propagate, then switch signing over.", record=note))
    else:  # unknown — a blind spot, NOT a confirmed gap
        F.append(dict(area="DKIM", severity="low", title="DKIM not found at common/provider selectors",
                      detail="No DKIM key at the selectors probed. DKIM has no discovery mechanism, so this is a blind spot — the domain may well sign with a custom selector. Verify against actual message headers before concluding DKIM is absent; don't treat this as a confirmed gap.",
                      fix="Confirm the selector with the sending provider; if genuinely unsigned, enable DKIM at the ESP."))
    if testing:
        F.append(dict(area="DKIM", severity="low", title="DKIM key is in testing mode (t=y)",
                      detail="The surfaced DKIM key carries the t=y testing flag, which tells receivers to treat the signature as experimental and NOT act on failures — so DKIM gives no real protection while it's set. Usually left over from initial setup.",
                      fix="Remove the t=y flag from the DKIM TXT record once you've confirmed signing works."))


def check_dmarc(domain, F):
    rec = first_txt(f"_dmarc.{domain}", "v=dmarc1")
    if not rec:
        F.append(dict(area="DMARC", severity="critical", title="No DMARC record",
                      detail="No policy at _dmarc. Receivers have no instruction on how to handle unauthenticated mail in your name — and as of 2024-25, Gmail/Yahoo/Microsoft require DMARC for bulk senders. This is both a spoofing exposure and a hard deliverability blocker.",
                      fix='Publish TXT at _dmarc: start with "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" to collect reports, then ramp to p=quarantine and p=reject.'))
        return
    kv = dict(re.findall(r"(\w+)=\s*([^;]+)", rec))
    p = kv.get("p", "none").strip().lower()
    sp = kv.get("sp", "").strip().lower()
    np_ = kv.get("np", "").strip().lower()
    rua = "rua" in kv
    if p == "none":
        F.append(dict(area="DMARC", severity="high", title="DMARC policy is p=none (monitor only)",
                      detail="p=none means spoofed mail is still delivered. It's a valid starting point but offers no protection at rest; mailbox providers increasingly treat enforced policies as a trust signal.",
                      fix="After reviewing aggregate reports, ramp to p=quarantine then p=reject (optionally with pct= staging)."))
    else:
        F.append(dict(area="DMARC", severity="pass", title=f"DMARC enforced (p={p})",
                      detail="Enforcement policy in place.", fix=None, record=rec))
        # Enforced at the org domain but subdomains left open (sp=none) — the parked /
        # cousin-subdomain spoofing vector. sp defaults to p when absent, so only flag
        # an explicit sp=none.
        if sp == "none":
            F.append(dict(area="DMARC", severity="medium", title="DMARC subdomain policy not enforced (sp=none)",
                          detail="The org domain is enforced but sp=none leaves every subdomain unprotected — attackers spoof random.<domain> and DMARC won't stop it. A common gap on domains with one strong apex policy.",
                          fix="Set sp=reject (or sp=quarantine) so the enforcement also covers subdomains."))
    # Partial enforcement via pct (pct is removed in DMARCbis / RFC 9989, and <100 = probabilistic).
    pct = kv.get("pct", "").strip()
    if pct and pct.isdigit() and int(pct) < 100:
        F.append(dict(area="DMARC", severity="medium", title=f"DMARC only partially enforced (pct={pct})",
                      detail=f"pct={pct} applies the policy to only {pct}% of failing mail — the rest is let through, so enforcement is probabilistic. (Note: pct is also removed in DMARCbis / RFC 9989.)",
                      fix="Once confident, remove pct (or set pct=100) so the policy applies to all failing mail."))
    # Tags removed in DMARCbis / RFC 9989.
    removed = [t for t in ("rf", "ri", "pct") if t in kv]
    if removed:
        F.append(dict(area="DMARC", severity="low", title="DMARC uses tags removed in RFC 9989 (DMARCbis)",
                      detail=f"The record uses {', '.join(removed)}, which DMARCbis (RFC 9989, published May 2026, obsoletes RFC 7489) removes. They're still tolerated today but are no longer part of the spec; np= is the new tag for non-existent subdomains.",
                      fix="Drop rf/ri/pct on your next edit; add np=reject to cover non-existent subdomains per RFC 9989."))
    if not rua:
        F.append(dict(area="DMARC", severity="medium", title="DMARC has no rua (no aggregate reporting)",
                      detail="Without rua you're blind to who's sending as you and to auth failures — you lose the early-warning signal a deliverability owner relies on.",
                      fix="Add rua=mailto:dmarc@<domain> to receive daily aggregate XML reports."))
    else:
        # External report-destination authorization (RFC 7489 §7.1 / RFC 9989): if a
        # rua/ruf address is at a DIFFERENT org domain, that domain must publish
        # {domain}._report._dmarc.{dest} or the reports are silently dropped.
        dests = re.findall(r"mailto:[^@\s;,]+@([^\s;,!]+)", rec, re.I)
        unauth = []
        for dest in {d.rstrip(".").lower() for d in dests}:
            if org_base(dest) != org_base(domain):
                auth = first_txt(f"{domain}._report._dmarc.{dest}", "v=dmarc1")
                if not auth:
                    unauth.append(dest)
        if unauth:
            F.append(dict(area="DMARC", severity="medium", title="DMARC report destination not authorized",
                          detail=f"Aggregate/forensic reports are sent to an external domain ({', '.join(sorted(unauth))}) that hasn't published the required authorization record, so most receivers will silently DROP your reports — you think you have reporting, but you don't.",
                          fix=f"Have the destination publish a TXT record at '{domain}._report._dmarc.<destination>' containing 'v=DMARC1;' (your DMARC vendor usually does this automatically)."))


def _mx_hosts(domain):
    out = []
    for r in dig(domain, "MX"):
        parts = r.split()
        if len(parts) >= 2 and parts[0].isdigit():
            out.append(parts[-1].rstrip(".").lower())
    return out


def _mx_pattern_matches(pattern, host):
    pattern = pattern.strip().rstrip(".").lower()
    host = host.rstrip(".").lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") >= pattern.count(".")
    return pattern == host


def check_mta_sts(domain, F):
    txt = first_txt(f"_mta-sts.{domain}", "v=stsv1")
    policy = None
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((f"mta-sts.{domain}", 443), SOCK_TIMEOUT)
        s = ctx.wrap_socket(conn, server_hostname=f"mta-sts.{domain}")
        req = f"GET /.well-known/mta-sts.txt HTTP/1.0\r\nHost: mta-sts.{domain}\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        s.close()
        policy = data.decode(errors="ignore")
    except Exception:
        policy = None
    if not txt:
        F.append(dict(area="MTA-STS", severity="medium", title="No MTA-STS policy",
                      detail="MTA-STS lets you require TLS for inbound SMTP and is part of a modern transport posture (and a growing compliance ask under NIS2/gov mandates). Absent it, downgrade attacks on mail-in-transit are possible.",
                      fix="Publish _mta-sts TXT (v=STSv1; id=...) and host https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: enforce."))
        return
    mode = re.search(r"mode:\s*(\w+)", policy or "")
    mode = mode.group(1).lower() if mode else "unknown"
    sev = "pass" if mode == "enforce" else "medium"
    F.append(dict(area="MTA-STS", severity=sev, title=f"MTA-STS present (mode: {mode})",
                  detail="Policy published." + ("" if mode == "enforce" else " mode is not 'enforce' — testing/none gives no real protection."),
                  fix=None if mode == "enforce" else "Move policy to mode: enforce once tested."))
    if policy:
        # max_age sanity (spec allows up to 31557600s; a missing/tiny value weakens the policy).
        ma = re.search(r"max_age:\s*(\d+)", policy)
        if not ma:
            F.append(dict(area="MTA-STS", severity="low", title="MTA-STS policy missing max_age",
                          detail="The hosted policy has no max_age, so caching behavior is undefined and the policy may not 'stick' at senders.",
                          fix="Add a max_age (e.g. max_age: 604800) to the hosted mta-sts.txt."))
        # Every real MX must be covered by an mx: line, or mail to it fails under enforce.
        pol_mx = re.findall(r"mx:\s*(\S+)", policy)
        real_mx = _mx_hosts(domain)
        if pol_mx and real_mx:
            unmatched = [h for h in real_mx if not any(_mx_pattern_matches(p, h) for p in pol_mx)]
            if unmatched:
                F.append(dict(area="MTA-STS", severity=("high" if mode == "enforce" else "medium"),
                              title="MTA-STS policy does not cover all MX hosts",
                              detail=f"These live MX hosts match no mx: line in the policy: {', '.join(unmatched)}."
                                     + (" Under mode: enforce, senders will REFUSE to deliver to them — active mail loss." if mode == "enforce" else " Once you move to enforce, mail to them will fail."),
                              fix="Add the missing MX hostnames (or a *.<domain> wildcard) to the mx: lines in the hosted policy."))


def check_simple(domain, F):
    # TLS-RPT
    tlsrpt = first_txt(f"_smtp._tls.{domain}", "v=tlsrptv1")
    if tlsrpt:
        if "rua=" not in tlsrpt.lower():
            F.append(dict(area="TLS-RPT", severity="low", title="TLS-RPT present but has no rua endpoint",
                          detail="A TLS-RPT record exists but defines no rua= destination, so no TLS failure reports are actually delivered anywhere.",
                          fix='Add a destination: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".'))
        else:
            F.append(dict(area="TLS-RPT", severity="pass", title="TLS-RPT present", detail="Receiving TLS failure reports.", fix=None))
    else:
        F.append(dict(area="TLS-RPT", severity="low", title="No TLS-RPT",
                      detail="No SMTP TLS reporting; you won't learn when senders fail to negotiate TLS to you.",
                      fix='Add _smtp._tls TXT: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".'))
    # BIMI
    bimi = first_txt(f"default._bimi.{domain}", "v=bimi1")
    if bimi:
        has_vmc = re.search(r"(?:^|;)\s*a=\s*https?://", bimi.lower())
        if not has_vmc:
            F.append(dict(area="BIMI", severity="low", title="BIMI present without a VMC",
                          detail="A BIMI record is published but has no a= (Verified Mark Certificate) URL. Gmail and Apple Mail require a VMC to actually display the logo, so without it most inboxes won't render your mark.",
                          fix="Obtain a VMC (or a CMC) and add it as a=https://<domain>/path/vmc.pem to the BIMI record."))
        else:
            F.append(dict(area="BIMI", severity="pass", title="BIMI present (with VMC)", detail="Brand indicator + VMC published.", fix=None))
    else:
        F.append(dict(area="BIMI", severity="low", title="No BIMI",
                      detail="BIMI (logo in inbox) requires p=quarantine/reject DMARC first; it's a trust/brand signal, not a blocker.",
                      fix="Once DMARC is enforced, publish default._bimi with an SVG logo (+ VMC for Gmail/Apple)."))


def check_transport(domain, F):
    mx = dig(domain, "MX")
    if not mx:
        F.append(dict(area="Transport", severity="low", title="No MX records",
                      detail="No inbound mail servers (may be intentional for a send-only/parked domain).", fix=None))
        return None
    # Null MX (RFC 7505): "0 ." positively declares the domain sends/receives no mail.
    if any(r.split()[-1].rstrip(".") == "" or r.strip() in ("0 .", "0.") for r in mx) or \
       all(r.split()[-1].rstrip(".") == "" for r in mx if r.split()):
        F.append(dict(area="Transport", severity="pass", title="Null MX (RFC 7505) — domain declares no mail",
                      detail="A null MX (0 .) correctly signals this domain neither sends nor receives mail, which helps receivers reject spoofed mail from it. Good hygiene for a non-mail domain.", fix=None))
        return None
    host = sorted(mx, key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 99)[0].split()[-1].rstrip(".")
    tls_ver = None
    try:
        conn = socket.create_connection((host, 25), SOCK_TIMEOUT)
        conn.recv(512)
        conn.sendall(b"EHLO amino-audit\r\n")
        ehlo = conn.recv(1024).decode(errors="ignore")
        if "STARTTLS" in ehlo.upper():
            conn.sendall(b"STARTTLS\r\n")
            conn.recv(512)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(conn)
            tls_ver = s.version()
            s.close()
        else:
            conn.close()
    except Exception:
        pass
    # DANE
    dane = dig(f"_25._tcp.{host}", "TLSA")
    if tls_ver:
        sev = "pass" if tls_ver == "TLSv1.3" else "low"
        F.append(dict(area="Transport", severity=sev, title=f"Inbound SMTP STARTTLS: {tls_ver}",
                      detail=f"Primary MX {host} negotiates {tls_ver}." + ("" if tls_ver == "TLSv1.3" else " TLS 1.3 is the floor for PQC-hybrid (ML-KEM) key exchange — on 1.2 you can't adopt PQC transport at all."),
                      fix=None if tls_ver == "TLSv1.3" else "Ensure the MX supports TLS 1.3 — prerequisite for any post-quantum (hybrid ML-KEM) transport readiness."))
    else:
        F.append(dict(area="Transport", severity="medium", title="Could not establish STARTTLS to primary MX",
                      detail=f"No TLS negotiated with {host}:25 (blocked port, timeout, or STARTTLS unsupported). Mail to you may travel in cleartext.",
                      fix="Verify the MX offers STARTTLS with a valid certificate."))
    if dane:
        bad = _bad_tlsa(dane)
        if bad:
            F.append(dict(area="Transport", severity="medium", title="DANE/TLSA present but misconfigured",
                          detail=f"TLSA records exist but {bad} For SMTP DANE only usage 3 (DANE-EE) or 2 (DANE-TA) are valid, and matching-type 1 (SHA-256) is recommended; an invalid record can break DANE-enforcing senders.",
                          fix="Correct the TLSA usage/selector/matching-type (typically '3 1 1' for the MX cert) and re-publish."))
        else:
            F.append(dict(area="Transport", severity="pass", title="DANE/TLSA present", detail="TLSA records bind the MX cert (requires DNSSEC).", fix=None))
    else:
        F.append(dict(area="Transport", severity="low", title="No DANE/TLSA",
                      detail="No TLSA records on the MX. DANE is an emerging transport-security ask (NIS2/BSI) and depends on DNSSEC.",
                      fix="If DNSSEC is enabled, publish TLSA records for the MX; otherwise enable DNSSEC first."))
    return host


def _bad_tlsa(rows):
    """Return a human note if any TLSA record has an SMTP-invalid usage, else ''."""
    for r in rows:
        parts = r.split()
        if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
            usage, sel, mtype = int(parts[0]), int(parts[1]), int(parts[2])
            if usage in (0, 1):
                return f"one uses usage {usage} (PKIX mode), which is inappropriate for SMTP DANE."
            if mtype == 0:
                return "one uses matching-type 0 (full cert), which is brittle across cert rotation."
    return ""


def mx_providers(domain):
    """[(priority, host, provider)] for each MX. provider = the registrable-ish base
    (last two labels) so aspmx.l.google.com and alt1.aspmx.l.google.com both -> google.com."""
    out = []
    for r in dig(domain, "MX"):
        parts = r.split()
        if len(parts) >= 2 and parts[0].isdigit():
            host = parts[-1].rstrip(".").lower()
            if not host:
                continue  # null MX
            labels = host.split(".")
            provider = ".".join(labels[-2:]) if len(labels) >= 2 else host
            out.append((int(parts[0]), host, provider))
    return out


def check_mx_hygiene(domain, F):
    """Flag MX that span MULTIPLE providers — a stale/duplicate backup MX (often a
    registrar default) can silently receive or drop inbound mail and is a relay risk.
    Worse when a secondary provider sits at a priority that can actively receive."""
    mxs = mx_providers(domain)
    providers = {}
    for prio, host, prov in mxs:
        providers.setdefault(prov, []).append(prio)
    if len(providers) <= 1:
        return
    primary = min(providers, key=lambda p: min(providers[p]))
    prim_hi = max(providers[primary])  # highest (numerically) primary priority
    risky = [p for p in providers if p != primary and min(providers[p]) <= prim_hi]
    listing = "; ".join(f"{p} (prio {','.join(map(str, sorted(v)))})" for p, v in providers.items())
    F.append(dict(area="MX", severity=("medium" if risky else "low"),
                  title=f"Mixed MX providers ({len(providers)})",
                  detail=f"Inbound MX spans multiple providers: {listing}. Senders deliver to whichever MX is reachable at the lowest priority, so a stale/duplicate backup provider can silently receive (or drop) mail and is a relay/interception surface."
                         + (f" '{risky[0]}' sits at a priority that can actively receive mail today." if risky else ""),
                  fix="Confirm every MX provider is intentional and enforces TLS; remove stale/registrar-default backup MX so all inbound flows to your primary provider."))


def priority(f):
    """(effort, value) in {low, high} for a gap finding — drives the effort×value
    improvement matrix. 'pass' findings return (None, None). Defaults are sensible
    starting points; the skill may nudge value up for regulated/compliance contexts."""
    if f.get("severity") == "pass":
        return None, None
    a, t = f["area"], f["title"].lower()
    if a == "SPF":
        if "exceeds 10" in t or "void-lookup" in t:
            return ("high", "high") if "exceeds 10" in t else ("low", "high")
        if "ptr" in t or "duplicate" in t:
            return ("low", "low")
        return ("low", "high")
    if a == "DKIM":
        return ("low", "low")           # rotate RSA-1024 / confirm selector / drop t=y — hygiene
    if a == "DMARC":
        if "p=none (monitor" in t:
            return ("high", "high")
        if "removed in rfc 9989" in t:
            return ("low", "low")
        return ("low", "high")          # publish / rua / sp=none / pct / unauthorized dest — quick wins
    if a == "MTA-STS":
        if "does not cover all mx" in t:
            return ("low", "high")      # edit the hosted policy — quick + prevents mail loss
        if "max_age" in t:
            return ("low", "low")
        return ("high", "low")
    if a == "TLS-RPT":
        return ("low", "low")
    if a == "BIMI":
        return ("high", "high")   # logo-in-inbox: brand trust + open-rate lift = high value for engagement-led senders
    if a == "MX":
        return ("low", "high")          # remove stale/duplicate MX — quick + protective
    if a == "Transport":
        return ("high", "low") if "dane" in t else ("low", "low")  # DANE vs STARTTLS-verify
    return ("low", "low")


QUADRANT = {
    ("low", "high"): "Quick wins — low effort, high value (do first)",
    ("high", "high"): "Major projects — high effort, high value (plan & resource)",
    ("low", "low"): "Fill-ins — low effort, low value (spare time)",
    ("high", "low"): "Hardening — high effort, security/compliance value (when required, e.g. NIS2 / security reviews); not a deliverability or engagement lever",
}


def action(f):
    """Canonical verb-led workflow label for a gap finding — one fix-type = one
    Amino workflow. Kept consistent across quadrants. None for 'pass' findings."""
    if f.get("severity") == "pass":
        return None
    a, t = f["area"], f["title"].lower()
    if a == "SPF":
        if "no spf" in t:
            return "Publish an SPF record"
        if "exceeds 10" in t:
            return "Flatten SPF to under 10 lookups"
        if "void-lookup" in t:
            return "Remove dead SPF includes"
        if "no `all`" in t or "no 'all'" in t:
            return "Add a terminating -all to SPF"
        if "ptr" in t:
            return "Remove the SPF ptr mechanism"
        if "duplicate" in t:
            return "Remove duplicate SPF includes"
        return "Tighten SPF to a hard -all policy"
    if a == "DKIM":
        if "rsa-1024" in t:
            return "Rotate DKIM to a 2048-bit key"
        if "testing mode" in t:
            return "Take the DKIM key out of testing (t=y)"
        return "Confirm or enable DKIM signing"
    if a == "DMARC":
        if "no dmarc" in t:
            return "Publish a DMARC policy"
        if "p=none (monitor" in t:
            return "Ramp DMARC up to p=reject"
        if "subdomain policy" in t:
            return "Set DMARC sp=reject for subdomains"
        if "partially enforced" in t:
            return "Raise DMARC pct to 100"
        if "removed in rfc 9989" in t:
            return "Drop deprecated DMARC tags; add np="
        if "report destination" in t:
            return "Authorize the external DMARC report destination"
        if "rua" in t:
            return "Turn on DMARC reporting (rua)"
        return "Strengthen the DMARC policy"
    if a == "MTA-STS":
        if "does not cover all mx" in t:
            return "Fix MTA-STS mx: entries to match your MX"
        if "max_age" in t:
            return "Set a valid MTA-STS max_age"
        return "Publish + host an MTA-STS policy"
    if a == "TLS-RPT":
        return "Add a rua endpoint to TLS-RPT" if "no rua" in t else "Add a TLS-RPT reporting record"
    if a == "BIMI":
        return "Add a VMC to your BIMI record" if "without a vmc" in t else "Get a VMC, then publish BIMI"
    if a == "MX":
        return "Consolidate to one MX provider"
    if a == "Transport":
        if "misconfigured" in t:
            return "Correct the DANE/TLSA record"
        return "Enable DNSSEC, then publish DANE/TLSA" if "dane" in t else "Confirm STARTTLS on the mail server"
    return f["title"]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: audit.py <domain>"}))
        sys.exit(1)
    domain = sys.argv[1].strip().lower().lstrip("@")
    F = []
    check_spf(domain, F)
    check_dkim(domain, F)
    check_dmarc(domain, F)
    check_mta_sts(domain, F)
    check_simple(domain, F)
    mx_host = check_transport(domain, F)
    check_mx_hygiene(domain, F)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "pass": 4}
    F.sort(key=lambda x: order.get(x["severity"], 5))
    for f in F:
        f["effort"], f["value"] = priority(f)
        if f["effort"]:
            f["quadrant"] = QUADRANT[(f["effort"], f["value"])]
            f["action"] = action(f)
    summary = {s: sum(1 for f in F if f["severity"] == s)
               for s in ["critical", "high", "medium", "low", "pass"]}
    print(json.dumps({
        "domain": domain,
        "primary_mx": mx_host,
        "summary": summary,
        "findings": F,
        "notes": "Read-only scan. DKIM is best-effort (common selectors only). "
                 "PQC transport readiness is inferred from TLS version; ML-KEM negotiation "
                 "is not directly probed by this scanner. DMARCbis = RFC 9989 (published May 2026).",
    }, indent=2))


if __name__ == "__main__":
    main()
