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
# a trimmed high-yield common list — and early-exit on the first good key. This
# turns a ~30-query sweep into ~1-2 queries for the common (Google/M365) case.
# A miss is still only "not found via common selectors", never "no DKIM".
# Full fallback list — coverage matters more than trimming here (a dropped
# selector = a missed key = a wrong "weak"/"unknown"). Efficiency instead comes
# from provider-first ordering + early-exit on a good key + memoized dig().
DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "k1", "k2", "k3",
    "mandrill", "dkim", "mail", "smtp", "s1", "s2", "sig1", "cf2024-1",
    "mxvault", "zoho", "pm", "scph0", "sendgrid", "sg", "fd", "mte1",
    "everlytickey1", "dkim1", "key1", "1", "2", "mailo",
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
    "amazonses": ["amazonses"],
    "zoho": ["zoho", "zmail"],
    "mailchimp": ["k1", "k2", "k3"],
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
    """Three-state DKIM result: ('good'|'weak'|'unknown', note).
    good = key found (Ed25519 / RSA>=2048); weak = RSA-1024 (real gap);
    unknown = no key at any probed selector (a discovery blind spot, NOT a
    confirmed gap — so callers must not score it as one). Early-exits on a good key."""
    weak = None
    for sel in dkim_candidates(domain):
        rec = first_txt(f"{sel}._domainkey.{domain}", "v=dkim1")
        if not rec:
            rec = next((r for r in dig(f"{sel}._domainkey.{domain}", "TXT") if "p=" in r), None)
        if rec:
            ktype, pub, bits = parse_dkim(rec)
            if ktype == "rsa" and bits == 1024:
                weak = weak or f"DKIM {sel}=RSA-1024"
                continue  # keep looking for a stronger key before concluding
            label = ktype.upper() + (f"-{bits}" if bits else "")
            return ("good", f"DKIM {sel} ({label})")
    return ("weak", weak) if weak else ("unknown", "no DKIM key at common/provider selectors")


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


def first_txt(name, prefix):
    for rec in dig(name, "TXT"):
        if rec.lower().startswith(prefix.lower()):
            return rec
    return None


def count_spf_lookups(domain, seen=None, depth=0):
    """SPF allows max 10 DNS-querying mechanisms (include/a/mx/ptr/exists/redirect).
    Exceeding it = PermError = SPF silently fails. Count them recursively."""
    if seen is None:
        seen = set()
    if depth > 12 or domain in seen:
        return 0
    seen.add(domain)
    spf = first_txt(domain, "v=spf1")
    if not spf:
        return 0
    n = 0
    for tok in spf.split():
        t = tok.lower()
        if t.startswith(("include:", "a:", "mx:", "ptr", "exists:", "redirect=")):
            n += 1
            if t.startswith("include:"):
                n += count_spf_lookups(tok.split(":", 1)[1], seen, depth + 1)
            elif t.startswith("redirect="):
                n += count_spf_lookups(tok.split("=", 1)[1], seen, depth + 1)
        elif t in ("a", "mx"):
            n += 1
    return n


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
    n = count_spf_lookups(domain)
    if n > 10:
        F.append(dict(area="SPF", severity="high", title=f"SPF exceeds 10 DNS lookups ({n})",
                      detail="Over 10 DNS-querying mechanisms triggers a PermError and SPF silently fails at many receivers — a classic invisible deliverability drain.",
                      fix="Flatten or consolidate includes; remove unused senders. Target <=8 to leave headroom."))
    F.append(dict(area="SPF", severity="pass", title="SPF present",
                  detail=f"Record found; effective terminator: {q}all; ~{n} DNS lookups.",
                  fix=None, record=spf))


def parse_dkim(rec):
    kv = dict(re.findall(r"(\w+)=([^;]+)", rec))
    ktype = kv.get("k", "rsa").strip().lower()
    pub = kv.get("p", "").strip()
    bits = None
    if ktype == "rsa" and pub:
        # crude DER length -> approx modulus size estimate from base64 length
        approx_bytes = len(pub) * 3 // 4
        bits = 1024 if approx_bytes < 200 else (2048 if approx_bytes < 400 else 4096)
    return ktype, pub, bits


def check_dkim(domain, F):
    state, note = dkim_lookup(domain)
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


def check_dmarc(domain, F):
    rec = first_txt(f"_dmarc.{domain}", "v=dmarc1")
    if not rec:
        F.append(dict(area="DMARC", severity="critical", title="No DMARC record",
                      detail="No policy at _dmarc. Receivers have no instruction on how to handle unauthenticated mail in your name — and as of 2024-25, Gmail/Yahoo/Microsoft require DMARC for bulk senders. This is both a spoofing exposure and a hard deliverability blocker.",
                      fix='Publish TXT at _dmarc: start with "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" to collect reports, then ramp to p=quarantine and p=reject.'))
        return
    kv = dict(re.findall(r"(\w+)=\s*([^;]+)", rec))
    p = kv.get("p", "none").strip().lower()
    rua = "rua" in kv
    if p == "none":
        F.append(dict(area="DMARC", severity="high", title="DMARC policy is p=none (monitor only)",
                      detail="p=none means spoofed mail is still delivered. It's a valid starting point but offers no protection at rest; mailbox providers increasingly treat enforced policies as a trust signal.",
                      fix="After reviewing aggregate reports, ramp to p=quarantine then p=reject (optionally with pct= staging)."))
    else:
        F.append(dict(area="DMARC", severity="pass", title=f"DMARC enforced (p={p})",
                      detail="Enforcement policy in place.", fix=None, record=rec))
    if not rua:
        F.append(dict(area="DMARC", severity="medium", title="DMARC has no rua (no aggregate reporting)",
                      detail="Without rua you're blind to who's sending as you and to auth failures — you lose the early-warning signal a deliverability owner relies on.",
                      fix="Add rua=mailto:dmarc@<domain> to receive daily aggregate XML reports."))


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
        while len(data) < 4096:
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
    mode = mode.group(1) if mode else "unknown"
    sev = "pass" if mode == "enforce" else "medium"
    F.append(dict(area="MTA-STS", severity=sev, title=f"MTA-STS present (mode: {mode})",
                  detail="Policy published." + ("" if mode == "enforce" else " mode is not 'enforce' — testing/none gives no real protection."),
                  fix=None if mode == "enforce" else "Move policy to mode: enforce once tested."))


def check_simple(domain, F):
    # TLS-RPT
    if first_txt(f"_smtp._tls.{domain}", "v=tlsrptv1"):
        F.append(dict(area="TLS-RPT", severity="pass", title="TLS-RPT present", detail="Receiving TLS failure reports.", fix=None))
    else:
        F.append(dict(area="TLS-RPT", severity="low", title="No TLS-RPT",
                      detail="No SMTP TLS reporting; you won't learn when senders fail to negotiate TLS to you.",
                      fix='Add _smtp._tls TXT: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".'))
    # BIMI
    if first_txt(f"default._bimi.{domain}", "v=bimi1"):
        F.append(dict(area="BIMI", severity="pass", title="BIMI present", detail="Brand indicator published.", fix=None))
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
        F.append(dict(area="Transport", severity="pass", title="DANE/TLSA present", detail="TLSA records bind the MX cert (requires DNSSEC).", fix=None))
    else:
        F.append(dict(area="Transport", severity="low", title="No DANE/TLSA",
                      detail="No TLSA records on the MX. DANE is an emerging transport-security ask (NIS2/BSI) and depends on DNSSEC.",
                      fix="If DNSSEC is enabled, publish TLSA records for the MX; otherwise enable DNSSEC first."))
    return host


def mx_providers(domain):
    """[(priority, host, provider)] for each MX. provider = the registrable-ish base
    (last two labels) so aspmx.l.google.com and alt1.aspmx.l.google.com both -> google.com."""
    out = []
    for r in dig(domain, "MX"):
        parts = r.split()
        if len(parts) >= 2 and parts[0].isdigit():
            host = parts[-1].rstrip(".").lower()
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
        return ("high", "high") if "exceeds 10" in t else ("low", "high")
    if a == "DKIM":
        return ("low", "low")           # rotate RSA-1024 / confirm selector — hygiene
    if a == "DMARC":
        return ("high", "high") if "p=none" in t else ("low", "high")
    if a == "MTA-STS":
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
        if "no `all`" in t or "no 'all'" in t:
            return "Add a terminating -all to SPF"
        return "Tighten SPF to a hard -all policy"
    if a == "DKIM":
        return "Rotate DKIM to a 2048-bit key" if "rsa-1024" in t else "Confirm or enable DKIM signing"
    if a == "DMARC":
        if "no dmarc" in t:
            return "Publish a DMARC policy"
        if "p=none" in t:
            return "Ramp DMARC up to p=reject"
        if "rua" in t:
            return "Turn on DMARC reporting (rua)"
        return "Strengthen the DMARC policy"
    if a == "MTA-STS":
        return "Publish + host an MTA-STS policy"
    if a == "TLS-RPT":
        return "Add a TLS-RPT reporting record"
    if a == "BIMI":
        return "Get a VMC, then publish BIMI"
    if a == "MX":
        return "Consolidate to one MX provider"
    if a == "Transport":
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
                 "is not directly probed by this scanner.",
    }, indent=2))


if __name__ == "__main__":
    main()
