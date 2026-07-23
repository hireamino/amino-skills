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
import sys
import time
import socket
import ssl
import base64
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from resolver import query as dig  # pluggable DNS (dig backend locally; DoH at the edge)
from resolver import query_fresh   # uncached re-query, for confirming critical absences

# Input is untrusted (any domain, incl. from the future public web tool). Validate it as
# a real DNS hostname before it flows into dig args / socket connects / name construction.
# Rejects whitespace, control chars, and leading '-' (dig flag/argument injection).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def safe_domain(raw):
    """Normalize + validate the input domain; return a clean hostname or None."""
    d = (raw or "").strip().strip(".").lower().lstrip("@")
    return d if d and len(d) <= 253 and DOMAIN_RE.match(d) else None


def host_public_ips(host):
    """Public IPs a host resolves to, excluding private/loopback/link-local/reserved/
    multicast ranges. SSRF guard for the socket probes: a malicious domain can point its
    MX or mta-sts host at an internal IP (e.g. 169.254.169.254, 127.0.0.1, 10.x) — we must
    never open a connection to those, especially from a server/edge context."""
    out = []
    for ip in dig(host, "A") + dig(host, "AAAA"):
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            continue
        if not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified):
            out.append(ip.strip())
    return out

SOCK_TIMEOUT = 3   # raw socket probes (STARTTLS:25, MTA-STS HTTPS) — these hit
                   # blocked ports on many networks, so fail fast rather than hang
MAX_WORKERS = 10   # bounded concurrency for the parallel DKIM sweep / check fan-out

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


def _dkim_probe(domain, sel):
    """One selector's key record (or None)."""
    rec = first_txt(f"{sel}._domainkey.{domain}", "v=dkim1")
    if not rec:
        rec = next((r for r in dig(f"{sel}._domainkey.{domain}", "TXT") if "p=" in r), None)
    return rec


def dkim_lookup(domain):
    """Three-state DKIM result: ('good'|'weak'|'unknown', note, testing).
    good = key found (Ed25519 / RSA>=2048); weak = RSA-1024 (real gap);
    unknown = no key at any probed selector (a discovery blind spot, NOT a
    confirmed gap). testing = the surfaced key carries t=y (testing mode).
    Probes candidates in small concurrent BATCHES with early-exit: a provider-matched
    domain (its real selector sits first) resolves in one batch instead of firing all
    ~50 selector probes at once. That burst is what makes a loaded resolver rate-limit /
    load-shed and return false-empty answers on co-occurring lookups (a heavy domain would
    intermittently mis-report "no MTA-STS / no SPF"). Result is identical to the old
    sequential early-exit (first good key in priority order wins)."""
    cands = dkim_candidates(domain)
    weak = None
    weak_testing = False
    invalid = None
    BATCH = 6
    for i in range(0, len(cands), BATCH):
        batch = cands[i:i + BATCH]
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(batch))) as ex:
            recs = list(ex.map(lambda s: _dkim_probe(domain, s), batch))
        for sel, rec in zip(batch, recs):
            if not rec:
                continue
            ktype, pub, bits, testing, invalid_reason = parse_dkim(rec)
            if invalid_reason is not None:
                # Revoked/malformed key here; a healthy sibling selector still wins, so
                # record it and keep scanning; surface it only if nothing better turns up.
                invalid = invalid or (f"DKIM {sel} revoked (empty p=)" if invalid_reason == "revoked"
                                      else f"DKIM {sel} malformed ({invalid_reason})")
                continue
            if ktype == "rsa" and bits == 1024:
                weak = weak or f"DKIM {sel}=RSA-1024"
                weak_testing = weak_testing or testing
                continue  # a stronger key later in priority order still wins
            label = ktype.upper() + (f"-{bits}" if bits else "")
            return ("good", f"DKIM {sel} ({label})", testing)
    if weak:
        return ("weak", weak, weak_testing)
    if invalid:
        return ("invalid", invalid, False)
    return ("unknown", "no DKIM key at common/provider selectors", False)


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


def confirm_txt(name, prefix):
    """Like first_txt, but for TRUST-CRITICAL records (SPF/DMARC/MTA-STS) where a false
    'missing' is a serious wrong answer. If the cached lookup comes back empty, re-confirm
    with a couple of cache-bypassed retries before trusting the absence — under a heavy
    concurrent fan-out a loaded/flaky resolver can return a transient empty answer that
    would otherwise surface as a phantom 'no SPF / no MTA-STS'. Adds queries ONLY when the
    record looks absent (live domains hit the fast path and add nothing)."""
    p = prefix.lower()
    hit = first_txt(name, prefix)
    if hit is not None:
        return hit
    for delay in (0.3, 0.7):
        time.sleep(delay)
        for rec in query_fresh(name, "TXT"):
            if rec.lower().startswith(p):
                return rec
    return None


# A pragmatic subset of the Public Suffix List: registry suffixes where the registrable
# domain is the last THREE labels, not two. Not exhaustive (the full PSL is a ~200 KB data
# dependency); it fixes the cases that matter for same-org checks — e.g. good.co.uk and
# evil.co.uk must read as DIFFERENT orgs, not both "co.uk".
PUBLIC_SUFFIX_2 = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp",
    "co.za", "org.za", "gov.za", "ac.za",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "ac.cn",
    "co.kr", "or.kr", "com.mx", "com.sg", "com.hk", "com.tw",
    "co.il", "com.tr", "co.id", "com.my", "co.th", "or.th",
}


def org_base(host):
    """Registrable base (eTLD+1): last two labels, or last three when the last two are a
    known multi-label public suffix — so good.co.uk and evil.co.uk read as different orgs."""
    labels = [x for x in host.rstrip(".").lower().split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    return ".".join(labels[-3:] if last_two in PUBLIC_SUFFIX_2 else labels[-2:])


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
    m = re.search(r"([-~?+]?)all\b", spf, re.I)  # qualifiers are case-insensitive: -ALL == -all
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
    spf_records = [r for r in dig(domain, "TXT") if r.lower().startswith("v=spf1")]
    if len(spf_records) > 1:
        F.append(dict(area="SPF", severity="high", title="Multiple SPF records (invalid)",
                      detail=f"{len(spf_records)} v=spf1 records are published at the apex. RFC 7208 allows only one — receivers treat multiple as a PermError, so SPF fails entirely.",
                      fix="Merge them into a single v=spf1 record."))
    spf = confirm_txt(domain, "v=spf1")
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
    """Returns (ktype, pub, bits, testing, invalid).
    invalid is None when the key is usable, else a reason string:
      'revoked'           -> empty p= (RFC 6376 §3.6.1): a revoked selector, never healthy
      'malformed-ed25519' -> Ed25519 p= that doesn't decode to exactly 32 bytes
    testing = t=y flag (key not enforced)."""
    kv = {k.lower(): v for k, v in re.findall(r"(\w+)=([^;]+)", rec)}
    ktype = kv.get("k", "rsa").strip().lower()
    pub = kv.get("p", "").strip()
    flags = kv.get("t", "").strip().lower()
    testing = "y" in [x.strip() for x in flags.split(":")] if flags else False
    if pub == "":
        return ktype, pub, None, testing, "revoked"
    bits, invalid = None, None
    if ktype == "rsa":
        # crude DER length -> approx modulus size estimate from base64 length
        approx_bytes = len(pub) * 3 // 4
        bits = 1024 if approx_bytes < 200 else (2048 if approx_bytes < 400 else 4096)
    elif ktype == "ed25519":
        # Ed25519 public keys are exactly 32 bytes; anything else is malformed.
        try:
            if len(base64.b64decode(pub + "===", validate=False)) != 32:
                invalid = "malformed-ed25519"
        except Exception:
            invalid = "malformed-ed25519"
    return ktype, pub, bits, testing, invalid


def check_dkim(domain, F):
    state, note, testing = dkim_lookup(domain)
    if state == "good":
        F.append(dict(area="DKIM", severity="pass", title=f"DKIM present ({note})",
                      detail="A modern DKIM key was found at a probed selector.", fix=None))
    elif state == "weak":
        F.append(dict(area="DKIM", severity="high", title="DKIM key is RSA-1024 (legacy)",
                      detail="RSA-1024 is below current strength guidance and is being phased out; some receivers discount it, and it's the first thing a PQC/crypto-hygiene review flags.",
                      fix="Rotate the selector to RSA-2048 (or Ed25519): publish the new key, let it propagate, then switch signing over.", record=note))
    elif state == "invalid":
        F.append(dict(area="DKIM", severity="high", title="DKIM key is revoked or malformed",
                      detail=f"A DKIM record is published but the key is unusable ({note}). A revoked (empty p=) or malformed key can't verify signatures — receivers treat the mail as unsigned, so DKIM gives no protection.",
                      fix="Publish a valid key at this selector (RSA >=2048 or Ed25519), or remove the dead record and sign from a live selector.", record=note))
    else:  # unknown — a blind spot, NOT a confirmed gap
        F.append(dict(area="DKIM", severity="low", title="DKIM not found at common/provider selectors",
                      detail="No DKIM key at the selectors probed. DKIM has no discovery mechanism, so this is a blind spot — the domain may well sign with a custom selector. Verify against actual message headers before concluding DKIM is absent; don't treat this as a confirmed gap.",
                      fix="Confirm the selector with the sending provider; if genuinely unsigned, enable DKIM at the ESP."))
    if testing:
        F.append(dict(area="DKIM", severity="low", title="DKIM key is in testing mode (t=y)",
                      detail="The surfaced DKIM key carries the t=y testing flag, which tells receivers to treat the signature as experimental and NOT act on failures — so DKIM gives no real protection while it's set. Usually left over from initial setup.",
                      fix="Remove the t=y flag from the DKIM TXT record once you've confirmed signing works."))


def discover_dmarc(domain):
    """RFC 9989 (DMARCbis) tree walk: the applicable DMARC record is the domain's own
    _dmarc if present, otherwise the nearest ancestor's, walking up to the organizational
    domain (bounded to 5 lookups). Returns (rec, source, inherited)."""
    domain = domain.rstrip(".").lower()
    own = confirm_txt(f"_dmarc.{domain}", "v=dmarc1")
    if own:
        return own, domain, False
    base = org_base(domain)
    labels = domain.split(".")
    for i in range(1, min(len(labels) - 1, 6)):
        parent = ".".join(labels[i:])
        rec = confirm_txt(f"_dmarc.{parent}", "v=dmarc1")
        if rec:
            return rec, parent, True
        if parent == base:
            break
    return None, None, False


def check_dmarc(domain, F):
    rec, source, inherited = discover_dmarc(domain)
    if not rec:
        F.append(dict(area="DMARC", severity="critical", title="No DMARC record",
                      detail="No policy at _dmarc. Receivers have no instruction on how to handle unauthenticated mail in your name — and as of 2024-25, Gmail/Yahoo/Microsoft require DMARC for bulk senders. This is both a spoofing exposure and a hard deliverability blocker.",
                      fix='Publish TXT at _dmarc: start with "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" to collect reports, then ramp to p=quarantine and p=reject.'))
        return
    kv = {k.lower(): v for k, v in re.findall(r"(\w+)=\s*([^;]+)", rec)}
    p = kv.get("p", "").strip().lower()
    sp = kv.get("sp", "").strip().lower()
    np_ = kv.get("np", "").strip().lower()

    if inherited:
        # No _dmarc at this subdomain: it inherits the org domain's policy — the sp
        # (subdomain policy) tag if set, otherwise p (RFC 9989 tree walk).
        eff = sp or p
        tag = "sp" if sp else "p"
        if eff not in ("quarantine", "reject"):
            F.append(dict(area="DMARC", severity="high",
                          title=f"DMARC subdomain not enforced (inherited {tag}={eff or '<missing>'} from {source})",
                          detail=f"This subdomain has no _dmarc record; it inherits {source}'s policy, which resolves to {eff or '<missing>'} — spoofed mail from this subdomain isn't stopped.",
                          fix=f"Publish _dmarc.{domain} with p=reject, or set sp=reject on {source}."))
        else:
            F.append(dict(area="DMARC", severity="pass",
                          title=f"DMARC enforced (inherited {tag}={eff} from {source})",
                          detail=f"This subdomain has no record of its own and is covered by {source}'s enforced policy.", fix=None, record=rec))
        return

    dmarc_records = [r for r in dig(f"_dmarc.{source}", "TXT") if r.lower().startswith("v=dmarc1")]
    if len(dmarc_records) > 1:
        F.append(dict(area="DMARC", severity="high", title="Multiple DMARC records (invalid)",
                      detail=f"{len(dmarc_records)} DMARC records exist at _dmarc. Exactly one is allowed — receivers ignore the policy entirely when there are several, so you effectively have no DMARC.",
                      fix="Keep one DMARC record and remove the rest."))
    rua = "rua" in kv
    if p not in ("none", "quarantine", "reject"):
        F.append(dict(area="DMARC", severity="high", title=f"DMARC policy value is invalid (p={p or '<missing>'})",
                      detail="The p= tag must be exactly none, quarantine, or reject (RFC 9989). An unrecognized or missing value means receivers apply no enforcement — you have a DMARC record but no effective policy.",
                      fix="Set p= to none (monitor), quarantine, or reject."))
    elif p == "none":
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
        # RFC 8461 §4.1: a wildcard matches exactly ONE leftmost label — *.example.com
        # matches mx.example.com but NOT a.b.example.com or example.com itself.
        suffix = pattern[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[:-len(suffix)]
        return bool(left) and "." not in left
    return pattern == host


def check_mta_sts(domain, F):
    txt = confirm_txt(f"_mta-sts.{domain}", "v=stsv1")
    policy = None
    mhost = f"mta-sts.{domain}"
    try:
        ips = host_public_ips(mhost)
        if not ips:
            raise OSError("mta-sts host does not resolve to a public IP")  # SSRF guard
        ctx = ssl.create_default_context()
        conn = socket.create_connection((ips[0], 443), SOCK_TIMEOUT)  # connect to the vetted IP
        s = ctx.wrap_socket(conn, server_hostname=mhost)  # SNI/cert validated against the hostname
        req = f"GET /.well-known/mta-sts.txt HTTP/1.0\r\nHost: {mhost}\r\n\r\n"
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
        ips = host_public_ips(host)
        if not ips:
            raise OSError("MX does not resolve to a public IP")  # SSRF guard
        conn = socket.create_connection((ips[0], 25), SOCK_TIMEOUT)  # connect to the vetted IP
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


# ── SSRF-guarded HTTPS GET (for RDAP + robots.txt) ───────────────────────────
# The skill runs on the operator's OWN machine, which (unlike the CF edge) CAN reach
# localhost / RFC1918 — so every fetch resolves its host to a vetted PUBLIC IP first
# (host_public_ips) and connects to that IP with the cert validated against the
# hostname. Redirects are NOT followed by default (follow=0) because the host can be
# attacker-controlled (e.g. robots.txt on a hostile domain); when followed (RDAP's
# rdap.org bootstrap), each hop is re-validated through the same guard.

def _http_get(host, path, follow=0, cap=65536):
    """Return (status:int|None, body:str). Read-only, body-capped, short timeout,
    fail-closed (returns (None, None)) on any error or a non-public host."""
    host_header = host
    hops = 0
    while True:
        ips = host_public_ips(host)
        if not ips:
            return None, None  # SSRF guard: refuse private/loopback/link-local/reserved
        try:
            ctx = ssl.create_default_context()
            conn = socket.create_connection((ips[0], 443), SOCK_TIMEOUT)
            s = ctx.wrap_socket(conn, server_hostname=host)  # cert validated vs hostname
            s.sendall((f"GET {path} HTTP/1.0\r\nHost: {host_header}\r\n"
                       "User-Agent: amino-audit\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
            raw = b""
            while len(raw) < cap:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
            s.close()
        except Exception:
            return None, None
        head, _, body = raw.decode("utf-8", errors="ignore").partition("\r\n\r\n")
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head)
        status = int(m.group(1)) if m else None
        if status in (301, 302, 303, 307, 308) and hops < follow:
            loc = re.search(r"\n[Ll]ocation:\s*(\S+)", head)
            mu = re.match(r"https://([^/:]+)(?::\d+)?(/\S*)?$", loc.group(1)) if loc else None
            if not mu:
                return status, body
            host = host_header = mu.group(1).lower()
            path = mu.group(2) or "/"
            hops += 1
            continue
        return status, body


def _parse_iso8601(s):
    s = re.sub(r"\.(\d{6})\d+", r".\1", s.strip())  # trim sub-microsecond precision
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ── DNSSEC ───────────────────────────────────────────────────────────────────

def check_dnssec(domain, F):
    if dig(domain, "DNSKEY"):
        F.append(dict(area="DNSSEC", severity="pass", title="DNSSEC enabled",
                      detail="The zone is DNSSEC-signed.", fix=None))
    else:
        F.append(dict(area="DNSSEC", severity="low", title="DNSSEC not enabled",
                      detail="The zone publishes no DNSKEY, so DNS answers for this domain aren't cryptographically signed — and DANE can't be used without it. A trust/security gap more than a deliverability one.",
                      fix="Enable DNSSEC at your DNS provider (it's also the prerequisite for DANE)."))


# ── Domain age / expiry via RDAP (modern WHOIS over HTTPS/JSON) ──────────────

def check_domain_age(domain, F):
    """rdap.org is the IANA bootstrap redirector → it 30x's to the authoritative RDAP
    server for the TLD, so we follow (each hop re-validated through the SSRF guard).
    Fail-open: no RDAP for the TLD / any error → no finding."""
    status, body = _http_get("rdap.org", "/domain/" + domain, follow=3, cap=131072)
    if status != 200 or not body:
        return
    try:
        data = json.loads(body)
    except Exception:
        return
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return
    now = time.time()
    for ev in events:
        if not isinstance(ev, dict) or not ev.get("eventDate"):
            continue
        try:
            ts = _parse_iso8601(ev["eventDate"])
        except Exception:
            continue
        if ev.get("eventAction") == "registration":
            age = int((now - ts) // 86400)
            if 0 <= age < 90:
                F.append(dict(area="Reputation", severity="medium", title=f"Domain is newly registered ({age} days)",
                              detail="Brand-new domains have no sending reputation, so mailbox providers throttle them. Sending cold or at volume now risks the spam folder.",
                              fix="Warm up gradually — start low-volume to engaged recipients and ramp over weeks before scaling."))
        elif ev.get("eventAction") == "expiration":
            left = int((ts - now) // 86400)
            if 0 <= left < 30:
                F.append(dict(area="Reputation", severity="high", title=f"Domain expires in {left} days",
                              detail="If the registration lapses, mail and the website stop entirely — a full outage, and a reputation reset once recovered.",
                              fix="Renew the domain now and turn on auto-renew."))


# ── AI-bot readiness — light (one robots.txt fetch, no redirect-follow) ──────

AI_BOTS = ["GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web",
           "PerplexityBot", "Google-Extended", "CCBot", "Applebot-Extended"]


def _robots_blocks_ai_bots(txt):
    lines = [re.sub(r"#.*", "", ln).strip() for ln in txt.splitlines()]
    lines = [ln for ln in lines if ln]
    groups, cur, expect_agent = [], None, False
    for ln in lines:
        ua = re.match(r"user-agent:\s*(.+)$", ln, re.I)
        if ua:
            if not expect_agent:
                cur = {"agents": [], "rules": []}
                groups.append(cur)
            cur["agents"].append(ua.group(1).strip().lower())
            expect_agent = True
            continue
        rule = re.match(r"(dis)?allow:\s*(.*)$", ln, re.I)
        if rule and cur is not None:
            cur["rules"].append({"allow": not rule.group(1), "path": rule.group(2).strip()})
            expect_agent = False

    def root_blocked(gs):
        dis = allow_root = False
        for g in gs:
            for r in g["rules"]:
                if r["path"] == "/":
                    if r["allow"]:
                        allow_root = True
                    else:
                        dis = True
        return dis and not allow_root

    blocked = []
    for bot in AI_BOTS:
        ua = bot.lower()
        exact = [g for g in groups if ua in g["agents"]]
        gs = exact if exact else [g for g in groups if "*" in g["agents"]]
        if root_blocked(gs):
            blocked.append(bot)
    return blocked


def check_ai_bots(domain, F):
    status, body = _http_get(domain, "/robots.txt", follow=0, cap=20000)
    if status != 200 or not body:
        return  # no robots / unreadable / redirect → nothing is blocked → no finding
    blocked = _robots_blocks_ai_bots(body)
    if blocked:
        more = ", and others" if len(blocked) > 4 else ""
        F.append(dict(area="AI visibility", severity="low", title="robots.txt blocks AI crawlers",
                      detail=f"robots.txt disallows {', '.join(blocked[:4])}{more}. As people increasingly ask AI engines (ChatGPT, Perplexity, Google AI) about vendors, blocking these crawlers makes your site invisible to those answers.",
                      fix="Allow the AI crawlers you want in robots.txt (or drop the blanket Disallow)."))


# ── Reverse DNS / FCrDNS on the primary MX ───────────────────────────────────

def _primary_mx(domain):
    mx = dig(domain, "MX")
    if not mx:
        return None
    if any(r.split()[-1].rstrip(".") == "" for r in mx if r.split()):
        return None  # null MX
    return sorted(mx, key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 99)[0].split()[-1].rstrip(".")


def _reverse_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def check_reverse_dns(domain, F):
    host = _primary_mx(domain)
    if not host:
        return
    ips = [ip.strip() for ip in dig(host, "A") if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip.strip())]
    if not ips:
        return
    ip = ips[0]
    ptr = dig(_reverse_name(ip), "PTR")
    if not ptr:
        F.append(dict(area="Transport", severity="low", title="Mail server has no reverse DNS (PTR)",
                      detail=f"The primary MX ({host}, {ip}) has no PTR record. Receivers check reverse DNS on connecting mail servers, so a missing PTR hurts deliverability for self-hosted / own-IP senders (managed providers like Google and Microsoft set this for you).",
                      fix="Have your host set a PTR (reverse DNS) record for the mail server's IP that matches its hostname."))
        return
    ptr_name = ptr[0].rstrip(".")
    if ip not in dig(ptr_name, "A"):
        F.append(dict(area="Transport", severity="low", title="Mail server reverse DNS isn't forward-confirmed",
                      detail=f"The MX IP {ip} has a PTR ({ptr_name}) but that name doesn't resolve back to the same IP — no forward-confirmed reverse DNS (FCrDNS). Some receivers read this as a spam signal.",
                      fix="Align the PTR hostname and its A record so reverse and forward DNS agree."))


# ── CAA — which CAs may issue TLS certs (protects the MTA-STS/DANE cert chain) ─

def check_caa(domain, F):
    if not dig(domain, "CAA"):
        F.append(dict(area="CAA", severity="low", title="No CAA records",
                      detail="No CAA record restricts which certificate authorities can issue TLS certificates for your domain. CAA narrows cert mis-issuance — and the certs your MTA-STS and DANE rely on are part of your email trust chain.",
                      fix='Publish a CAA record naming your CA(s), e.g. 0 issue "letsencrypt.org".'))


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
        return ("high", "low") if "dane" in t else ("low", "low")  # DANE vs STARTTLS / reverse-DNS
    if a == "DNSSEC":
        return ("high", "low")          # security/trust, not a deliverability lever -> Hardening
    if a == "Reputation":
        return ("low", "high")          # warm-up / renew -> Quick win
    if a == "AI visibility":
        return ("low", "high")          # unblock AI crawlers -> Quick win
    if a == "CAA":
        return ("low", "low")           # cert-issuance hygiene -> Fill-in
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
        if "multiple spf" in t:
            return "Merge to a single SPF record"
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
        if "multiple dmarc" in t:
            return "Merge to a single DMARC record"
        if "p=none (monitor" in t:
            return "Ramp DMARC up to p=reject"
        if "subdomain policy" in t:
            return "Set DMARC sp=reject for subdomains"
        if "partially enforced" in t:
            return "Raise DMARC pct to 100"
        if "removed in rfc 9989" in t:
            return "Modernize DMARC tags for RFC 9989"
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
        return "Publish an MTA-STS policy"
    if a == "TLS-RPT":
        return "Add a rua endpoint to TLS-RPT" if "no rua" in t else "Add a TLS-RPT record"
    if a == "BIMI":
        return "Add a VMC to your BIMI record" if "without a vmc" in t else "Get a VMC, then publish BIMI"
    if a == "MX":
        return "Consolidate to one MX provider"
    if a == "Transport":
        if "misconfigured" in t:
            return "Correct the DANE/TLSA record"
        if "no reverse dns" in t or "has no reverse" in t:
            return "Set reverse DNS (PTR) for your mail server"
        if "forward-confirmed" in t:
            return "Fix forward-confirmed reverse DNS (FCrDNS)"
        return "Publish DANE/TLSA records" if "dane" in t else "Confirm STARTTLS on the mail server"
    if a == "CAA":
        return "Add a CAA record"
    if a == "DNSSEC":
        return "Enable DNSSEC"
    if a == "Reputation":
        return "Renew the domain before it lapses" if "expires" in t else "Warm up the domain before scaling sends"
    if a == "AI visibility":
        return "Unblock AI crawlers in robots.txt"
    return f["title"]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: audit.py <domain>"}))
        sys.exit(1)
    domain = safe_domain(sys.argv[1])
    if not domain:
        print(json.dumps({"error": "invalid domain — provide a hostname like example.com"}))
        sys.exit(1)
    # Two phases. PHASE 1 = the pure-DNS checks (incl. the parallel DKIM selector sweep)
    # run concurrently and fully drain. PHASE 2 = the checks that open sockets (STARTTLS:25,
    # the MTA-STS/RDAP/robots HTTPS fetches). Why split: concurrent socket connects interfere
    # with the `dig` SUBPROCESSES under a heavy DNS burst and make some lookups return a
    # transient false-empty (a phantom "no MTA-STS / no SPF"). Keeping the socket I/O from
    # overlapping the DNS fan-out removes that whole class of flake; within each phase the
    # checks still run in parallel. (confirm_txt is the second line of defense for the
    # trust-critical records.) Each check writes its own list → deterministic reassembly.
    dns_checks = [
        ("spf", check_spf), ("dkim", check_dkim), ("dmarc", check_dmarc),
        ("simple", check_simple), ("mx", check_mx_hygiene),
        ("dnssec", check_dnssec), ("rdns", check_reverse_dns), ("caa", check_caa),
    ]
    socket_checks = [
        ("mta_sts", check_mta_sts), ("transport", check_transport),
        ("reputation", check_domain_age), ("aibots", check_ai_bots),
    ]

    def _run(item):
        _key, fn = item
        local = []
        ret = fn(domain, local)
        return _key, local, ret

    buckets, mx_host = {}, None
    # Phase 1: pure-DNS checks in parallel (no sockets → digs don't corrupt each other).
    with ThreadPoolExecutor(max_workers=len(dns_checks)) as ex:
        for key, local, ret in ex.map(_run, dns_checks):
            buckets[key] = local
    # Phase 2: socket-probing checks run ONE AT A TIME. Each does its own DNS then its
    # socket; running them serially means no check's socket connect overlaps another check's
    # `dig`, which is the interference that produced phantom false-empties. Costs a little
    # latency (the probes no longer overlap) in exchange for correct results.
    for key, local, ret in map(_run, socket_checks):
        buckets[key] = local
        if key == "transport":
            mx_host = ret

    F = []
    for key, _ in dns_checks + socket_checks:
        F.extend(buckets[key])

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
