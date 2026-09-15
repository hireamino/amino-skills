#!/usr/bin/env python3
"""
Pluggable DNS resolver for the audit.

One query contract — `query(name, rrtype) -> list[str]` — behind a swappable backend:

- Default backend shells out to `dig` (works locally and in sandboxes where outbound
  HTTPS from Python is blocked; DNS over :53 is fine).
- The web tool runs at the edge (e.g. a Cloudflare Pages Function) where you can't spawn
  `dig` — it injects a DoH backend via `set_backend()`. Same contract, so audit.py reuses
  every check unchanged on both surfaces.

Results are memoized, so the concurrent checks in audit.py dedupe overlapping lookups for
free. TXT answers are de-chunked (255-byte segments) and unquoted here, in one place.
"""

import re
import time
import threading
import subprocess
from functools import lru_cache

DNS_TIMEOUT = 8  # seconds, per dig invocation

# Bound concurrent `dig` subprocesses. audit.py fans out ~12 checks, several of which
# spawn their own lookups (plus the ~50-selector DKIM sweep). Under that burst a local
# stub resolver starts returning SERVFAIL/REFUSED — a FAST empty answer that +tries won't
# retry (it's not a timeout), which `lru_cache` then memoizes, surfacing as a false
# "no SPF / no MTA-STS". So: a semaphore caps the in-flight queries, AND the backend reads
# dig's rcode and retries the transient failures (SERVFAIL/REFUSED/timeout) while trusting
# a real NOERROR/NXDOMAIN empty. (No effect on the DoH edge backend, which bypasses this.)
_DIG_SEM = threading.BoundedSemaphore(4)
_STATUS_CODES = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMP": 4,
    "REFUSED": 5,
    "YXDOMAIN": 6,
    "YXRRSET": 7,
    "NXRRSET": 8,
    "NOTAUTH": 9,
    "NOTZONE": 10,
}
_AUTHORITATIVE = {0, 3}  # only NOERROR and NXDOMAIN establish presence/absence
_TRANSIENT = {2, 5, None}  # rcodes worth a retry (None = no status seen)

# DNSSEC/rcode meta side-channel:
# (name, rrtype) -> {"status": int|None, "ad": bool, "error": bool}.
# Populated by the dig backend (+dnssec, parses the header AD flag) or record_meta() for
# alternate backends. Read via meta(); the DANE/DNSSEC/reliability checks use it, and the
# plain query() contract stays list[str] so every other check is unchanged.
_META = {}
_META_LOCK = threading.Lock()


def meta(name, rrtype):
    """DNSSEC/rcode meta for the last lookup, including terminal lookup failure."""
    with _META_LOCK:
        return dict(_META.get((name, rrtype), {}))


def normalize_status(status):
    """Normalize dig names and DoH/fixture numbers to one DNS RCODE representation."""
    if status is None:
        return None
    if isinstance(status, int) and not isinstance(status, bool):
        return status
    if isinstance(status, str):
        value = status.strip().upper()
        if value in _STATUS_CODES:
            return _STATUS_CODES[value]
        if value.isdigit():
            return int(value)
    return None


def normalized_meta(status, ad=False, error=False):
    """Return the shared metadata shape used by dig, DoH, and fixture backends."""
    code = normalize_status(status)
    return {
        "status": code,
        "ad": bool(ad),
        "error": bool(error or code not in _AUTHORITATIVE),
    }


def record_meta(name, rrtype, status, ad, error=False):
    """For alternate backends (e.g. DoH) to surface Status/AD into the meta channel."""
    with _META_LOCK:
        _META[(name, rrtype)] = normalized_meta(status, ad, error)


def _parse_answer(out, rrtype):
    """Pull the rdata for `rrtype` from a full (non-+short) dig ANSWER section."""
    rows, in_answer = [], False
    for line in out.splitlines():
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if in_answer:
            if not line.strip() or line.startswith(";"):
                break
            parts = line.split(None, 4)
            if len(parts) >= 5 and parts[3] == rrtype:
                rows.append(parts[4].strip())
    return rows


_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,253}")  # DNS charset (incl. leading '_', reverse-arpa)


def _dig_backend(name, rrtype):
    """Raw backend over `dig`. Returns answer rdata (TXT still quoted), [] on real-empty.
    Retries transient resolver failures so a SERVFAIL under load can't poison the cache."""
    # Argument-injection guard: names reach here from DNS DATA too (MX targets, PTR names,
    # redirect hosts), not just the validated input domain. A name starting with '-' would be
    # parsed by the dig CLI as a flag (e.g. `-f<path>` reads a file and leaks it over DNS).
    # Reject anything that isn't a clean DNS name before it becomes an argv element.
    if not name or name[0] == "-" or not _NAME_RE.fullmatch(name):
        return []
    terminal_status = None
    for attempt in range(3):
        try:
            with _DIG_SEM:
                out = subprocess.run(
                    ["dig", "+dnssec", "+tries=2", "+time=2", rrtype, name],
                    capture_output=True, text=True, timeout=DNS_TIMEOUT,
                ).stdout
        except Exception:
            terminal_status = None
            time.sleep(0.15 * (attempt + 1))
            continue  # spawn/timeout error → transient, retry
        m = re.search(r"status:\s*(\w+)", out)
        status = normalize_status(m.group(1) if m else None)
        terminal_status = status
        if status in _TRANSIENT:
            time.sleep(0.15 * (attempt + 1))
            continue  # SERVFAIL/REFUSED under load → retry (don't trust the empty)
        # AD (Authenticated Data) flag in the header = the validating resolver verified the
        # DNSSEC chain. Record it (+ rcode) for the DANE/DNSSEC checks.
        fm = re.search(r"flags:\s*([a-z ]+);", out)
        ad = bool(fm and "ad" in fm.group(1).split())
        record_meta(name, rrtype, status, ad)
        # A non-retry RCODE is final. Metadata marks only NOERROR/NXDOMAIN as
        # authoritative; every other final code remains a lookup failure.
        return _parse_answer(out, rrtype)
    record_meta(name, rrtype, terminal_status, False, error=True)
    return []


_BACKEND = _dig_backend


def set_backend(fn):
    """Swap the raw query backend. `fn(name, rrtype) -> list[str]` returns answer strings
    (TXT may be quoted; this module de-chunks/unquotes). Used by the web tool to plug in DoH.
    Clears the cache so a backend swap can't serve stale results."""
    global _BACKEND
    _BACKEND = fn
    cache_clear()


@lru_cache(maxsize=8192)
def query(name, rrtype):
    """Answer strings for name/rrtype, or [] on failure. Thread-safe (lru_cache holds a
    lock) so audit.py's concurrent checks can share it. TXT answers are joined + unquoted."""
    rows = _BACKEND(name, rrtype)
    if rrtype == "TXT":
        joined = []
        for r in rows:
            parts = re.findall(r'"([^"]*)"', r)
            joined.append("".join(parts) if parts else r)
        return joined
    return rows


def query_fresh(name, rrtype):
    """Uncached single query (same de-chunking as query()). Used to re-confirm an empty
    answer for trust-critical records, so a transient false-empty can't be served from
    (or written to) the cache."""
    rows = _BACKEND(name, rrtype)
    if rrtype == "TXT":
        return ["".join(re.findall(r'"([^"]*)"', r)) if re.findall(r'"([^"]*)"', r) else r
                for r in rows]
    return rows


def cache_clear():
    query.cache_clear()
    with _META_LOCK:
        _META.clear()
