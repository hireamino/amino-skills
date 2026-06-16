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
import subprocess
from functools import lru_cache

DNS_TIMEOUT = 6  # seconds, per dig invocation


def _dig_backend(name, rrtype):
    """Raw backend: `dig +short`. Returns the answer lines verbatim (TXT still quoted)."""
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=4", "+tries=1", rrtype, name],
            capture_output=True, text=True, timeout=DNS_TIMEOUT,
        ).stdout.strip()
    except Exception:
        return []
    return [r.strip() for r in out.splitlines() if r.strip()]


_BACKEND = _dig_backend


def set_backend(fn):
    """Swap the raw query backend. `fn(name, rrtype) -> list[str]` returns answer strings
    (TXT may be quoted; this module de-chunks/unquotes). Used by the web tool to plug in DoH.
    Clears the cache so a backend swap can't serve stale results."""
    global _BACKEND
    _BACKEND = fn
    query.cache_clear()


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


def cache_clear():
    query.cache_clear()
