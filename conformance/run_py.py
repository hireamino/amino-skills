#!/usr/bin/env python3
"""Unified conformance runner for the Python skill surface (WS1/WS5).

Drives the SHARED conformance/fixtures.json corpus through the real scripts/audit.py
check functions with a fixture-backed resolver (no network), and asserts each fixture's
`expect`. Same corpus as the JS runner (conformance/run.mjs) — a fixture added once is
enforced on every surface. Exits non-zero on any failure; non-dns-engine fixtures are
logged SKIPPED with a reason (no silent caps).
"""
import json
import os
import sys

HERE = os.path.dirname(__file__)
SCRIPTS = os.path.join(HERE, "..", "amino-deliverability-audit", "skills",
                       "amino-deliverability-audit", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))
import audit  # noqa: E402


def _norm(n):
    return n.rstrip(".").lower()


def install_resolver(dns):
    """Point audit.py's resolver seam at fixture DNS. `*._domainkey.<domain>` is a
    wildcard matching any DKIM selector under that domain."""
    m = {_norm(k): v for k, v in (dns or {}).items()}

    def recs(name, rtype="A", *a, **k):
        name = _norm(name)
        if name in m and rtype in m[name]:
            return m[name][rtype]
        for key, val in m.items():
            if key.startswith("*._domainkey.") and name.endswith(key[1:]) and rtype in val:
                return val[rtype]
        return []

    def first_txt(name, prefix):
        for r in recs(name, "TXT"):
            if r.lower().startswith(prefix.lower()):
                return r
        return None

    audit.dig = recs
    audit.query_fresh = recs
    audit.first_txt = first_txt
    audit.confirm_txt = lambda name, prefix: first_txt(name, prefix)


CHECKS = {"DKIM": "check_dkim", "DMARC": "check_dmarc", "SPF": "check_spf"}


def run():
    fixtures = json.load(open(os.path.join(HERE, "fixtures.json")))["fixtures"]
    npass = nfail = nskip = 0
    for fx in fixtures:
        if fx.get("mode") != "dns-engine":
            nskip += 1
            print(f"  SKIP  {fx['id']} ({fx['invariant']}) — {fx.get('skip_reason', fx.get('mode'))}")
            continue
        area = fx["expect"]["present"][0]["area"] if fx["expect"].get("present") else None
        fn = getattr(audit, CHECKS.get(area, ""), None)
        if fn is None:
            nskip += 1
            print(f"  SKIP  {fx['id']} ({fx['invariant']}) — no python check mapped for area {area}")
            continue
        install_resolver(fx["input"]["dns"])
        F = []
        try:
            fn(fx["input"]["domain"], F)
        except Exception as e:
            nfail += 1
            print(f"  FAIL  {fx['id']} ({fx['invariant']}) — threw {e}")
            continue
        titles = [f"{f['area']}:{f['title']}" for f in F]
        problems = []
        for p in fx["expect"].get("present", []):
            if not any(f["area"] == p["area"] and p["includes"] in f["title"] for f in F):
                problems.append(f'missing present [{p["area"]} ~ "{p["includes"]}"]')
        for a in fx["expect"].get("absent", []):
            if any(a in t for t in titles):
                problems.append(f'unexpected absent-match "{a}"')
        if problems:
            nfail += 1
            print(f"  FAIL  {fx['id']} ({fx['invariant']}) — {'; '.join(problems)}")
        else:
            npass += 1
            print(f"  PASS  {fx['id']} ({fx['invariant']})")

    print(f"\nEngine: scripts/audit.py")
    print(f"Results: {npass} passed, {nfail} failed, {nskip} skipped.")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    run()
