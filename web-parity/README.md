# web-parity — skill ↔ web-tool parity guards

The "Try Amino" web tool (`amino-site/functions/audit.js`, a Cloudflare Pages Function)
re-implements the skill's logic in JavaScript over DoH, because the edge can't spawn `dig`
or open a raw `:25` socket. Two implementations of the same logic = drift risk. These two
guards keep them in lockstep — one for scoring, one for findings coverage.

## `inventory.mjs` — findings coverage (the hard gate)

Statically diffs, from both `scripts/audit.py` and `amino-site/functions/audit.js`:
- the set of check **areas** the findings use, and
- the set of canonical **action labels** `action()` can emit.

If a check is added to one surface but not the other, the sets differ and it fails. No
network, fully deterministic — this is the gate that runs in CI. This is what previously
drifted: the web tool grew checks (DNSSEC, CAA, reverse-DNS, domain-age, AI-bot,
multiple-SPF/DMARC) that the skill lacked, and bucket parity couldn't see it.

```
node web-parity/inventory.mjs           # compare + report (exit non-zero on divergence)
node web-parity/inventory.mjs --list    # also print both full inventories
```

## `parity.mjs` — bucket scoring

Diffs the edge JS `buckets()` against `scripts/batch_score.py` (the canonical Y/N scorer)
across a varied domain set. Those 9 buckets are the DNS-derivable, edge-safe subset (the
live STARTTLS:25 probe is intentionally dropped at the edge), so a mismatch is a real
scoring-logic divergence. Needs `python3` + `dig` + outbound DoH; can be DNS-flaky on
shared CI runners, so it's informational there and definitive when run locally.

```
node web-parity/parity.mjs                # default 14-domain set
node web-parity/parity.mjs foo.com bar.io # custom domains
```

## Paths

Both default to the sibling-repo dev layout (`amino-site` next to this repo). Override for
CI via env: `PARITY_PY`, `PARITY_SCRIPTS`, `PARITY_JS`.

## CI gate

`amino-site/.github/workflows/skill-parity.yml` runs `inventory.mjs` as a **hard gate** on
any change to `functions/audit.js` (cloning this public repo token-free), plus `parity.mjs`
informationally. A web-tool PR that diverges from the skill fails the build.

## When to run locally

After editing **either** side: the skill's `scripts/audit.py` / `batch_score.py`, or the
web port `amino-site/functions/audit.js`. Last validated **0-DIFF** + inventory in lockstep
(12 areas / 37 labels) on 2026-06-20.
