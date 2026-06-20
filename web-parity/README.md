# web-parity — JS port ↔ Python parity guard

The "Try Amino" web tool (`amino-site/functions/audit.js`, a Cloudflare Pages Function)
re-implements the skill's DNS bucket logic in JavaScript over DoH, because the edge can't
spawn `dig` or open a raw `:25` socket. Two implementations of the same logic = drift risk.

`parity.mjs` is the guard: it diffs the edge JS `buckets()` against `scripts/batch_score.py`
(the canonical Y/N scorer) across a varied domain set. Those 9 buckets are exactly the
DNS-derivable, edge-safe subset (the live STARTTLS:25 probe is intentionally dropped at the
edge), so any mismatch is a real logic divergence — not an artifact of the edge dropping a check.

## Run

```
node web-parity/parity.mjs                # default 14-domain set
node web-parity/parity.mjs foo.com bar.io # custom domains
```

Needs `python3` + `dig` and outbound DoH (cloudflare-dns.com). Assumes `amino-site` is a
sibling of this repo. Exit code is non-zero on any diff.

## When to run

After editing **either** side of the logic:
- the skill's `scripts/audit.py` / `scripts/batch_score.py` bucket rules, or
- the web port `amino-site/functions/audit.js`.

Last validated **0-DIFF across 14 domains** on 2026-06-16 (build of the web tool).

## What it does NOT cover

The full effort×value **card** (findings → quadrants → action labels) is rendered only by
the web tool; the parity guard checks the bucket scoring that underlies it. The card's
`priority()/QUADRANT/action()` tables are ported verbatim from `audit.py` — if you change
those, eyeball the rendered card on a few domains too.
