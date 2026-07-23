# Amino Deliverability — Correctness Conformance Spec (v1.2)

**Status:** proposed · **Owner:** hireamino · **Canonical home:** `amino-skills/conformance/`

## Why this exists

The same deliverability audit is implemented **three times**:

| Surface | Repo · path | Runtime | Resolver |
|---|---|---|---|
| **Skill** (canonical) | `amino-skills/…/scripts/audit.py` (+ `verify.py`, `batch_score.py`) | Python | `dig` |
| **Web tool** | `amino-site/functions/audit.js` | JS (Cloudflare Pages Fn) | DoH |
| **Action** | `amino-audit-action/src/engine.mjs` | JS (Node) | DoH |

The existing `web-parity/` harness only reconciles **skill ↔ web**, and only their *bucket
scores* + *finding inventory* — never the **Action**, and never the *verdict logic* against
known-answer inputs. Result: the two JS ports drifted from the canonical Python and each
other. This spec is the single source of truth all three must conform to, proven by a
fixture corpus (`fixtures.json`) run against every surface in CI.

## Conformance model

Each surface ships a thin **conformance harness** that:
1. injects a fixture's canned DNS/HTTP state into its resolver seam (mock — no network), and
2. emits a normalized verdict `{ dimension: value, findings: [{area, severity}] }`.

The runner diffs each surface's output against the fixture's `expect`. A surface may
declare a fixture **N/A** only for a documented reason (e.g. the edge can't open `:25`, so
live-STARTTLS fixtures are web/Action-N/A). Any other diff fails CI.

## v1.2 batch 1 — status

**Fixed across all three surfaces** (verified via the conformance checks in each repo):
**I1** (DKIM revoked empty `p=`), **I4** (Ed25519 length), **I6/I9** (DMARC policy must be
`{none,quarantine,reject}`), **I7** (case-insensitive tags), **I11** (SPF `-ALL`), **I14**
(MTA-STS single-label wildcard). The matrix below is the **baseline at review time**; the
✓/✗ cells for those rows are superseded by this batch. Correction to the baseline: **I11 was
a violation in the skill too** (`spf_qualifier` was case-sensitive), and **I6/I9 were correct
only in the skill's *bucket scorer* (`batch_score.py`), not its *findings* (`check_dmarc`)** —
both now fixed.

**Still open (v1.2 remainder / v1.3):** I2, I10 (RFC 9989 tree walk), I12, I13, I15, I16,
I17, I18, I19, I20.

## The invariants (the contract)

Legend: ✓ conforms · ✗ violates (bug) · ~ partial · ? confirm during impl.

| # | Invariant | Skill | Web | Action |
|---|---|:--:|:--:|:--:|
| **DKIM** |
| I1 | Empty `p=` (`v=DKIM1;k=rsa;p=`) is **revoked**, never healthy | ✗ | ✗ | ✗ |
| I2 | Valid RSA ≥2048 modulus → good (validate real modulus, not base64 length) | ~ | ~ | ~ |
| I3 | RSA-1024 → weak | ✓ | ✓ | ✓ |
| I4 | Ed25519 `p=` must decode to exactly 32 bytes; else invalid | ✗ | ✗ | ✗ |
| I5 | `t=y` testing flag → not enforced | ✓ | ✓ | ✓ |
| **DMARC** |
| I6 | `p`/`sp` must ∈ {none,quarantine,reject}; `p=banana` invalid | ✓ | ✗ | ✗ |
| I7 | Tag names parsed case-insensitively (`P=Reject`) | ~ | ? | ? |
| I8 | Multiple `_dmarc` records → policy void | ✓ | ✓ | ✓ |
| I9 | "Enforced" only if effective `p` ∈ {quarantine,reject} | ✓ | ✗ | ✗ |
| I10 | Subdomain inherits org policy via RFC 9989 tree walk; `sp`/`np` applied | ~ | ✗ | ✗ |
| **SPF** |
| I11 | `-ALL` == `-all` (qualifier case-insensitive) | ✓ | ? | ✗ |
| I12 | >10 DNS lookups → fail; void lookups counted by actual record type | ~ | ~ | ~ |
| I13 | "no `all` mechanism" distinct from "SPF present" (no contradictory pair) | ~ | ~ | ✗ |
| **MTA-STS** |
| I14 | Wildcard `*.example.com` matches **exactly one** leftmost label | ✗ | ✗ | ✗ |
| I15 | `enforce` requires `version:STSv1` + valid mode + integer `max_age` + ≥1 mx | ~ | ~ | ~ |
| I16 | Policy fetch requires HTTP 200 + `text/plain` | ? | ? | ? |
| **DNSSEC / DANE** |
| I17 | DANE "active" requires DNSSEC-validated (AD) TLSA, not mere presence | ✗ | ✗ | ✗ |
| I18 | DNSSEC evaluated at the zone cut, not the exact input label | ✗ | ✗ | ✗ |
| **Input / reliability** |
| I19 | Empty/invalid input → non-zero exit (Action) / explicit error (skill/web) | ? | n/a | ✗ |
| I20 | SERVFAIL/timeout ≠ NXDOMAIN/NODATA; transient → **incomplete**, never pass | ~ | ~ | ~ |
| **Labeling** (advisory-score hygiene) |
| I21 | rDNS/null-MX/BIMI worded as inbound/brand signals, not blocking posture | — | — | — |

**Reading of the matrix:** the two JS ports are the problem child (they share I1/I4/I6/I9/
I10/I14/I17/I18 violations); the Python skill is already correct on DMARC policy (I6/I9) and
ahead on the tree walk (I10). The universal bugs — in **all three** — are **I1 (DKIM empty
`p=`)**, **I4 (Ed25519)**, **I14 (MTA-STS wildcard)**, and **I17/I18 (DANE/DNSSEC)**.

## Release gate

`v1.2` = every ✗ and (implementation-confirmed) `?`/`~` in I1–I16 + I19–I20 turned ✓ on all
three surfaces, with the conformance runner green in all three repos' CI. I17/I18 (DANE/
DNSSEC depth) may slip to **v1.3** if scoped out explicitly — they're advisory-only and
equally absent everywhere, so they don't cause *divergence*, only shared understatement.

## Fixtures

See `fixtures.json`. ~24 known-answer cases, one+ per invariant. Each is language-neutral:
it declares logical DNS/HTTP state and the expected normalized verdict, and every surface's
harness adapts it to its own resolver mock.
