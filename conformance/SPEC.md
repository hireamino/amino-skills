# Amino Deliverability — Correctness Conformance Spec (v1.4)

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
2. emits its findings plus the DNS-only score contract.

The runner checks each surface against a reviewed answer in `expect`, never against
another surface or a regenerated snapshot. For every `dns-engine` fixture:

- `present` and `absent` retain the original positive/negative guards;
- `findings` is a closed list: missing, duplicate, and additional findings fail;
- finding identity, severity, action, and explicit-null/fix substring are asserted;
- `score` is exact, including all buckets, DKIM state, gap, and note; and
- a surface may omit a finding only through `surfaces` plus a non-empty
  `notApplicable` reason for that surface.

The only current N/A is the skill's live port-25 STARTTLS finding on the two DANE
fixtures: the web and Action engines intentionally omit that capability. Any other
difference fails CI and requires Product review. The corpus has no expectation
regeneration mode; reviewed answers cannot be replaced by current output.

## Current status

**v1.4 / WHI-8 — material contract is load-bearing:** all 15 `dns-engine`
fixtures assert 139 common findings, the two documented skill-only STARTTLS findings,
and 15 exact score objects across the published skill, web audit, and GitHub Action.
The Python runner executes `audit.main()` itself, then rebinds every import-time
`batch_score.py` lookup to the fixture resolver. Real DNS and socket fallbacks are
kill-switched. Runtime assertion ledgers fail if a runner stubs out the new checks.
Committed mutation canaries prove severity, finding presence, action, fix, score,
runner integrity, and the Python network kill switch independently.

Historical delivery notes follow.

**Batch 1 — fixed across all three surfaces:** **I1** (DKIM revoked empty `p=`), **I4**
(Ed25519 length), **I6/I9** (DMARC policy must be `{none,quarantine,reject}`), **I7**
(case-insensitive tags), **I11** (SPF `-ALL`), **I14** (MTA-STS single-label wildcard).

**Batch 2 — fixed across all three surfaces:** **I10** (RFC 9989 DMARC tree walk +
subdomain policy inheritance, and an eTLD+1-aware `orgBase`/`org_base` so `good.co.uk` and
`evil.co.uk` are different orgs for report-authorization).

**Batch 3 — Action only** (exit-code semantics live in `index.mjs`): **I19** (empty/invalid
`domains` input now exits non-zero — a config error can't silently pass) and **I20 (partial)**
— a domain the engine can't audit (it throws) is now *inconclusive*: `audit-complete=false`
+ `passed=false`, failing the build only when `continue-on-audit-error=false` ("strict input,
lenient transient"). **Still pending for I20:** resolver-level SERVFAIL/timeout-vs-NXDOMAIN
detection, which needs DoH `Status` plumbed through the `q` resolver (→ v1.3, with I17/I18).

**Batch 4 — fixed across all three surfaces:** **I15** (MTA-STS `enforce` now requires
`version: STSv1` + valid mode + integer `max_age` in range + ≥1 `mx:` — a malformed policy is
flagged, not read as a valid enforce) and **I16** (policy fetch now requires HTTP 200 +
`Content-Type: text/plain`; a TXT that advertises an unfetchable/wrong-type policy is flagged
"not retrievable", not silently trusted). New testable helper `mtaStsPolicyProblems` /
`mta_sts_policy_problems`.

The matrix below is the **baseline at review time**; the ✓/✗ cells for the rows above are
superseded. Corrections to the baseline found while fixing: **I11 was a violation in the
skill too** (`spf_qualifier` was case-sensitive); **I6/I9 were correct only in the skill's
*bucket scorer*, not its *findings***; and **I10 was absent in all three** (no surface did
the tree walk — the skill only parsed `sp`/`np` on the record it already had).

**WS1/WS5 — DONE (unified runner):** `conformance/run.mjs` (JS, `ENGINE` env → either
JS engine: the Action's `engine.mjs` or the web's `audit.js`) and `conformance/run_py.py`
(skill) drive the SAME `fixtures.json`
corpus through each real engine with a mock resolver and assert the reviewed contract. Wired as a hard
CI gate in all three repos (Action `security-gate.yml`, web `skill-parity.yml`, skill
`conformance.yml`). Add a fixture once → all three surfaces must pass it. Currently 15
dns-engine cases pass on all three; five cases are logged SKIPPED with reasons.

**v1.3 — DONE (all $0, DoH/dig only, zero new deps):** a resolver meta side-channel now
surfaces DoH `Status` (RCODE) + `AD` (DNSSEC-validated) — JS via `query.meta`, skill via
`resolver.meta` (dig `+dnssec` + header AD-flag parse). On it: **I17** (DANE requires a
DNSSEC-validated TLSA — `ad=false` → "present but not DNSSEC-validated", not a pass),
**I18** (DNSSEC via the AD bit, which respects the zone cut — no false "unsigned" on a
subdomain of a signed zone), and **I20-resolver** (a SERVFAIL/REFUSED/error on a critical
lookup (SPF/DMARC/MX) → `auditDomain` returns `inconclusive`, distinct from NXDOMAIN/NODATA;
the Action folds it into `audit-complete`). Corpus: 14 dns-engine cases pass on all three
(incl. DANE/DNSSEC with mock AD bits); I20-resolver covered by the Action suite.

**Polish — DONE:** **I2** now reads the real RSA modulus bit-length from the DKIM p= DER
(`rsaModulusBits` / `_rsa_modulus_bits`; falls back to the base64-length estimate only if
the DER can't be parsed), and weak = any RSA `< 2048`, not just `== 1024`. **I13** was
resolved by the I11 case fix (`-ALL` → "SPF present" with no contradictory "no all
mechanism" — asserted by the `spf-dash-all` fixture).

**Nothing open.** All 21 invariants are addressed across the three surfaces (I17/I18 +
I20-resolver shipped in v1.3). The corpus runs 15 dns-engine cases green on skill / web /
Action; the rest are pure-function / HTTP-stub / wrapper cases covered by per-surface tests.

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

Every shipping surface must consume the same reviewed corpus revision and pass the
closed-world runner plus its mutation canaries. A severity, action, fix-meaning, or score
difference is a product decision and cannot be normalized by weakening an expectation.
The web and Action pin files must name the same full amino-skills commit before release.

## Fixtures

See `fixtures.json`. It contains 20 known-answer cases: 15 closed-world
`dns-engine` cases plus five explicitly skipped pure/HTTP/wrapper cases covered by
per-surface tests or later work. Each is language-neutral and every harness adapts it to
its own resolver mock.
