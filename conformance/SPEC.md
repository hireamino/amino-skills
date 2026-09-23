# Amino Deliverability — Correctness Conformance Spec (v1.15)

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
another surface or a regenerated snapshot. For every `dns-engine` or
`http-observation` fixture:

- `present` and `absent` retain the original positive/negative guards;
- `findings` is a closed list: missing, duplicate, and additional findings fail;
- finding identity, severity, lane, action, and fix substring are asserted;
- every non-pass expected finding must declare a non-null fix substring;
- exact detail and effort+value are asserted only where a fixture declares them, and
  effort and value must be declared together;
- `score` is exact, including all buckets, DKIM state, gap, note, and the scored-bucket
  `lanes` map;
- `observations` is an exact result-level map with the keys `mta_sts_policy`, `robots`,
  and `rdap`; and
- `inconclusive` and `inconclusive_reason` are compared on both surfaces whenever
  a fixture declares them; and
- a surface may omit a finding only through `surfaces` plus a non-empty
  `notApplicable` reason for that surface.

The only surface-specific finding N/A is the skill's live port-25 STARTTLS finding
when a fixture has a real MX: the web and Action engines intentionally omit that
capability. A true null MX also makes the score buckets `MTA_STS`, `TLS_RPT`, and
`DANE` explicitly `null` on every surface; `null` means not applicable, renders as
`—`, and is excluded from the gap. Any other difference fails CI and requires Product
review. The corpus has no expectation regeneration mode; reviewed answers cannot be
replaced by current output.

## Current status

**v1.15 / WHI-180 Step 2 — critical-DNS rcode boundary:** for the three
critical lookups (apex TXT, `_dmarc.<domain>` TXT, then apex MX), only NOERROR
(0) and NXDOMAIN (3) are conclusive. Every other response code—including FORMERR
(1), SERVFAIL (2), NOTIMP (4), and REFUSED (5)—and every transport error is
inconclusive. Status 2 and 5 use the existing reason
`"<TYPE> <name>: SERVFAIL/REFUSED"`; every other failure uses
`"<TYPE> <name>: lookup error"`. Non-critical lookups never set the flag.

Six fixtures extend the corpus from 52 to 58 cases (53 contract passes and five
skips): three critical FORMERR/NOTIMP rows, one non-critical NOTIMP control, an
AAAA-only website lookup failure, and an apex-NXDOMAIN website path. The website
rows pin that either address-family lookup failure makes `robots` unavailable,
while authoritative apex NXDOMAIN makes it not applicable; neither affects the
critical-DNS inconclusive result. Python mutation canaries rise from 54 to 59 and
JavaScript mutation canaries from 23 to 27. The skipped `reliability-servfail`
wrapper placeholder is retained, but its stale pre-v1.14 explanation is replaced:
resolver-level I20 is now covered by `dns-engine` fixtures, while wrapper exception
handling remains covered by consumer `finalize()` tests.

The Python skill already implements this rule through its normalized resolver
metadata, so this revision changes no shipping Python logic. Engine contract 1.4.0
intentionally fails the three new critical-rcode rows; its correction ships only
in the engine's own reviewed PR together with the immutable skills-pin bump.

**v1.14 / WHI-180 — critical-DNS inconclusive result contract:** both the Python
skill and the JavaScript engine report `inconclusive: bool` and
`inconclusive_reason: string | null`. After the normal resolver retries, inspect
the final metadata in this exact order: apex TXT, `_dmarc.<domain>` TXT, then apex
MX. The first lookup whose metadata has an error, SERVFAIL (2), or REFUSED (5)
sets `inconclusive: true` with the exact reason
`"<TYPE> <name>: SERVFAIL/REFUSED"` for status 2 or 5, otherwise
`"<TYPE> <name>: lookup error"` for a fetch/transport error (including a Python
timeout with no final status). With no such lookup, return `false` and `null`.
NXDOMAIN (3) and NOERROR/NODATA (0) are conclusive. DKIM, MTA-STS, TLS-RPT,
BIMI, A/AAAA, CAA, DNSSEC, PTR, and TLSA are non-critical and never set this
flag. Python's metadata `error` includes SERVFAIL/REFUSED, so the numeric status
takes precedence when choosing the reason string. The fixture fields
`expect.inconclusive` and `expect.inconclusive_reason` bind both surfaces. They
are now stated on all 26 existing `dns-engine` fixtures and five new cases,
bringing the corpus from 47 to 52 fixtures (47 contract passes, five skips).
Python mutation canaries rise from 49 to 54; JavaScript canaries from 18 to 23.
This version deliberately leaves finding text for a failed critical lookup
unchanged; whether to revise those affected “missing” verdicts remains an open
product decision, not a silent consequence of this metadata change.

**v1.13 / WHI-176 Step 1b — website observation split and one RDAP port shape:**
the website/robots check now reports `not_applicable` when the apex has no A or
AAAA answers at all from authoritative DNS responses. A failed A or AAAA lookup,
answers that exist but are refused by the public-address contract, and an attempted
fetch that fails all remain `unavailable`. MTA-STS is
deliberately different: once `_mta-sts` TXT advertises a policy, a policy host
with no address or refused answers is a broken promise and stays `unavailable`.
DNS metadata remains backward-compatible: `status: 2` applies to every record
type for that name, while an optional per-record-type map applies only to the
listed types and treats an unlisted type as NOERROR. For example,
`status: {"A": 2, "AAAA": 2}` makes address lookups fail while TXT and MX stay
authoritative. A DNS name must not mix the scalar and map forms.
The RDAP fixture port is exactly `{status, data}` or `null`; `body` remains in the
fixture only for the Python raw-HTTP surface, and the engine's tolerant bare-object
branch is removed in contract 1.4.0. Two fixtures extend the corpus from 45 to
47: an apex A/AAAA lookup failure that leaves TXT and MX authoritative, and an
advertised MTA-STS policy whose policy host has no A/AAAA answers. The 24 existing
no-apex-address rows still flip only `observations.robots`, while private-address
and attempted-fetch rows remain `unavailable`. Python mutation canaries rise from
42 to 49; the staged JavaScript count remains 18.

**v1.12 / WHI-176 Step 1 — Domain posture lane:** the finding-lane enum is now
the closed five-value set `outbound_auth | inbound_transport | domain_posture |
brand_optional | outside_sending_posture`. The enum value
`outside_sending_posture` is unchanged. Finding areas map as follows:

| Lane | Finding areas |
|---|---|
| `outbound_auth` | SPF, DKIM, DMARC |
| `inbound_transport` | MTA-STS, TLS-RPT, MX, Transport, except the reverse-DNS title exception |
| `domain_posture` | DNSSEC, Reputation, CAA |
| `brand_optional` | BIMI |
| `outside_sending_posture` | AI visibility, and the reverse-DNS title exception |

Reverse DNS stays outside sending posture because the PTR belongs to a receiving
host, and DNS cannot show whether that host also sends. Unknown finding areas still
fail closed. This lane-only contract revision deliberately raises the Python mutation
canaries from 39 to 42 and the JavaScript mutation canaries from 15 to 18; finding
text, severity, score, observations, address handling, and HTTP behavior are unchanged.

**v1.11 / WHI-175 C3 — real HTTP checks and zone-qualified addresses:** the Python
fixture runner now invokes the skill's shipping MTA-STS-policy and generic HTTPS
readers. A shared deterministic seam replaces only `socket.create_connection()` and
`ssl.create_default_context()`, records the vetted endpoint, verified TLS context, SNI,
and request path, and serves raw fixture HTTP; the runner no longer re-implements either
reader. Address-contract 1.1 adds six IPv6-zone rows and explicitly refuses every
zone-qualified address literal. Exactly four rows become newly refused relative to the
reviewed base; no row becomes newly allowed. The table now has 120 rows and the Python
runner is guarded by 39 mutation canaries.

**v1.10 / WHI-127 C1 — one strict public-address contract:**
`address-contract.json` is the single editable machine-readable contract for every
domain-controlled socket and HTTPS fetch. The published Python skill carries a generated
byte-identical copy beside `audit.py`; `check.py` rejects any drift between the two files.
The contract is derived from the
[IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml),
retrieved 2026-09-15.

A host is eligible only when DNS returns at least one A/AAAA answer and every answer is
public. IPv4 refuses the exact networks in the table. IPv6 is public only inside
`2000::/3` and outside `2001::/23`, `2001:db8::/32`, `2002::/16`, and `3fff::/20`;
everything else is refused. IPv4-mapped IPv6 is judged as its embedded IPv4 in every
valid textual form. One unparseable answer refuses the whole host. The table's 114 rows
pin boundaries, special ranges, mapped/compatible/NAT64 forms, and mixed answer sets on
Python 3.12 and 3.14 without relying on version-sensitive `ipaddress` classification
flags. Seven appended closed-world fixtures bring the corpus to 40 executable contract
fixtures plus five skips, and the Python runner is guarded by 34 mutation canaries.

**v1.9 / WHI-125 Step 1 — MTA-STS DNS lookup failure is not absence:** the
Python resolver normalizes dig string RCODEs and numeric fixture/DoH RCODEs into one
metadata shape and records terminal `SERVFAIL`, `REFUSED`, missing-status, and
subprocess failures with `error: true` after retries. Only `NOERROR` and `NXDOMAIN`
are authoritative; `NXDOMAIN` and NOERROR-empty remain authoritative absence. One
`mta_sts_txt_lookup()` helper drives both the
shipping finding and `batch_score.py`: failure emits **“Unable to confirm MTA-STS
policy”**, sets `mta_sts_policy: unavailable`, and makes `MTA_STS: null`, while
confirmed absence retains **“No MTA-STS policy”**, `not_applicable`, and a scored
`false`. True null MX takes precedence. Four appended closed-world fixtures and six
new mutation canaries guard the distinction. The Python finding inventory is now 12
areas / 39 action labels. The JavaScript consumers remain intentionally unchanged
until engine contract 1.3.0 consumes this reviewed corpus revision.

**v1.8 / WHI-79 Phase A.2 — public-address socket guard:** the Python skill's
single `host_public_ips()` helper established whole-host refusal, IPv4-mapped handling,
and low-level guards at the robots, MTA-STS-policy, and MX STARTTLS call sites. The
original partial range list and implementation-specific classification were superseded
by the v1.10 table without changing those call sites.

**v1.7 / WHI-79 Phase A — lane and HTTP observation metadata:** every finding
carries one lane from the closed enum `outbound_auth | inbound_transport |
brand_optional | outside_sending_posture`. The current 12 finding areas have an
explicit mapping; an unknown area is a contract failure. The score object remains
flat and adds a `lanes` map keyed by all nine scored buckets. Reverse-DNS findings
currently share the `Transport` area with inbound checks; their titles are the one
closed exception and map to `outside_sending_posture`, while the other Transport
findings remain `inbound_transport`.

Every audit result also carries a closed `observations` map for the three
HTTP-dependent checks. `checked` means an HTTP response was obtained and evaluated,
including a response that proves absence such as 404. `unavailable` means no
trustworthy response was obtained. `not_applicable` means the operation was
intentionally skipped because its prerequisite does not apply (for example no
advertised MTA-STS TXT or a true null MX). This metadata does not replace or weaken
the existing DNS `inconclusive` contract. Robots and the MTA-STS policy fetch run only
after their host resolves to a public address. For robots, no A/AAAA answers means
`not_applicable`, while refused answers mean `unavailable`; for an advertised
MTA-STS policy host, either condition remains `unavailable`.
Three absent/unavailable pairs (six fixtures) prove that the states remain distinct
without changing findings, scores, or ordering. A separate
closed-world lane fixture exercises all 12 finding areas plus the reverse-DNS title
exception; a valid-but-wrong lane therefore reaches the runner comparison instead of
being caught only by the implementation's unknown-area guard.

The Python skill implements this contract independently. The two JavaScript
consumers remain on engine contract 1.1.0 until the separately reviewed engine 1.2.0
phase lands; during that staged interval they are expected to fail the new corpus
fields rather than silently infer them.

**v1.6 / WHI-10 Phase 1 — evidence-boundary fields are enforceable:** selected
findings can assert exact detail and effort+value placement without making either
field universal. Every non-pass finding in the corpus must carry a remediation fix,
preventing a surface from pairing an action with "no action needed" evidence. The
No-MX and null-MX copy boundaries and the brand/optional low-value rule are guarded
by targeted mutation canaries.

**v1.5 / WHI-50 — null MX has an explicit inbound-only boundary:** a true null MX
emits the same MTA-STS not-applicable pass on every surface, suppresses TLS-RPT as a
gap, and represents MTA-STS/TLS-RPT/DANE as `null` score buckets. The two remaining
outbound-relevant gaps in the reviewed fixture still count. Separate fixtures prove
that no MX records and a null exchange mixed with a real MX do not receive the
exemption. Removing the score exemption on any surface is mutation-canaried.

**v1.4 / WHI-8 — material contract is load-bearing:** all 15 original `dns-engine`
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

**Nothing open.** All 21 original invariants are addressed across the three surfaces (I17/I18 +
I20-resolver shipped in v1.3). The corpus runs 19 dns-engine cases green on skill / web /
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
closed-world runner plus its mutation canaries. A severity, action, fix-meaning, selected
exact-detail, selected effort/value, or score difference is a product decision and cannot
be normalized by weakening an expectation.
The web and Action pin files must name the same full amino-skills commit before release.

## Fixtures

See `fixtures.json`. It contains 47 known-answer cases: 26 closed-world
`dns-engine` cases, 16 closed-world `http-observation` cases (the original
absent/unavailable pairs, lane coverage and address refusals plus seven WHI-127
coverage cases), and five explicitly skipped
pure/HTTP/wrapper cases covered by per-surface tests or later work. Each is
language-neutral and every harness adapts it to its own resolver/HTTP mock without
ambient network access. The Python runner is guarded by 49 mutation canaries; the
staged JavaScript runner remains guarded by 18 canaries on each consumer engine.
