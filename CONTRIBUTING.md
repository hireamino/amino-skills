# Contributing to Amino Skills

Thanks for considering a contribution. This repo holds free, read-only email-posture
tools from [Amino](https://hireamino.com). The skill inspects public DNS and drafts
fixes — it never changes anything — and contributions should keep it that way.

## Good places to start

The audit is only as good as the signals it understands. The highest-value
contributions:

- **New or sharper checks** — a deliverability/authentication/transport signal we
  don't yet inspect, or a more accurate reading of one we do (SPF, DKIM, DMARC,
  alignment, MTA-STS, TLS-RPT, DANE, BIMI, MX hygiene).
- **More DKIM selectors** — DKIM presence can't be confirmed without knowing the
  selector. We probe a list of common provider selectors; adding ones we miss
  directly improves coverage. See `scripts/audit.py`.
- **Standards updates** — the forward-readiness logic tracks DMARCbis, the
  Gmail/Yahoo/Microsoft sender rules, and the PQC migration
  (`references/standards-radar.md`). When a standard moves, update it — **with a
  citation** (IETF datatracker, NIST, the provider's own docs). Do not assert RFC
  numbers that aren't published.
- **Bug reports with a domain** — if a domain scores wrong, tell us *which domain*
  and what you expected. Reproducibility is everything for a DNS tool.
- **False-positive / false-negative fixes** — especially around SPF parsing,
  redirect/include following, and DKIM key detection.

## Ground rules

- **Read-only stays read-only.** No contribution may add the ability to send mail,
  write DNS, require credentials, or exfiltrate data about the domains it scans.
- **Verify against real resolvers.** Changes to detection logic should be checked
  against Google (`8.8.8.8`) and Cloudflare (`1.1.1.1`) — `scripts/verify.py` runs a
  golden-set cross-check. Include before/after for any domain whose score changes.
- **Cite sources for any standards claim.** No claim about a spec, a date, or a
  provider rule without a link to the primary source.
- **Keep it fast.** The scan targets ~10–20s for a single domain. Don't add
  unbounded network work; respect the existing timeouts and `dig` memoization.
- **No scope creep into the product.** This is a public posture *auditor*. Please
  don't propose features that belong in a hosted service.

## Workflow

1. Open an issue first for anything non-trivial (use the templates) so we can agree
   on the approach before you build.
2. Fork, branch, make the change.
3. Run `scripts/verify.py` and include the result in your PR.
4. Run `claude plugin validate` if you touched the plugin/marketplace manifests.
5. Open a PR describing *what changed and why*, with reproduction (domain + expected
   vs actual) for any detection change.

## Licensing of contributions

This project is licensed under **Apache-2.0** (see [LICENSE](./LICENSE)). By
submitting a contribution, you agree it is licensed under the same terms.

## Questions

Open an issue, or reach us at [hireamino.com](https://hireamino.com).
