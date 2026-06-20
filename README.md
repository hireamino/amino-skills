# Amino Skills

Free tools to assess email sending domains, from [Amino](https://hireamino.com).

## Install (Claude Code)

```
/plugin marketplace add hireamino/amino-skills
/plugin install amino-deliverability-audit
```

## Plugins

### amino-deliverability-audit — benchmark your sending domain

Emails landing in spam? Not sure a domain is set up to send? Point this at any domain and
it benchmarks the signals mailbox providers actually judge you on — SPF, DKIM, DMARC,
alignment, MTA-STS, TLS-RPT, DANE, BIMI, and MX hygiene, plus the surrounding trust
signals (DNSSEC, CAA, reverse DNS/FCrDNS, domain age, and AI-crawler visibility) — then
tells you, in plain terms, where you stand and what to fix first.

Read-only: it inspects public DNS and drafts the exact changes, but never touches anything.

**What makes it different from a free DMARC checker:**

- **Whole-posture, not one record.** Most tools check whether a record *exists*. This scores
  all the signals together, weighs them by impact, and tells you what to fix *first* — as an
  effort × value plan, not a wall of green/red.
- **Catches the silent failures** existence-checks miss: SPF void-lookup PermErrors,
  unverified external DMARC report destinations (reports you think you're getting but aren't),
  `sp=none` subdomain gaps, MTA-STS policies that don't cover your real MX, DKIM keys stuck in
  testing mode.
- **Forward-readiness no other free checker does:** flags **DMARCbis (RFC 9989)** cleanup
  (removed `pct`/`rf`/`ri` tags, missing `np=`) and **post-quantum** exposure (RSA-1024 DKIM,
  TLS 1.2 transport) — so you fix today's gaps and get ahead of the ones coming.
- **Read-only and local.** Inspects public DNS and drafts the exact records; never sends mail,
  needs credentials, or changes anything.

## Learn

New to deliverability, or want the questions answered before you run anything? See the
**[Email deliverability FAQ](./FAQ.md)** — SPF/DKIM/DMARC explained, what DMARC
enforcement actually means, the Gmail/Yahoo sender rules, MTA-STS/TLS-RPT/DANE, BIMI,
DMARCbis, and what "post-quantum ready" means for email.

## Contributing

Contributions welcome — new checks, missing DKIM selectors, standards updates, and
bug reports (with the offending domain) all help. See
**[CONTRIBUTING.md](./CONTRIBUTING.md)**. The one rule: the skill stays read-only.

## License

[Apache-2.0](./LICENSE).

_From Amino — hireamino.com_
