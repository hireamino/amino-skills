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
alignment, MTA-STS, TLS-RPT, DANE, BIMI, and MX hygiene — then tells you, in plain terms,
where you stand and what to fix first.

Read-only: it inspects public DNS and drafts the exact changes, but never touches anything.

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
