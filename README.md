# Amino Skills

Free tools to assess email sending domains, from [Amino](https://hireamino.com).

## Install (Claude Code)

```
/plugin marketplace add cisoventures/amino-skills
/plugin install amino-deliverability-audit
```

## Plugins

### amino-deliverability-audit — benchmark your sending domain

Emails landing in spam? Not sure a domain is set up to send? Point this at any domain and
it benchmarks the signals mailbox providers actually judge you on — SPF, DKIM, DMARC,
alignment, MTA-STS, TLS-RPT, DANE, BIMI, and MX hygiene — then tells you, in plain terms,
where you stand and what to fix first.

Read-only: it inspects public DNS and drafts the exact changes, but never touches anything.

_From Amino — hireamino.com_
