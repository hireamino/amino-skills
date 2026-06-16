# Amino Skills

Agentic email-infrastructure skills from [Amino](https://hireamino.com).

## Install (Claude Code)

```
/plugin marketplace add cisoventures/amino-skills
/plugin install amino-deliverability-audit
```

## Plugins

### amino-deliverability-audit
Point it at a domain and it audits the whole email-trust posture — SPF, DKIM (three-state),
DMARC, MTA-STS, TLS-RPT, DANE, BIMI, MX hygiene — plus forward-looking DMARCbis and
post-quantum (PQC) readiness, then hands back a prioritized, paste-ready remediation plan.
Read-only: inspects public DNS, never changes anything.

_Built by Amino. Make whatever you send actually arrive._
