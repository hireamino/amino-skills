# Security Policy

## Reporting a vulnerability

If you find a security issue in `amino-deliverability-audit`, please email
**admin@whiteboard.vc** with the details. Do not open a public issue for security reports.

We aim to acknowledge within a few business days and to ship a fix promptly for confirmed
issues. Coordinated disclosure is appreciated.

## What this skill does (and doesn't)

`amino-deliverability-audit` is **read-only**. It inspects a domain's public DNS and makes a
couple of outbound socket probes (STARTTLS to the MX, MTA-STS over HTTPS) to assess email
posture, then prints JSON. It never:

- writes or modifies DNS,
- sends email,
- requires or stores credentials, API keys, or tokens,
- writes to the filesystem.

## Hardening in place

- **Input validation** — the domain argument is validated as a syntactic hostname before it
  reaches any subprocess, socket, or DNS-name construction (rejects whitespace, control
  characters, over-length input, and leading `-` flag-injection).
- **No shell** — `dig` is invoked with list arguments, never `shell=True` or string
  interpolation.
- **SSRF guard** — before any socket probe, the target host must resolve to a public IP;
  private, loopback, link-local, reserved, and multicast addresses are refused (so a
  malicious domain can't point its MX/MTA-STS host at an internal address).
- **Untrusted-content handling** — DNS record contents are attacker-controllable and are
  treated as data, never instructions; values echoed into HTML are escaped.
- **Secret scanning** — every push and pull request is scanned for committed secrets in CI
  (see `.github/workflows/secret-scan.yml`).

## Scope

In scope: the skill's scripts, manifest, and instructions in this repository.
Out of scope: third-party services the skill queries (public DNS resolvers, mailbox
providers), and issues requiring a compromised local machine.
