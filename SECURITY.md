# Security Policy

## Reporting a vulnerability

If you find a security issue in `amino-deliverability-audit`, please email
**admin@whiteboard.vc** with the details. Do not open a public issue for security reports.

We aim to acknowledge within a few business days and to ship a fix promptly for confirmed
issues. Coordinated disclosure is appreciated.

## What this skill does (and doesn't)

`amino-deliverability-audit` is **read-only**. It inspects a domain's public DNS and makes a
few outbound requests to assess email posture — a STARTTLS probe to the MX and HTTPS GETs to
the MTA-STS policy host, to RDAP (domain age/expiry), and to the domain's `robots.txt` (AI-bot
readiness) — then prints JSON. It never:

- writes or modifies DNS,
- sends email,
- requires or stores credentials, API keys, or tokens,
- writes to the filesystem.

## Hardening in place

- **Input validation** — the domain argument is validated as a syntactic hostname before it
  reaches any subprocess, socket, or DNS-name construction (rejects whitespace, control
  characters, over-length input, and a leading `-`).
- **Argument-injection guard at the resolver sink** — names reach `dig` from DNS *data* too
  (MX targets, PTR names, redirect hosts), not just the validated input domain. Every name is
  re-checked against the DNS charset and rejected if it starts with `-`, so attacker-controlled
  DNS data can never become a `dig` flag (e.g. `-f<path>`) or inject a CRLF.
- **No shell** — `dig` is invoked with list arguments, never `shell=True` or string
  interpolation.
- **SSRF guard** — before any socket probe *or HTTPS fetch* (MTA-STS, RDAP, robots.txt), the
  target host must resolve to a public IP; private, loopback, link-local, reserved, and
  multicast addresses are refused. The TLS cert is validated against the hostname; `robots.txt`
  does not follow redirects (the host is attacker-controlled) and RDAP follows only a bounded
  number, each re-validated through the same guard.
- **Untrusted-content handling** — DNS record and fetched-file contents are
  attacker-controllable and are treated as data, never instructions; the skill emits JSON and
  any value echoed into HTML downstream is escaped.
- **Secret scanning** — every push and pull request is scanned for committed secrets in CI
  (see `.github/workflows/secret-scan.yml`).

## Scope

In scope: the skill's scripts, manifest, and instructions in this repository.
Out of scope: third-party services the skill queries (public DNS resolvers, mailbox
providers), and issues requiring a compromised local machine.
