# Standards radar — what's coming for email senders

Use this to write the "What's coming" section. Only surface what's relevant to the
domain's *current* state (e.g. don't lecture about PQC-DKIM if they don't even have DKIM).
Verify specifics against IETF datatracker before asserting RFC numbers — these standards
move, and stating a draft as a published RFC is a credibility-killer.

## 1. DMARCbis = RFC 9989 (PUBLISHED — affects everyone with DMARC)

The DMARC spec has been modernized. **DMARCbis is now published as RFC 9989** (Proposed
Standard, May 2026; `draft-ietf-dmarc-dmarcbis`), and it **obsoletes RFC 7489 and RFC 9091**
— the original DMARC (RFC 7489) was only Informational, so this is the first Standards-Track
DMARC. (Verified against rfc-editor.org/info/rfc9989 + IETF datatracker. Still re-verify any
*other* RFC number before asserting it — don't pattern-match adjacent numbers.)

What changes that matters to a sender:
- **DNS Tree Walk replaces the Public Suffix List** for organizational-domain discovery.
  Policy now resolves by walking up the DNS tree. Domains relying on PSL quirks should
  re-verify their policy still applies the way they expect.
- **`np=` (non-existent-subdomain policy) is new** — set `np=reject` to cover subdomains
  that don't exist (a common cousin-domain spoofing vector). `sp=` still covers existing
  subdomains.
- **`pct`, `rf`, and `ri` are removed.** A record still using them isn't broken today, but
  it's no longer spec-conformant — flag them as cleanup, and note `pct<100` was always
  probabilistic enforcement.
- **Readiness check:** an enforced policy (`p=quarantine`/`reject`) with working aggregate
  reporting (`rua`) and `sp`/`np` set is the right posture. A domain stuck at `p=none`, or
  enforced at the apex but `sp=none`, is *less* ready, not more.

## 2. Mailbox-provider sender requirements (live and tightening)

Not a standards body, but the de-facto rules that gate the inbox:
- **Google & Yahoo** (since Feb 2024): bulk senders need SPF + DKIM + DMARC, aligned;
  one-click unsubscribe; spam-complaint rate under ~0.3%.
- **Microsoft / Outlook** (rolling out 2025+): joining DMARC enforcement for high-volume
  senders. The floor keeps rising, so "passes today" is not "passes next quarter."
- A domain at `p=none`, missing DKIM, or with a broken SPF (>10 lookups) is exposed to these
  rules right now — frame those findings as *current* deliverability risk, not future.

## 3. Post-quantum cryptography (PQC) — the long migration

The macro clock: **NIST IR 8547** sets RSA-2048 / ECC P-256 as **deprecated by 2030,
disallowed by 2035**; NSA CNSA 2.0 wants PQC for new national-security acquisitions by
**2027**. Quantum-vulnerable crypto is woven through email in three places:

- **Transport (most urgent — "harvest now, decrypt later").** Mail captured in transit today
  can be decrypted post-quantum. The fix is **TLS 1.3 + hybrid ML-KEM key exchange**
  (the `X25519MLKEM768` group), per IETF `draft-ietf-uta-pqc-app`. **Prerequisite: the MX
  must speak TLS 1.3.** A domain still on TLS 1.2 can't adopt PQC transport at all — so a
  "TLS 1.2 only" finding is also a PQC-readiness blocker.
- **Authentication (DKIM).** DKIM signs with RSA/Ed25519 today — both quantum-breakable. The
  path is ML-DSA (Dilithium) / SLH-DSA (SPHINCS+), likely hybrid. The operational catch:
  PQC keys/signatures are 1–2 orders of magnitude larger (ML-DSA pubkey ~1.3 KB, sig
  ~2.4 KB) but DKIM publishes its key in a **DNS TXT record**, which collides with the
  255-byte string chunking and UDP/EDNS size limits. Google/Microsoft/Fastmail are reportedly
  experimenting with hybrid DKIM. Less time-urgent than transport, bigger operational lift.
  A domain still on **RSA-1024 DKIM** is doubly behind: weak today *and* furthest from PQC.
- **End-to-end (S/MIME, PGP).** IETF LAMPS composite ML-DSA for X.509 carries S/MIME certs
  into PQC. Matters mainly for regulated/gov senders doing signed/encrypted mail.

**Sleeper dependency:** DANE and MTA-STS lean on **DNSSEC**, and PQC for DNSSEC signatures
(size again) is unsolved at scale. Worth a one-line mention if the domain uses DANE.

## How to use this in the report

- Map each forward item to the domain's actual findings. Examples:
  - `p=none` → "DMARCbis and the provider rules both reward enforcement; ramp the policy."
  - TLS 1.2 MX → "blocks any future post-quantum transport; get to TLS 1.3."
  - RSA-1024 DKIM → "weak now and the furthest from the coming PQC-DKIM migration; rotate."
  - DANE present → "note the DNSSEC/PQC dependency for the long term."
- Keep it to the 2–4 items that actually apply. The point is *credible foresight*, not a
  standards lecture.
