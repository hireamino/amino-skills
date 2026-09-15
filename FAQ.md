# Email deliverability FAQ

Plain-language answers to the questions people actually ask about email
deliverability, sender reputation, and the DNS records mailbox providers judge you
on. Written by [Amino](https://hireamino.com) — the vendor-agnostic layer that makes
whatever you send arrive and be trusted.

If you want these answers *for your own domain*, run the free
[`amino-deliverability-audit`](./README.md) skill — it benchmarks your domain in
seconds and tells you what to fix first.

---

## The basics

### Why are my emails going to spam?

Almost always one of three things, in this order of likelihood:

1. **Authentication gaps.** If your domain doesn't publish SPF, DKIM, and a DMARC
   policy that *aligns*, mailbox providers can't confirm the mail is really from you —
   so they discount or junk it. This is the #1 cause and the easiest to fix.
2. **Reputation.** Your sending IP or domain has a history of spam complaints, hitting
   spam traps, or sending to dead addresses. Reputation is earned slowly and lost fast.
3. **Content and list hygiene.** Spammy copy, broken HTML, no unsubscribe, or mailing
   people who never opted in.

A posture audit catches #1 immediately and surfaces the structural risks behind #2.

### What's the difference between SPF, DKIM, and DMARC?

They're three layers of "prove this email is really from you":

- **SPF** (Sender Policy Framework) — a DNS record listing which servers are allowed to
  send mail for your domain. Answers *"is this server authorized?"*
- **DKIM** (DomainKeys Identified Mail) — a cryptographic signature on each message,
  verified against a public key in your DNS. Answers *"was this message tampered with,
  and is the signing domain who it claims?"*
- **DMARC** (Domain-based Message Authentication, Reporting & Conformance) — ties SPF
  and DKIM together with *alignment* (the authenticated domain must match the visible
  From: address) and tells receivers what to do when checks fail. Answers *"what should
  happen to mail that fails, and where do I send the reports?"*

You need all three. SPF and DKIM without an enforcing DMARC policy still leaves you
spoofable.

### What is DMARC enforcement — and what's the difference between p=none, p=quarantine, and p=reject?

DMARC's `p=` policy tells receivers how to handle mail that fails authentication:

- **`p=none`** — monitor only. RFC 9989 defines it as the domain owner offering "no
  expression of preference", so a receiver applying DMARC has nothing to act on and
  anyone can still spoof your domain — though the receiver's own filtering still applies.
  Most domains that think they "have DMARC" are here.
- **`p=quarantine`** — asks receivers to treat failures as suspicious.
- **`p=reject`** — asks receivers to reject failing mail outright. Receivers can still
  apply their own local policy either way.

**Which policy you should end on depends on your mail flows, and `reject` is not
automatically the answer.** RFC 9989 §7.4 says domains that host users who might post
to mailing lists **SHOULD NOT** publish `p=reject`, because mail forwarded with an
unmodified `From:` line frequently fails and gets rejected. It also requires that any
domain publishing `p=reject` apply valid DKIM rather than relying on SPF alone. A
dedicated transactional domain faces fewer indirect-mail risks, but should still verify
its actual forwarding and third-party flows rather than assume it has none.

For the domains §7.4 addresses, its advice is `p=none` for at least a month, then
`p=quarantine` for an equally long period, comparing the aggregate-report results before
going further. As of August 2026, Google's bulk-sender guidance permits `p=none`.
Enforcement is primarily an anti-spoofing choice, not a universal deliverability
requirement.

### What is a good DMARC record?

Start every domain here:
`v=DMARC1; p=none; rua=mailto:reports@yourdomain.com`
— an aggregate-report address (`rua=`) so you can actually see who is sending as you.
That is the part no domain should be without, and it is the prerequisite for every
decision below it.

Where you go next is a judgement about your own mail, not a fixed target. Strict
alignment (`adkim=s`, `aspf=s`) and an enforcing policy are the strong end, and
`p=quarantine` is the right next step once your authorized senders are passing. Whether
`p=reject` belongs on a given domain depends on whether it carries general user mail —
see the §7.4 caveats above. Add `ruf=` for forensic reports if your provider supports
them.

---

## Sending readiness

### How do I know if my domain is ready to send cold or scaled outbound?

Valid SPF/DKIM/DMARC records are necessary but **not sufficient**. A few traps:

- **Receive-only domains.** If your domain is set up only to *receive* mail (e.g. via a
  forwarding service), having auth records doesn't make it send-ready.
- **Alignment, not just presence.** Your ESP's mail has to align to *your* domain, not
  the ESP's, or DMARC fails even with SPF and DKIM "present."
- **Don't send cold/scaled outbound from your root domain.** Use a dedicated sending
  subdomain so a reputation hit on cold outreach doesn't poison your primary mail
  (invoices, password resets, replies).

The audit skill flags all three.

### Do I need MTA-STS, TLS-RPT, and DANE?

These are **transport-security** records — they make sure mail to your domain travels
over encrypted, authenticated connections (defeating downgrade and man-in-the-middle
attacks):

- **MTA-STS** — declares "always use TLS to reach me" via an HTTPS-published policy.
- **TLS-RPT** — gives you reports when someone *fails* to connect securely.
- **DANE** — pins your TLS certificate in DNS (and is only trusted when your DNSSEC chain validates).

They aren't a deliverability lever the way DMARC is — your open rates won't jump. But
they're increasingly **required** in regulated, government, and security-conscious
contexts, and they're table stakes for a "we take trust seriously" posture. Treat them
as hardening: do them when the requirement (or the buyer) calls for it.

If the `_mta-sts` TXT lookup fails, the audit reports **“Unable to confirm MTA-STS
policy”** and excludes that bucket from the gap. It reports **“No MTA-STS policy”**
only after an authoritative NXDOMAIN or NOERROR-empty answer. A resolver failure is
not evidence that the policy is missing; re-run the check before changing DNS.

### What is BIMI and is it worth it?

**BIMI** (Brand Indicators for Message Identification) shows your verified logo next to
your emails in supporting inboxes (Gmail, Apple Mail, Yahoo). It requires a strong
DMARC policy (`p=quarantine` or `p=reject`) as a prerequisite, and for the blue
verified checkmark, a VMC (Verified Mark Certificate).

Worth it for brands that send real volume: it lifts recognition and open rates, and the
DMARC prerequisite means adopting BIMI *forces* you into a strong authentication
posture. High value — not just hardening.

---

## Provider rules and the road ahead

### What are the Gmail and Yahoo sender requirements?

Since 2024, Gmail and Yahoo require bulk senders (roughly 5,000+ messages/day to their
users) to: authenticate with SPF **and** DKIM, publish a DMARC policy (at least
`p=none`, with alignment), keep spam complaint rates low (under ~0.3%), and support
one-click unsubscribe **on marketing and subscribed messages** — Google scopes that
requirement to those categories, not to transactional mail. Microsoft has announced similar expectations. These aren't
suggestions — mail that doesn't comply gets throttled or junked. The bar for "set up
correctly" has permanently risen.

### What is DMARCbis?

DMARCbis is the modernized DMARC standard, **published as RFC 9989** (May 2026), which
obsoletes the original DMARC (RFC 7489) and RFC 9091. The original was only Informational;
this is the first Standards-Track DMARC. The changes that matter to operators:

- **A DNS "Tree Walk" replaces the Public Suffix List** for determining organizational
  domains — this changes how alignment and policy discovery work, especially for subdomains.
- **`np=` is new** — a policy for *non-existent* subdomains of **your own** domain (set
  `np=reject` so nobody can send as a subdomain you never created). `sp=` still governs
  existing subdomains. Note what it does **not** do: a lookalike "cousin" domain is a
  separate registration, and no DMARC policy on your domain can reach it.
- **`pct`, `rf`, and `ri` are removed.** Records still using them aren't broken yet, but
  they're no longer spec-conformant — worth cleaning up.

If you run DMARC across subdomains, this is worth acting on now. The audit flags records
that still use removed tags and checks whether your subdomain policy is actually enforced.

### Does email need to be "post-quantum ready"?

Eventually, yes — and the direction of travel is public, though less settled than it is
often made to sound. NIST's draft guidance on the transition (**IR 8547, still an initial
public draft** rather than a final publication) proposes treating today's classical crypto
(RSA-2048, ECC P-256) as deprecated around 2030 and disallowed after 2035. NSA CNSA 2.0
wants PQC for new national-security acquisitions sooner. Treat both as direction, not as
settled mandate. For email this shows up in three places:

- **Transport:** TLS 1.3 is the floor for hybrid post-quantum key exchange
  (`X25519MLKEM768`). A domain still on TLS 1.2 can't adopt PQC transport at all.
- **DKIM signing:** there is as yet **no standardized post-quantum path**. The PQC
  signature schemes (ML-DSA, SLH-DSA) are large relative to what DNS TXT records carry
  comfortably, and the IETF work is early — so the actionable move today is classical
  hygiene, not waiting for a migration. A domain still on **RSA-1024 DKIM** is behind on
  the standard that already exists.
- **DNSSEC** (which DANE and MTA-STS lean on) has its own unsolved PQC signature-size
  problem.

You don't need to act today, but the cheap moves now — get to TLS 1.3, rotate off
RSA-1024 DKIM — are also your PQC head start. Regulated senders should plan first.

---

## About the audit

### What does the amino-deliverability-audit skill check?

Point it at any domain and it inspects the public DNS signals mailbox providers judge
you on: **SPF** (incl. multiple-record, lookup/void limits, the deprecated `ptr`),
**DKIM** (modern vs legacy key strength), **DMARC** (presence, enforcement, alignment,
subdomain policy, reporting, and external-report authorization), **MTA-STS, TLS-RPT,
DANE, BIMI**, and **MX hygiene** — plus the surrounding trust signals: **DNSSEC**, **CAA**,
**reverse DNS / FCrDNS** on your mail server, **domain age / expiry** (newly registered or
about-to-lapse), and **AI-bot readiness** (whether your robots.txt blocks the crawlers
behind ChatGPT/Perplexity). On top of that, forward-readiness against DMARCbis, the
Gmail/Yahoo/Microsoft rules, and the PQC migration. It returns a prioritized,
plain-language plan: what to fix first, and the exact records to publish.

### Do I need DNSSEC, and does it affect email?

DNSSEC cryptographically signs your DNS so the answers — including your mail records —
can't be forged in transit, and it's the prerequisite for DANE. It's more a
security/trust measure than a direct deliverability lever: enable it when a security
review or compliance requirement calls for it, or as part of a strong overall posture.
The audit flags whether your zone is signed (and its answers cryptographically validate).

### Does my domain's age affect deliverability?

Yes. A brand-new domain has no sending reputation, so mailbox providers throttle it by
default — send cold or at volume from a freshly registered domain and much of it lands in
spam. Warm up gradually: start with low volume to engaged recipients and ramp over a few
weeks before scaling. The audit flags a domain that's only days old (and one that's about
to expire — a lapse takes mail *and* the website down).

### Can AI search engines like ChatGPT and Perplexity see my site?

Increasingly people ask AI answer engines about vendors instead of searching, and those
engines use their own crawlers (GPTBot, ClaudeBot, PerplexityBot, OAI-SearchBot,
Google-Extended and others). If your robots.txt blocks them, your site is invisible to
those answers. The audit checks whether your robots.txt is shutting AI crawlers out, so
you can decide which to allow.

### Is it really read-only? Does it change anything?

Yes, fully read-only — though "read" covers a little more than DNS, so here is the whole
list. It queries your public DNS records; it fetches your published MTA-STS policy over
HTTPS (that file is served over HTTPS by design, not DNS); it reads your `robots.txt` to
check AI-crawler visibility; and it looks up your domain's registration date via public
RDAP. All four are public information, and it *drafts* the exact changes for you to
review — it never touches your DNS, sends mail, or needs credentials. Nothing changes
until you choose to apply a fix yourself.

### How is this different from a free DMARC checker?

Most checkers tell you whether a record *exists*. This benchmarks your **whole sending
posture** across all the signals together, weighs them by impact, catches the traps
record-existence misses (alignment, receive-only domains, legacy key strength), and
tells you what to fix *first* — and where you stand on what's coming next. It's the
difference between a syntax check and a diagnosis.

---

_Want this run against your domain — and the fixes monitored and maintained over time?
That's what [Amino](https://hireamino.com) does. Let Amino agents monitor and manage
your email infrastructure._
