# WHI-215 Step 1 — measured baseline

This is a report, not an adoption. The generated artifact is not imported by any
shipping surface in this change.

## Canonical input

- URL: `https://publicsuffix.org/list/public_suffix_list.dat`
- VERSION: `2026-10-01_23-02-52_UTC`
- COMMIT: `6cd82aff889e3d64e5e03bc5c1f43da1934a960a`
- Source SHA-256: `e0fe072d26b0536525badea237953ff451c9f8e64c9d02c6daa81a4491d2fc66`
- Artifact SHA-256: `c16d8b621302b8b5c04ad7c6378494e5aec55e8017f87c4e9fc82efe61e1c7cf`
- Rules: 6949 ICANN + 3384 PRIVATE = 10333 total
- Rules converted from Unicode to A-label form: 459

The canonical source advanced after the Product Lead's September 24 measurement:
the earlier source was 334,786 bytes / 10,334 rules; the fetched October 1 source
is 334,734 bytes / 10,333 rules. The generator therefore pins the
newer canonical VERSION and COMMIT rather than silently reproducing a stale snapshot.

## Official-vector score of the three existing hand-written tables

| Existing implementation | Revision | Passed | Failed |
|---|---|---:|---:|
| skill | `amino-skills 24faecb4f0db092bfd853319b6cf66b5834073d2` | 28 | 50 |
| engine | `amino-audit-engine 41abd12470ccaa43564f8d8c9c1e350fed9d922c` | 28 | 50 |
| monitor | `amino-monitor 91faa30bdc4b7f0721b81d9a2b7123175223cf01` | 26 | 52 |

### skill failures

- **invalid/null input boundary (5):** `null`, `.com`, `.example`, `.example.com`, `.example.example`
- **public-suffix boundary (6):** `COM`, `example`, `biz`, `com`, `jp`, `us`
- **missing multi-label suffix (16):** `uk.com`, `example.uk.com`, `b.example.uk.com`, `a.b.example.uk.com`, `ac.jp`, `kyoto.jp`, `test.kyoto.jp`, `ide.kyoto.jp`, `b.ide.kyoto.jp`, `a.b.ide.kyoto.jp`, `ak.us`, `test.ak.us`, `www.test.ak.us`, `k12.ak.us`, `test.k12.ak.us`, `www.test.k12.ak.us`
- **wildcard rule (11):** `mm`, `c.mm`, `b.c.mm`, `a.b.c.mm`, `c.kobe.jp`, `b.c.kobe.jp`, `a.b.c.kobe.jp`, `ck`, `test.ck`, `b.test.ck`, `a.b.test.ck`
- **exception rule (2):** `city.kobe.jp`, `www.city.kobe.jp`
- **IDN / A-label rule (10):** `食狮.公司.cn`, `www.食狮.公司.cn`, `shishi.公司.cn`, `公司.cn`, `中国`, `xn--85x722f.xn--55qx5d.cn`, `www.xn--85x722f.xn--55qx5d.cn`, `shishi.xn--55qx5d.cn`, `xn--55qx5d.cn`, `xn--fiqs8s`

### engine failures

- **invalid/null input boundary (5):** `null`, `.com`, `.example`, `.example.com`, `.example.example`
- **public-suffix boundary (6):** `COM`, `example`, `biz`, `com`, `jp`, `us`
- **missing multi-label suffix (16):** `uk.com`, `example.uk.com`, `b.example.uk.com`, `a.b.example.uk.com`, `ac.jp`, `kyoto.jp`, `test.kyoto.jp`, `ide.kyoto.jp`, `b.ide.kyoto.jp`, `a.b.ide.kyoto.jp`, `ak.us`, `test.ak.us`, `www.test.ak.us`, `k12.ak.us`, `test.k12.ak.us`, `www.test.k12.ak.us`
- **wildcard rule (11):** `mm`, `c.mm`, `b.c.mm`, `a.b.c.mm`, `c.kobe.jp`, `b.c.kobe.jp`, `a.b.c.kobe.jp`, `ck`, `test.ck`, `b.test.ck`, `a.b.test.ck`
- **exception rule (2):** `city.kobe.jp`, `www.city.kobe.jp`
- **IDN / A-label rule (10):** `食狮.公司.cn`, `www.食狮.公司.cn`, `shishi.公司.cn`, `公司.cn`, `中国`, `xn--85x722f.xn--55qx5d.cn`, `www.xn--85x722f.xn--55qx5d.cn`, `shishi.xn--55qx5d.cn`, `xn--55qx5d.cn`, `xn--fiqs8s`

### monitor failures

- **invalid/null input boundary (5):** `null`, `.com`, `.example`, `.example.com`, `.example.example`
- **public-suffix boundary (6):** `COM`, `example`, `biz`, `com`, `jp`, `us`
- **missing multi-label suffix (18):** `uk.com`, `example.uk.com`, `b.example.uk.com`, `a.b.example.uk.com`, `ac.jp`, `test.ac.jp`, `www.test.ac.jp`, `kyoto.jp`, `test.kyoto.jp`, `ide.kyoto.jp`, `b.ide.kyoto.jp`, `a.b.ide.kyoto.jp`, `ak.us`, `test.ak.us`, `www.test.ak.us`, `k12.ak.us`, `test.k12.ak.us`, `www.test.k12.ak.us`
- **wildcard rule (11):** `mm`, `c.mm`, `b.c.mm`, `a.b.c.mm`, `c.kobe.jp`, `b.c.kobe.jp`, `a.b.c.kobe.jp`, `ck`, `test.ck`, `b.test.ck`, `a.b.test.ck`
- **exception rule (2):** `city.kobe.jp`, `www.city.kobe.jp`
- **IDN / A-label rule (10):** `食狮.公司.cn`, `www.食狮.公司.cn`, `shishi.公司.cn`, `公司.cn`, `中国`, `xn--85x722f.xn--55qx5d.cn`, `www.xn--85x722f.xn--55qx5d.cn`, `shishi.xn--55qx5d.cn`, `xn--55qx5d.cn`, `xn--fiqs8s`

### Disagreements between today's implementations

| Case | Input | Skill | Engine | Monitor |
|---:|---|---|---|---|
| 1 | `null` | `{"error": "AttributeError"}` | `{"error": "TypeError"}` | `` |
| 5 | `.com` | `com` | `com` | `.com` |
| 6 | `.example` | `example` | `example` | `.example` |
| 34 | `test.ac.jp` | `test.ac.jp` | `test.ac.jp` | `ac.jp` |
| 35 | `www.test.ac.jp` | `test.ac.jp` | `test.ac.jp` | `ac.jp` |

## Size measurement

Gzip uses level 9 with `mtime=0`. Section rows are the exact tagged A-label rows
inside the shipped artifact; the combined row is the complete artifact including
its MPL notice and provenance-identifying header.

| Payload | Bytes | Gzip bytes |
|---|---:|---:|
| ICANN tagged A-label rows | 119,306 | 28,137 |
| PRIVATE tagged A-label rows | 96,265 | 17,524 |
| Shipped combined artifact | 216,020 | 46,376 |
| Canonical full upstream source (comments included) | 334,734 | 90,185 |
| Current Action vendored engine | 73,620 | 22,737 |

For comparison, the converted rule text without section tags is
77,612 bytes ICANN and 69,193 bytes PRIVATE.
If the public Action later vendors this artifact as a separate file, its raw
payload grows by 216,020 bytes, from 73,620 to 289,640
bytes before other package overhead (gzip delta: 46,376 bytes when compressed separately).
The full list is intentional: excluding PRIVATE rules would allow a claim such as
`foo.github.io` to collapse to `github.io`, which violates the one-registrable-root invariant.

## Measurement method

`run_vectors.py` parsed all 78 active upstream cases without filtering. The skill
adapter imported the reviewed Python `org_base`; the engine adapter executed the
private `orgBase` from the 1.5.0 artifact; and the monitor adapter extracted the one
`regDomain` function from Watchtower main. The reference lookup built from the new
artifact passed 78/78, including longest-match, wildcard, exception, Unicode, and
A-label cases. The score above records errors as outputs rather than normalizing them.
