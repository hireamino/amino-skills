# Pinned Public Suffix List

This directory is the reviewed source of truth for the question “which part of
this DNS name is registrable?” It contains the full Public Suffix List—ICANN and
PRIVATE sections—with every row tagged by section and converted to A-label form
at generation time.

The Python audit skill consumes a byte-identical sibling copy of this artifact;
the canonical JavaScript engine embeds the same reviewed bytes so it remains a
single-file artifact. Both shipping lookups are release-blocked by the official
vectors and their own fallback mutation canary. Consumer adoption remains staged:
the console follows, then Watchtower deletes its smaller `MULTI_TLD` table.

## Files

- `public_suffix_rules.tsv` — generated data. Never hand-edit it.
- `provenance.json` — canonical source identity, fetch time, counts, and the
  artifact SHA-256. A hand edit breaks the offline integrity gate.
- `test_psl.txt` — the upstream project’s official CC0 test vectors.
- `generate.py` — deterministic generator. It fetches only the canonical URL,
  validates the complete source and both sections, and refuses an unencodable rule.
- `run_vectors.py` — a language-neutral JSON-command runner plus the test-only
  reference lookup used to prove the artifact against all 78 official cases.
- `freshness.py` — the networked comparison used only by the weekly workflow.

## Licensing and downstream attribution

The Public Suffix List is distributed under the Mozilla Public License 2.0. The
three-line MPL notice from upstream is retained verbatim at the start of the
generated artifact. The official test vectors retain their CC0 dedication.

Any later consumer—including the public `amino-audit-action` repository—must copy
the artifact byte-for-byte together with `provenance.json`, retain the MPL notice,
and include attribution pointing to `https://publicsuffix.org/list/` and the MPL
2.0. The engine's generated embedding is the sole exception needed to preserve its
one-file distribution contract; it is verified byte-for-byte against this artifact.
A consumer must not maintain a second editable table.

## Refresh

The weekly `public-suffix-freshness` workflow reports added and removed tagged
rules. A reviewed refresh runs `generate.py`, verifies the new provenance and all
78 official vectors, and lands as an ordinary pull request. Offline conformance
never runs the freshness fetch and its network kill switch is unchanged.
