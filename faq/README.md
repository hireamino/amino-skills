# Canonical `/audit` FAQ

`audit-faq.json` is the ordered, canonical source for the 14 FAQ entries that
`hireamino.com/audit` renders as visible HTML and FAQPage JSON-LD. The site adoption
lands with the next consumer repin; once adopted, the site must not hand-copy these
answers.

The consumer checks out `amino-skills` at its immutable skills pin, then runs:

```sh
node "$SKILLS_DIR/faq/generate-audit-faq.mjs" --target functions/audit.js
node "$SKILLS_DIR/faq/generate-audit-faq.mjs" --target functions/audit.js --check
```

Generation happens before deployment and the generated block is committed with that
consumer pin. There is no runtime fetch. `--check` fails closed when either the generated
block is hand-edited or the pinned artifact changes without regeneration.

The public DMARC-discovery claim gate scans the artifact itself. Its mutation canary
proves that a false claim introduced here fails the same behavior-backed copy gate as
the longer `FAQ.md`.
