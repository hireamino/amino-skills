#!/usr/bin/env node
/**
 * Findings-coverage parity — the structural guard against skill↔web divergence.
 *
 * The bucket harness (parity.mjs) proves the two implementations SCORE the same 9
 * buckets. It does NOT see the findings layer — the advisory checks that render as
 * the 2x2 card's action bullets. That layer is where the two surfaces silently drifted
 * (the web tool grew 7 checks the skill's audit.py never got).
 *
 * This harness closes that gap WITHOUT live network or per-domain flakiness: it statically
 * extracts, from BOTH scripts/audit.py and amino-site/functions/audit.js,
 *   (1) the set of check AREAS the findings use, and
 *   (2) the set of canonical ACTION labels the action() mapper can emit,
 * and asserts the two sets are identical. Adding a check to one surface always adds a
 * new area and/or action label — so a one-sided change fails this check. Run it in CI on
 * both repos; it exits non-zero on any asymmetry.
 *
 *   node web-parity/inventory.mjs            # compare + report
 *   node web-parity/inventory.mjs --list     # also print both full inventories
 *
 * Layout assumed (same as parity.mjs): this skill repo and `amino-site` are siblings.
 */
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// Paths default to the sibling-repo dev layout; CI overrides via env (the web tool lives
// in a separate private repo, so the gate runs where both files are reachable).
const PY = process.env.PARITY_PY || resolve(here, "../scripts/audit.py");
const JS = process.env.PARITY_JS || resolve(here, "../../amino-site/functions/audit.js");

// STARTTLS live-probe findings are skill-only BY DESIGN (the edge can't open a :25
// socket, so the web port drops them). Exclude them from the symmetric comparison.
const SKILL_ONLY_LABELS = new Set(["Confirm STARTTLS on the mail server"]);

// ── area inventory: every distinct `area=`/`area:` value a finding is tagged with ──
function areas(src, re) {
  const s = new Set();
  for (const m of src.matchAll(re)) s.add(m[1]);
  return s;
}

// ── action-label inventory: the string literals action() can RETURN. Strip the
//    match fragments first (`.includes("x")`, `=== "x"`, `"x" in t`, f["title"]) so only
//    the returned labels remain, then collect the quoted literals. ──
function jsActionLabels(src) {
  const start = src.search(/function action\s*\(/);
  const body = src.slice(start).split(/\n(?:function |const |export )/)[0];
  const cleaned = body
    .replace(/\.includes\(\s*"[^"]*"\s*\)/g, "")
    .replace(/===\s*"[^"]*"/g, "")
    .replace(/f\.title|f\.area|f\.severity/g, "");
  return new Set([...cleaned.matchAll(/"([^"]+)"/g)].map((m) => m[1]));
}

function pyActionLabels(src) {
  const start = src.search(/def action\s*\(/);
  const body = src.slice(start).split(/\ndef /)[0];
  const cleaned = body
    .replace(/"""[\s\S]*?"""/g, "")     // drop the docstring (triple-quotes skew pairing)
    .replace(/#.*$/gm, "")              // drop line comments
    .replace(/"[^"]*"\s+in\s+t/g, "")   // match fragments: "x" in t
    .replace(/f\.get\(\s*"[^"]*"\s*\)/g, "")
    .replace(/f\["[^"]*"\]/g, "")
    .replace(/==\s*"[^"]*"/g, "");
  // every action() label is double-quoted; single-quoted strings are only fragments.
  return new Set([...cleaned.matchAll(/"([^"]+)"/g)].map((m) => m[1]));
}

function diff(a, b) {
  const onlyA = [...a].filter((x) => !b.has(x)).sort();
  const onlyB = [...b].filter((x) => !a.has(x)).sort();
  return { onlyA, onlyB };
}

const pySrc = readFileSync(PY, "utf8");
const jsSrc = readFileSync(JS, "utf8");

const pyAreas = areas(pySrc, /area="([^"]+)"/g);
const jsAreas = areas(jsSrc, /area:\s*"([^"]+)"/g);
let pyLabels = pyActionLabels(pySrc);
let jsLabels = jsActionLabels(jsSrc);

// Drop the skill-only STARTTLS label from BOTH before comparing (it legitimately exists
// as a source literal in both files; the asymmetry is in emission, not coverage).
for (const l of SKILL_ONLY_LABELS) { pyLabels.delete(l); jsLabels.delete(l); }

if (process.argv.includes("--list")) {
  console.log("PY areas :", [...pyAreas].sort().join(", "));
  console.log("JS areas :", [...jsAreas].sort().join(", "));
  console.log("PY labels:", [...pyLabels].sort().join(" | "));
  console.log("JS labels:", [...jsLabels].sort().join(" | "));
  console.log("");
}

const aDiff = diff(pyAreas, jsAreas);
const lDiff = diff(pyLabels, jsLabels);
let ok = true;

function report(name, d) {
  if (d.onlyA.length || d.onlyB.length) {
    ok = false;
    console.log(`✗ ${name} DIVERGE:`);
    if (d.onlyA.length) console.log(`    skill-only (audit.py): ${d.onlyA.join(" | ")}`);
    if (d.onlyB.length) console.log(`    web-only   (audit.js): ${d.onlyB.join(" | ")}`);
  } else {
    console.log(`✓ ${name} match (${name === "AREAS" ? pyAreas.size : pyLabels.size})`);
  }
}

report("AREAS", aDiff);
report("ACTION LABELS", lDiff);

if (ok) {
  console.log("\n✅ findings inventory in lockstep — skill and web tool cover the same checks");
  process.exit(0);
} else {
  console.log("\n❌ findings drift — a check exists on one surface but not the other");
  process.exit(1);
}
