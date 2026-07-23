#!/usr/bin/env node
/**
 * Unified conformance runner for the JS surfaces (WS1/WS5).
 *
 * Drives the SHARED fixtures.json corpus through a real JS audit engine with a mock
 * resolver (no network) and asserts each fixture's `expect`. One corpus, every surface:
 * point ENGINE at src/engine.mjs (the Action) or functions/audit.js (the web tool) and
 * the same cases are enforced. This is the gate that makes three-way parity load-bearing
 * — add a fixture once, all surfaces must pass it.
 *
 *   ENGINE=../amino-audit-action/src/engine.mjs node conformance/run.mjs
 *   ENGINE=../amino-site/functions/audit.js       node conformance/run.mjs
 *
 * Exits non-zero on any failure. Non-dns-engine fixtures are logged SKIPPED with a
 * reason (no silent caps) — they're covered by per-surface pure-function checks or are
 * v1.3 (DANE/DNSSEC/resolver-level).
 */
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ENGINE = process.env.ENGINE || resolve(here, "../../amino-site/functions/audit.js");
const { auditDomain } = await import(pathToFileURL(resolve(ENGINE)).href);
const { fixtures } = JSON.parse(readFileSync(resolve(here, "fixtures.json"), "utf8"));

// Mock q(name, type) from a fixture's `dns`. Supports a `*._domainkey.<domain>` wildcard
// (DKIM has no discovery, so a fixture shouldn't have to enumerate probed selectors).
function mockQ(dns) {
  const norm = (n) => n.replace(/\.+$/, "").toLowerCase();
  const map = {};
  for (const [k, v] of Object.entries(dns || {})) map[norm(k)] = v;
  return async (name, type) => {
    name = norm(name);
    if (map[name] && map[name][type]) return map[name][type];
    for (const k of Object.keys(map)) {
      if (k.startsWith("*._domainkey.") && name.endsWith(k.slice(1)) && map[k][type]) return map[k][type];
    }
    return [];
  };
}

let pass = 0, fail = 0, skip = 0;
const fails = [];

for (const fx of fixtures) {
  if (fx.mode !== "dns-engine") {
    skip++;
    console.log(`  SKIP  ${fx.id} (${fx.invariant}) — ${fx.skip_reason || fx.mode}`);
    continue;
  }
  let findings;
  try {
    findings = (await auditDomain(fx.input.domain, mockQ(fx.input.dns))).findings || [];
  } catch (e) {
    fail++; fails.push(`${fx.id}: threw ${e && e.message}`);
    console.log(`  FAIL  ${fx.id} (${fx.invariant}) — threw ${e && e.message}`);
    continue;
  }
  const titles = findings.map((f) => `${f.area}:${f.title}`);
  const problems = [];
  for (const p of fx.expect.present || []) {
    if (!findings.some((f) => f.area === p.area && f.title.includes(p.includes))) {
      problems.push(`missing present [${p.area} ~ "${p.includes}"]`);
    }
  }
  for (const a of fx.expect.absent || []) {
    if (titles.some((t) => t.includes(a))) problems.push(`unexpected absent-match "${a}"`);
  }
  if (problems.length) {
    fail++; fails.push(`${fx.id}: ${problems.join("; ")}`);
    console.log(`  FAIL  ${fx.id} (${fx.invariant}) — ${problems.join("; ")}`);
  } else {
    pass++;
    console.log(`  PASS  ${fx.id} (${fx.invariant})`);
  }
}

console.log(`\nEngine: ${ENGINE}`);
console.log(`Results: ${pass} passed, ${fail} failed, ${skip} skipped.`);
process.exit(fail ? 1 : 0);
