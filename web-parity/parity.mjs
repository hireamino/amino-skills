#!/usr/bin/env node
/**
 * Golden-set parity harness — keeps the web tool's JS port in lockstep with the skill.
 *
 * Diffs the edge JS `buckets()` (DoH, in amino-site/functions/audit.js) against the
 * Python `batch_score.py` (dig) — the canonical Y/N bucket scorer. These 9 buckets are
 * exactly the DNS-derivable, edge-safe subset (no live STARTTLS), so a JS↔Python diff is
 * a real LOGIC divergence. Run this after editing EITHER the skill's check logic or the
 * web port; it exits non-zero on any mismatch.
 *
 *   node web-parity/parity.mjs                 # default domain set
 *   node web-parity/parity.mjs a.com b.com     # custom domains
 *
 * Layout assumed: this skill repo and `amino-site` are siblings under the same parent
 * (…/Projects/amino-deliverability-audit and …/Projects/amino-site). Needs `dig` + python3
 * locally and outbound DoH (cloudflare-dns.com) for the JS side.
 *
 * Resolver note: batch_score.py uses `dig` (system resolver) and the JS side uses
 * Cloudflare DoH. verify.py already proves the scanner is 0-DIFF across Google+Cloudflare
 * resolvers, so a divergence here is logic, not resolver. If you ever want to fully
 * eliminate the resolver as a variable, pin dig to @1.1.1.1 in scripts/resolver.py for
 * the run.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// Defaults = sibling-repo dev layout; CI overrides via env (web tool is a separate repo).
const SCRIPTS = process.env.PARITY_SCRIPTS || resolve(here, "../scripts");
const WEB_FN = process.env.PARITY_JS || resolve(here, "../../amino-site/functions/audit.js");

// The function is plain .js with ES `export`; copy to a .mjs so Node imports it as ESM.
const tmp = join(tmpdir(), "amino_audit_web.mjs");
writeFileSync(tmp, readFileSync(WEB_FN));
const { buckets } = await import(tmp);

const DOMAINS = process.argv.slice(2).length ? process.argv.slice(2) : [
  "hireamino.com", "whiteboard.vc", "google.com", "microsoft.com", "github.com",
  "cloudflare.com", "fanatics.com", "stripe.com", "paypal.com", "amazon.com",
  "example.com", "apple.com", "salesforce.com", "mailchimp.com",
];

const COLS = ["SPF", "DKIM", "DMARC", "DMARC_enforced", "DMARC_rua", "MTA_STS", "TLS_RPT", "DANE", "BIMI"];
const disp = (r, k) => k === "DKIM" ? ({ good: "Y", weak: "N", unknown: "—" }[r.DKIM]) : (r[k] ? "Y" : "N");

const tsv = execFileSync("python3", ["batch_score.py", ...DOMAINS.map((d) => `${d}=${d}`)],
  { cwd: SCRIPTS, encoding: "utf8" });
const golden = {};
for (const line of tsv.trim().split("\n").slice(1)) {
  const f = line.split("\t");
  golden[f[1]] = { cells: f.slice(2, 2 + COLS.length), gap: f[2 + COLS.length] };
}

let diffs = 0;
console.log("domain".padEnd(22), COLS.map((c) => c.slice(0, 4)).join(" "), " gap  verdict");
for (const d of DOMAINS) {
  const js = await buckets(d);
  const jsCells = COLS.map((k) => disp(js, k));
  const g = golden[d];
  const ok = g && jsCells.every((v, i) => v === g.cells[i]) && String(js.gap) === g.gap;
  if (!ok) diffs++;
  console.log(d.padEnd(22), jsCells.join("    "), String(js.gap).padStart(3), ok ? " OK" : " ❌ DIFF");
  if (!ok && g) {
    console.log("   JS    :", jsCells.join(" "), "gap", js.gap);
    console.log("   Python:", g.cells.join(" "), "gap", g.gap);
  }
}
console.log("\n" + (diffs === 0 ? `✅ 0-DIFF across ${DOMAINS.length} domains` : `❌ ${diffs} domain(s) diverged`));
process.exit(diffs === 0 ? 0 : 1);
