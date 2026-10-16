#!/usr/bin/env node
/**
 * Golden-set parity harness — keeps the web tool's JS port in lockstep with the skill.
 *
 * Diffs the edge JS `buckets()` (DoH, in amino-site/functions/audit.js) against the
 * Python `batch_score.py` (dig) — the canonical Y/N bucket scorer. These 9 buckets and
 * their three named lane counts are exactly the DNS-derivable, edge-safe subset (no live
 * STARTTLS), so a JS↔Python diff is a real LOGIC divergence. Run this after editing EITHER
 * the skill's check logic or the web port; it exits non-zero on any mismatch.
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
import {
  copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// Defaults = sibling-repo dev layout; CI overrides via env (web tool is a separate repo).
const SCRIPTS = process.env.PARITY_SCRIPTS || resolve(here, "../scripts");
const WEB_FN = process.env.PARITY_JS || resolve(here, "../../amino-site/functions/audit.js");

// The function is plain .js with ES `export`; copy to a .mjs so Node imports it as ESM.
const temporary = mkdtempSync(join(tmpdir(), "amino-audit-parity-"));
const tmp = join(temporary, "audit.mjs");
writeFileSync(tmp, readFileSync(WEB_FN));
const metrics = join(dirname(WEB_FN), "_metrics.mjs");
if (existsSync(metrics)) copyFileSync(metrics, join(temporary, "_metrics.mjs"));
let buckets;
try {
  ({ buckets } = await import(tmp));
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

const DOMAINS = process.argv.slice(2).length ? process.argv.slice(2) : [
  "hireamino.com", "whiteboard.vc", "google.com", "microsoft.com", "github.com",
  "cloudflare.com", "fanatics.com", "stripe.com", "paypal.com", "amazon.com",
  "example.com", "apple.com", "salesforce.com", "mailchimp.com",
];

const COLS = ["SPF", "DKIM", "DMARC", "DMARC_enforced", "DMARC_rua", "MTA_STS", "TLS_RPT", "DANE", "BIMI"];
const LANE_COLUMNS = {
  Outbound_gaps: ["SPF", "DKIM", "DMARC", "DMARC_enforced", "DMARC_rua"],
  Inbound_gaps: ["MTA_STS", "TLS_RPT", "DANE"],
  Brand_gaps: ["BIMI"],
};
const disp = (r, k) => {
  if (k === "DKIM") return ({ good: "Y", weak: "N", invalid: "N", unknown: "—" }[r.DKIM]);
  if (r[k] === null) return "—";
  return r[k] ? "Y" : "N";
};
const laneGap = (r, buckets) => {
  const cells = buckets.map((key) => disp(r, key));
  return cells.every((cell) => cell === "—") ? "—" : String(cells.filter((cell) => cell === "N").length);
};

const tsv = execFileSync("python3", ["batch_score.py", ...DOMAINS.map((d) => `${d}=${d}`)],
  { cwd: SCRIPTS, encoding: "utf8" });
const golden = {};
const lines = tsv.trim().split("\n");
const header = lines[0].split("\t");
if (header.includes("Gap")) throw new Error("batch output still exposes the retired blended Gap column");
for (const line of lines.slice(1)) {
  const f = line.split("\t");
  const row = Object.fromEntries(header.map((name, index) => [name, f[index]]));
  golden[row.Domain] = {
    cells: COLS.map((name) => row[name]),
    lanes: Object.fromEntries(Object.keys(LANE_COLUMNS).map((name) => [name, row[name]])),
  };
}

let diffs = 0;
console.log("domain".padEnd(22), COLS.map((c) => c.slice(0, 4)).join(" "), " out in br verdict");
for (const d of DOMAINS) {
  const js = await buckets(d);
  const jsCells = COLS.map((k) => disp(js, k));
  const jsLanes = Object.fromEntries(
    Object.entries(LANE_COLUMNS).map(([name, laneBuckets]) => [name, laneGap(js, laneBuckets)]),
  );
  const g = golden[d];
  const ok = g
    && jsCells.every((v, i) => v === g.cells[i])
    && Object.keys(LANE_COLUMNS).every((name) => jsLanes[name] === g.lanes[name]);
  if (!ok) diffs++;
  console.log(
    d.padEnd(22), jsCells.join("    "),
    jsLanes.Outbound_gaps.padStart(3), jsLanes.Inbound_gaps.padStart(2),
    jsLanes.Brand_gaps.padStart(2), ok ? " OK" : " ❌ DIFF",
  );
  if (!ok && g) {
    console.log("   JS    :", jsCells.join(" "), jsLanes);
    console.log("   Python:", g.cells.join(" "), g.lanes);
  }
}
console.log("\n" + (diffs === 0 ? `✅ 0-DIFF across ${DOMAINS.length} domains` : `❌ ${diffs} domain(s) diverged`));
process.exit(diffs === 0 ? 0 : 1);
