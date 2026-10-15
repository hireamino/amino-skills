#!/usr/bin/env node
/**
 * WHI-251 — public DMARC-discovery claims must match observed behaviour.
 *
 * This is the one canonical detector for the published skill and /audit. The
 * site consumes it from its immutable amino-skills checkout; it must not grow a
 * second matcher. Every mode observes the implementation before scanning copy.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SKILLS_ROOT = path.resolve(HERE, "..");
const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i], process.argv[i + 1]);
const surface = args.get("--surface");
const root = path.resolve(args.get("--root") || (surface === "skill" ? SKILLS_ROOT : process.cwd()));

let passed = 0;
let failed = 0;
function check(name, condition, detail = "") {
  if (condition) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}${detail ? ` -> ${detail}` : ""}`);
  }
}

// Written from the claim, not from the exact sentence that exposed it. A
// replacement assertion is acceptable only when the same local context both
// attributes the rule to RFC 9989 and discloses Amino's PSL-bounded divergence.
const REPLACEMENT = [
  /(?:dns\s+)?tree[ -]?walk[\s\S]{0,180}(?:replac(?:e|es|ed)|instead\s+of|rather\s+than)[\s\S]{0,180}(?:public\s+suffix\s+list|\bpsl\b)/i,
  /(?:public\s+suffix\s+list|\bpsl\b)[\s\S]{0,180}(?:replac(?:e|es|ed)\s+by|gives?\s+way\s+to)[\s\S]{0,180}(?:dns\s+)?tree[ -]?walk/i,
  /(?:amino|the\s+audit|we)[\s\S]{0,140}(?:discover|resolve|determine)[\s\S]{0,140}(?:organizational|policy)[\s\S]{0,140}(?:tree[ -]?walk)/i,
  /RFC\s*9989[\s\S]{0,100}tree[ -]?walk[\s\S]{0,240}(?:applicable\s+DMARC\s+record|walking\s+up\s+to\s+the\s+organizational\s+domain|nearest\s+ancestor)/i,
];
const SPEC_ATTRIBUTION = /RFC\s*9989/i;
const AMINO_SUBJECT = /(?:Amino(?:'s)?|this\s+audit|the\s+audit|current\s+implementation|product)/i;
const PSL_BOUND = /(?:PSL|Public\s+Suffix\s+List)[\s\S]{0,100}(?:bound(?:ed|ary)|uses?|remains?|compatib)|(?:uses?|remains?|is|stays?)[\s\S]{0,100}(?:PSL|Public\s+Suffix\s+List)[ -]?bound(?:ed|ary)/i;
const NOT_FULL_WALK = /(?:does\s+not|doesn't|not|has\s+not|hasn't|yet\s+to)[\s\S]{0,100}(?:full(?:y)?[ -]?)?(?:RFC\s*9989[ -]?)?(?:DNS[ -]?)?tree[ -]?walk/i;

export function falseDmarcDiscoveryClaims(text) {
  const findings = [];
  for (const pattern of REPLACEMENT) {
    const matcher = new RegExp(pattern.source, `${pattern.flags}g`);
    for (const match of text.matchAll(matcher)) {
      const start = Math.max(0, match.index - 320);
      const end = Math.min(text.length, match.index + match[0].length + 420);
      const context = text.slice(start, end);
      const bounded = SPEC_ATTRIBUTION.test(context)
        && AMINO_SUBJECT.test(context)
        && (PSL_BOUND.test(context) || NOT_FULL_WALK.test(context));
      if (!bounded) findings.push(match[0].replace(/\s+/g, " ").trim());
    }
  }
  return [...new Set(findings)];
}

const MUST_FLAG = [
  "A DNS Tree Walk replaces the Public Suffix List for determining organizational domains.",
  "We no longer use the PSL; Amino discovers the organizational domain with a DNS tree-walk.",
  "Policy discovery uses RFC 9989's tree walk instead of the Public Suffix List.",
  "The Public Suffix List gives way to a DNS Tree Walk for policy resolution.",
  "RFC 9989 tree walk: use the nearest ancestor policy up to the organizational domain.",
];
const MUST_NOT_FLAG = [
  "RFC 9989 specifies a DNS Tree Walk rather than PSL discovery. Amino's current implementation remains bounded by the pinned Public Suffix List for compatibility with deployed receivers.",
  "The audit uses PSL-bounded organizational-domain discovery and does not claim full RFC 9989 tree-walk compliance.",
  "Amino remains Public Suffix List bounded; RFC 9989's broader DNS Tree Walk is a named compatibility divergence.",
];

function detectorSelfCheck() {
  check(
    `claim detector flags every false formulation (${MUST_FLAG.length})`,
    MUST_FLAG.every((value) => falseDmarcDiscoveryClaims(value).length > 0),
    MUST_FLAG.find((value) => falseDmarcDiscoveryClaims(value).length === 0) || "",
  );
  check(
    `claim detector accepts every bounded formulation (${MUST_NOT_FLAG.length})`,
    MUST_NOT_FLAG.every((value) => falseDmarcDiscoveryClaims(value).length === 0),
    MUST_NOT_FLAG.find((value) => falseDmarcDiscoveryClaims(value).length > 0) || "",
  );
}

function walk(dir, extensions, out = []) {
  for (const entry of readdirSync(dir)) {
    const file = path.join(dir, entry);
    if (statSync(file).isDirectory()) walk(file, extensions, out);
    else if (extensions.has(path.extname(entry))) out.push(file);
  }
  return out;
}

function scan(label, files) {
  check(`${label} scan is non-vacuous`, files.length > 0, "0 files");
  const offenders = files.flatMap((file) =>
    falseDmarcDiscoveryClaims(readFileSync(file, "utf8"))
      .map((claim) => `${path.relative(root, file)}: ${claim}`),
  );
  check(`${label} makes no false tree-walk compliance claim`, offenders.length === 0, offenders.join(" | "));
}

function observePythonSkill() {
  const scripts = path.join(root, "amino-deliverability-audit", "skills", "amino-deliverability-audit", "scripts");
  const program = String.raw`
import json, sys
sys.path.insert(0, sys.argv[1])
import audit
calls = []
audit.confirm_txt = lambda name, prefix: calls.append(name) or None
result = audit.discover_dmarc("tenant.github.io")
print(json.dumps({"base": audit.org_base("tenant.github.io"), "calls": calls, "result": result}))
`;
  const run = spawnSync("python3", ["-c", program, scripts], { encoding: "utf8" });
  check("skill behaviour probe exits cleanly", run.status === 0, (run.stderr || run.stdout).trim());
  if (run.status !== 0) return false;
  let observation;
  try {
    observation = JSON.parse(run.stdout);
  } catch {
    check("skill behaviour probe returns JSON", false, run.stdout.trim());
    return false;
  }
  const own = "_dmarc.tenant.github.io";
  const ancestor = "_dmarc.github.io";
  check("skill identifies the pinned-PSL registrable root", observation.base === "tenant.github.io", observation.base);
  check("skill queries the registrable root's own DMARC name", observation.calls.includes(own), JSON.stringify(observation.calls));
  check("skill makes no ancestor DMARC lookup beyond that root", !observation.calls.includes(ancestor), JSON.stringify(observation.calls));
  return observation.base === "tenant.github.io"
    && observation.calls.includes(own)
    && !observation.calls.includes(ancestor);
}

async function observeWebEngine() {
  const enginePath = path.resolve(process.env.ENGINE || path.join(root, "vendor", "amino-audit-engine", "engine.mjs"));
  const { createAuditEngine } = await import(pathToFileURL(enginePath).href);
  const calls = [];
  const dns = {
    async query(name, type) {
      calls.push([name, type]);
      return [];
    },
    meta() { return { status: 0, error: false }; },
  };
  const engine = createAuditEngine({
    dns,
    http: {
      async mtaSts() { return null; },
      async robots() { return null; },
      async rdap() { return null; },
    },
    clock: { nowMs: () => Date.parse("2026-01-01T00:00:00Z") },
  });
  await engine.auditDomain("tenant.github.io");
  const txtNames = calls.filter(([, type]) => type === "TXT").map(([name]) => name);
  const own = "_dmarc.tenant.github.io";
  const ancestor = "_dmarc.github.io";
  check("web engine queries the registrable root's own DMARC name", txtNames.includes(own), JSON.stringify(txtNames));
  check("web engine makes no ancestor DMARC lookup beyond that root", !txtNames.includes(ancestor), JSON.stringify(txtNames));
  return txtNames.includes(own) && !txtNames.includes(ancestor);
}

async function runSkill() {
  console.log("DMARC discovery claim gate — published skill");
  detectorSelfCheck();
  const established = observePythonSkill();
  if (!established) {
    check("published-skill copy scan may run only after behaviour is established", false);
    return;
  }
  const publishedRoot = path.join(root, "amino-deliverability-audit", "skills", "amino-deliverability-audit");
  const files = [path.join(root, "FAQ.md"), ...walk(publishedRoot, new Set([".md", ".py", ".json", ".txt"]))];
  scan("published skill", files);
}

function jsonLdBlocks(html) {
  return [...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]
    .map((match) => match[1]);
}

async function runWeb() {
  console.log("DMARC discovery claim gate — /audit");
  detectorSelfCheck();
  const established = await observeWebEngine();
  if (!established) {
    check("web copy scan may run only after behaviour is established", false);
    return;
  }

  const routePath = path.join(root, "functions", "audit.js");
  const route = await import(`${pathToFileURL(routePath).href}?claim-gate=${Date.now()}`);
  const response = await route.onRequestGet({ request: new Request("https://hireamino.com/audit"), env: {} });
  const html = await response.text();
  check("/audit form renders successfully", response.status === 200 && html.length > 0, `status=${response.status}, bytes=${html.length}`);

  const blocks = jsonLdBlocks(html);
  check("/audit renders JSON-LD", blocks.length > 0, "0 blocks");
  for (const [index, block] of blocks.entries()) {
    try {
      JSON.parse(block);
      check(`/audit JSON-LD block ${index + 1} is valid JSON`, true);
    } catch (error) {
      check(`/audit JSON-LD block ${index + 1} is valid JSON`, false, error.message);
    }
  }
  const visible = html.replace(/<script\b[\s\S]*?<\/script>/gi, " ");
  const visibleClaims = falseDmarcDiscoveryClaims(visible);
  check("/audit visible HTML makes no false tree-walk compliance claim", visibleClaims.length === 0, visibleClaims.join(" | "));
  const jsonClaims = falseDmarcDiscoveryClaims(blocks.join("\n"));
  check("/audit JSON-LD makes no false tree-walk compliance claim", jsonClaims.length === 0, jsonClaims.join(" | "));

  scan("served JavaScript", walk(path.join(root, "public"), new Set([".js", ".mjs"])));
  scan("/audit route source", [routePath]);
}

if (surface === "skill") await runSkill();
else if (surface === "web") await runWeb();
else {
  console.error("usage: dmarc-discovery-claims.mjs --surface skill|web [--root PATH]");
  process.exit(2);
}

console.log(`DMARC discovery claim gate: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
