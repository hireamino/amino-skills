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

// This is deliberately an allowlist, not a clever claim regex. Any public
// sentence using the sensitive trigger term must be reviewed and added here.
// That makes adjacency, negation and new assertion forms fail closed.
const TREE_WALK = /\btree(?:\s|[-‐‑‒–—])+walk/i;

function normalizeSentence(value) {
  return value
    .replace(/<[^>]*>/g, " ")
    .replace(/&(?:nbsp|#160);/gi, " ")
    .replace(/&quot;|&#34;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&amp;/gi, "&")
    .replace(/\\(["'])/g, "$1")
    .replace(/\*\*|__|`/g, "")
    .replace(/^\s*(?:[-#>*]+\s*)+/, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

const APPROVED_TREE_WALK_SENTENCES = new Set([
  "RFC 9989 specifies a DNS Tree Walk instead of Public Suffix List discovery.",
  "This is a deliberate compatibility divergence, not a claim of full RFC 9989 tree-walk compliance.",
  "RFC 9989 specifies a broader DNS Tree Walk; this compatibility implementation deliberately does not cross the PSL boundary.",
  "No _dmarc at this subdomain: it inherits the org domain's policy — the sp (subdomain policy) tag if set, otherwise p (RFC 9989 tree walk).",
  "RFC 9989 replaced Public-Suffix-List org-domain discovery with a live DNS Tree Walk (it depends on where DMARC records + psd= tags actually exist), which an offline tool can't reproduce.",
  'This heuristic is good enough for relaxed-alignment previews; a true tree-walk needs a live DNS lookup (future "live domain" mode).',
].map(normalizeSentence));

function treeWalkSentences(text) {
  const lines = text
    .replace(/<[^>]*>/g, " ")
    .replace(/\\n/g, "\n")
    .replace(/\*\*|__|`/g, "")
    .split(/\r?\n/);
  const blocks = [];
  let current = [];
  let currentKind = null;
  function flush() {
    if (current.length) blocks.push(current.join(" "));
    current = [];
    currentKind = null;
  }
  for (const line of lines) {
    if (!line.trim()) {
      flush();
      continue;
    }
    const listItem = line.match(/^\s*(?:[-*+]|\d+\.)\s+(.*)$/);
    if (listItem) {
      flush();
      currentKind = "prose";
      current.push(listItem[1]);
      continue;
    }
    const comment = line.match(/^\s*(\/\/|#)\s?(.*)$/);
    const kind = comment ? `comment:${comment[1]}` : "prose";
    if (currentKind && currentKind !== kind) flush();
    currentKind = kind;
    current.push(comment ? comment[2] : line.trim());
  }
  flush();
  return blocks
    .map(normalizeSentence)
    .flatMap((block) => block.split(/(?<=[.!?])\s+/))
    .filter((sentence) => TREE_WALK.test(sentence));
}

export function falseDmarcDiscoveryClaims(text) {
  return [...new Set(
    treeWalkSentences(text).filter((sentence) => !APPROVED_TREE_WALK_SENTENCES.has(sentence)),
  )];
}

const MUST_FLAG = [
  "A DNS Tree Walk replaces the Public Suffix List for determining organizational domains.",
  "The audit follows the complete DMARCbis tree-walk when locating organization policy.",
  "The product switched from PSL boundaries to a DNS tree walk.",
  "Amino uses RFC 9989's tree walk and is not PSL-bounded.",
  "RFC 9989 specifies a DNS Tree Walk instead of Public Suffix List discovery. In Amino, a DNS tree walk now replaces the PSL boundary.",
  "The audit follows the RFC 9989 DNS tree\nwalk all the way to the root.",
  "The implementation now follows DMARCbis without qualification:\nRFC 9989 specifies a DNS Tree Walk instead of Public Suffix List discovery.",
  "We support complete organizational discovery by tree-walking DNS under RFC 9989.",
  "The resolver tree walks through every parent label under DMARCbis.",
];
const MUST_NOT_FLAG = [
  "RFC 9989 specifies a DNS Tree Walk instead of Public Suffix List discovery.",
  "This is a deliberate compatibility divergence, not a claim of full RFC 9989 tree-walk compliance.",
  "RFC 9989 specifies a broader DNS Tree Walk; this compatibility implementation deliberately does not cross the PSL boundary.",
  "No _dmarc at this subdomain: it inherits the org domain's policy — the sp (subdomain policy) tag if set, otherwise p (RFC 9989 tree walk).",
  "RFC 9989 replaced Public-Suffix-List org-domain discovery with a live DNS Tree Walk (it depends on where DMARC records + psd= tags actually exist), which an offline tool can't reproduce.",
  'This heuristic is good enough for relaxed-alignment previews; a true tree-walk needs a live DNS lookup (future "live domain" mode).',
  "Amino's audit remains bounded at the registrable domain from its pinned Public Suffix List.",
  "RFC 9989 specifies a DNS Tree Walk instead of\nPublic Suffix List discovery.",
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
