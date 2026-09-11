#!/usr/bin/env node
/**
 * Mutation canaries for the JavaScript conformance runner.
 *
 * Each case changes one material contract field in a throwaway engine (or stubs
 * the runner comparison itself) and requires run.mjs to fail with the fixture
 * and field named. The shipping engine and corpus are never modified.
 */
import {
  mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const runner = resolve(here, "run.mjs");
const enginePath = resolve(process.env.ENGINE || "");
const surface = process.env.SURFACE;
if (!enginePath || !["web", "action"].includes(surface)) {
  console.error("ENGINE and SURFACE=web|action are required");
  process.exit(2);
}

const originalEngine = readFileSync(enginePath, "utf8");
const portableEngine = originalEngine.replace(
  'import { record } from "./_metrics.mjs";',
  "const record = () => {};",
);
const temporary = mkdtempSync(join(tmpdir(), `amino-whi8-${surface}-`));
writeFileSync(
  join(temporary, "fixtures.json"),
  readFileSync(resolve(here, "fixtures.json"), "utf8"),
);
let passed = 0;
let failed = 0;

function replaceExactlyOnce(source, from, to, name) {
  const first = source.indexOf(from);
  const second = first < 0 ? -1 : source.indexOf(from, first + from.length);
  if (first < 0 || second >= 0) {
    throw new Error(`${name}: mutation anchor must occur exactly once (found ${first < 0 ? 0 : 2})`);
  }
  return source.slice(0, first) + to + source.slice(first + from.length);
}

function execute(engineSource, fixture, runnerPath = runner) {
  const mutant = join(temporary, `${basename(enginePath).replace(/\.[^.]+$/, "")}-mutant.mjs`);
  writeFileSync(mutant, engineSource);
  return spawnSync(process.execPath, [runnerPath], {
    encoding: "utf8",
    env: {
      ...process.env,
      ENGINE: mutant,
      SURFACE: surface,
      CONFORMANCE_FIXTURE: fixture,
    },
  });
}

function expectRed(name, source, fixture, expectedText, runnerPath = runner) {
  const result = execute(source, fixture, runnerPath);
  const output = (result.stdout || "") + (result.stderr || "");
  const ok = result.status !== 0 && output.includes(expectedText);
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}`
      + (ok ? ` — ${expectedText}` : `\n  exit=${result.status}\n  ${output.trim()}`),
  );
  if (ok) passed++;
  else failed++;
}

try {
  const severity = replaceExactlyOnce(
    portableEngine,
    'F.push({ area: "SPF", severity: "high", title: "No SPF record",',
    'F.push({ area: "SPF", severity: "low", title: "No SPF record",',
    "severity",
  );
  expectRed(
    "A high→low severity",
    severity,
    "dkim-revoked-empty-p",
    'dkim-revoked-empty-p.findings[SPF|No SPF record].severity: expected "high", got "low"',
  );

  const deletedGuard = replaceExactlyOnce(
    portableEngine,
    "if (n > 10) {",
    "if (false) { // WHI-8 deleted-guard canary",
    "deleted guard",
  );
  expectRed(
    "B deleted finding guard",
    deletedGuard,
    "spf-over-10-lookups",
    "spf-over-10-lookups.findings[SPF|SPF exceeds 10 DNS lookups (11)].identity: expected finding, got missing",
  );

  const renamedAction = replaceExactlyOnce(
    portableEngine,
    'if (t.includes("no spf")) return "Publish an SPF record";',
    'if (t.includes("no spf")) return "Create an SPF record";',
    "action",
  );
  expectRed(
    "C renamed action",
    renamedAction,
    "dkim-revoked-empty-p",
    'dkim-revoked-empty-p.findings[SPF|No SPF record].action: expected "Publish an SPF record", got "Create an SPF record"',
  );

  const changedFix = replaceExactlyOnce(
    portableEngine,
    'fix: \'Add a TXT record at the apex: "v=spf1',
    'fix: \'Create a TXT record at the apex: "v=spf1',
    "fix",
  );
  expectRed(
    "D changed fix",
    changedFix,
    "dkim-revoked-empty-p",
    'dkim-revoked-empty-p.findings[SPF|No SPF record].fix: expected substring',
  );

  const changedScore = replaceExactlyOnce(
    portableEngine,
    'r.SPF = (qual === "-" || qual === "~") && lookups <= 10 && voids <= 2;',
    "r.SPF = true; // WHI-8 score canary",
    "score",
  );
  expectRed(
    "E changed score bucket",
    changedScore,
    "spf-over-10-lookups",
    "spf-over-10-lookups.score.SPF: expected false, got true",
  );

  const originalRunner = readFileSync(runner, "utf8");
  const stubbedRunner = replaceExactlyOnce(
    originalRunner,
    "    ...compareContract(fx, findings, score, SURFACE, ledger),",
    "    // WHI-8 canary: contract comparison stubbed out.",
    "runner stub",
  );
  const stubPath = join(temporary, "run-stubbed.mjs");
  writeFileSync(stubPath, stubbedRunner);
  expectRed(
    "F runner stub ignores material keys",
    portableEngine,
    "dkim-revoked-empty-p",
    "runner.assertions.severity: expected 9, got 0",
    stubPath,
  );
} catch (error) {
  console.log(`FAIL  canary setup — ${error.message}`);
  failed++;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

console.log(`\nCanaries (${surface}): ${passed} passed, ${failed} failed; expected 6 cases.`);
if (passed + failed !== 6) {
  console.error(`FAIL  canary count: expected 6, got ${passed + failed}`);
  process.exit(1);
}
process.exit(failed ? 1 : 0);
