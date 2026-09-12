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

  const removedNullMxExemption = replaceExactlyOnce(
    portableEngine,
    "if (nullMx) {\n    r.MTA_STS = null;",
    "if (false) { // WHI-50 null-MX exemption canary\n    r.MTA_STS = null;",
    "null-MX score exemption",
  );
  expectRed(
    "H removed null-MX score exemption",
    removedNullMxExemption,
    "null-mx-not-applicable",
    "null-mx-not-applicable.score.MTA_STS: expected null, got false",
  );

  const revertedNullMxDetail = replaceExactlyOnce(
    portableEngine,
    "A null MX (0 .) declares under RFC 7505 that this domain accepts no inbound mail. That is good hygiene for a domain not meant to receive mail. It says nothing about whether the domain sends — outbound authentication is assessed separately.",
    "A null MX (0 .) correctly signals this domain neither sends nor receives mail, which helps receivers reject spoofed mail from it. Good hygiene for a non-mail domain.",
    "null-MX detail",
  );
  expectRed(
    "J reverted null-MX detail",
    revertedNullMxDetail,
    "null-mx-not-applicable",
    'null-mx-not-applicable.findings[Transport|Null MX (RFC 7505) — domain declares no mail].detail: expected "A null MX (0 .) declares under RFC 7505 that this domain accepts no inbound mail. That is good hygiene for a domain not meant to receive mail. It says nothing about whether the domain sends — outbound authentication is assessed separately.", got "A null MX (0 .) correctly signals this domain neither sends nor receives mail, which helps receivers reject spoofed mail from it. Good hygiene for a non-mail domain."',
  );

  const restoredNoMxAction = replaceExactlyOnce(
    portableEngine,
    'if (t === "no mx records") return "Confirm whether this domain should receive mail";',
    'if (t === "no mx records") return "Confirm STARTTLS on the mail server";',
    "No-MX action",
  );
  expectRed(
    "K restored STARTTLS action",
    restoredNoMxAction,
    "no-mx-not-exempt",
    'no-mx-not-exempt.findings[Transport|No MX records].action: expected "Confirm whether this domain should receive mail", got "Confirm STARTTLS on the mail server"',
  );

  const invalidCorpus = JSON.parse(readFileSync(resolve(here, "fixtures.json"), "utf8"));
  const noMxFixture = invalidCorpus.fixtures.find((fixture) => fixture.id === "no-mx-not-exempt");
  const noMxFinding = noMxFixture?.expect?.findings?.find(
    (finding) => finding.area === "Transport" && finding.title === "No MX records",
  );
  if (!noMxFinding || noMxFinding.fixIncludes === null) {
    throw new Error("No-MX corpus fix: expected a non-null fixture anchor");
  }
  noMxFinding.fixIncludes = null;
  writeFileSync(join(temporary, "fixtures.json"), JSON.stringify(invalidCorpus));
  const structuralRunner = join(temporary, "run-structural.mjs");
  writeFileSync(structuralRunner, readFileSync(runner, "utf8"));
  expectRed(
    "L restored null No-MX corpus fix",
    portableEngine,
    "no-mx-not-exempt",
    "no-mx-not-exempt.findings[Transport|No MX records].fix: non-pass finding must declare a non-null fixIncludes",
    structuralRunner,
  );
  writeFileSync(
    join(temporary, "fixtures.json"),
    readFileSync(resolve(here, "fixtures.json"), "utf8"),
  );

  const restoredBimiHighValue = replaceExactlyOnce(
    portableEngine,
    'if (a === "BIMI") return ["high", "low"];',
    'if (a === "BIMI") return ["high", "high"];',
    "BIMI value",
  );
  expectRed(
    "M restored BIMI high value",
    restoredBimiHighValue,
    "bimi-present-without-vmc",
    'bimi-present-without-vmc.findings[BIMI|BIMI present without a VMC].value: expected "low", got "high"',
  );

  const revertedNoMxDetail = replaceExactlyOnce(
    portableEngine,
    "No MX record is published. SMTP then treats the domain as if it had an implicit MX pointing to itself and resolves that host's address records, so this does not show that the domain receives no mail — a null MX (0 .) is what says that explicitly. This may be intentional for a send-only or parked domain.",
    "No inbound mail servers (may be intentional for a send-only/parked domain).",
    "No-MX detail",
  );
  expectRed(
    "N reverted No-MX detail",
    revertedNoMxDetail,
    "no-mx-not-exempt",
    'no-mx-not-exempt.findings[Transport|No MX records].detail: expected "No MX record is published. SMTP then treats the domain as if it had an implicit MX pointing to itself and resolves that host\'s address records, so this does not show that the domain receives no mail — a null MX (0 .) is what says that explicitly. This may be intentional for a send-only or parked domain.", got "No inbound mail servers (may be intentional for a send-only/parked domain)."',
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

console.log(`\nCanaries (${surface}): ${passed} passed, ${failed} failed; expected 12 cases.`);
if (passed + failed !== 12) {
  console.error(`FAIL  canary count: expected 12, got ${passed + failed}`);
  process.exit(1);
}
process.exit(failed ? 1 : 0);
