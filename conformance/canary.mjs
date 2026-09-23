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
// Phase A lands before the 1.2.0 engine by design. Until Phase B, wrap the real
// 1.1.0 surface with only the additive contract fields so the two new runner
// canaries can prove their diagnostics now. Once the engine has the contract
// anchors, the same cases mutate the real engine source directly.
let contractEngine = portableEngine;
const versionMatch = portableEngine.match(/export const contractVersion = "([^"]+)";/);
if (!versionMatch) {
  console.error("FAIL  WHI-79 staged wrapper selection — engine must declare export const contractVersion");
  rmSync(temporary, { recursive: true, force: true });
  process.exit(2);
}
const declaredContractVersion = versionMatch[1];
if (declaredContractVersion === "1.1.0") {
  writeFileSync(join(temporary, "phase-a-legacy-engine.mjs"), portableEngine);
  contractEngine = `
import * as legacy from "./phase-a-legacy-engine.mjs";
const AREA_LANES = Object.freeze({
  SPF: "outbound_auth",
  DKIM: "outbound_auth",
  DMARC: "outbound_auth",
  "MTA-STS": "inbound_transport",
  "TLS-RPT": "inbound_transport",
  Transport: "inbound_transport",
  MX: "inbound_transport",
  BIMI: "brand_optional",
  CAA: "domain_posture",
  DNSSEC: "domain_posture",
  "AI visibility": "outside_sending_posture",
  Reputation: "domain_posture",
});
const BUCKET_LANES = Object.freeze({ SPF: "outbound_auth", DKIM: "outbound_auth",
  DMARC: "outbound_auth", DMARC_enforced: "outbound_auth", DMARC_rua: "outbound_auth",
  MTA_STS: "inbound_transport", TLS_RPT: "inbound_transport",
  DANE: "inbound_transport", BIMI: "brand_optional" });
function laneForFinding(finding) {
  const title = (finding.title || "").toLowerCase();
  if (finding.area === "Transport" && title.includes("reverse dns")) {
    return "outside_sending_posture";
  }
  if (!AREA_LANES[finding.area]) throw new Error("unknown finding area has no lane: " + finding.area);
  return AREA_LANES[finding.area];
}
export async function auditDomain(domain, q) {
  const result = await legacy.auditDomain(domain, q);
  for (const finding of result.findings || []) finding.lane = laneForFinding(finding);
  const observations = domain.startsWith("mta-sts-policy-")
    ? { mta_sts_policy: "checked", robots: "checked", rdap: "checked" }
    : domain === "lane-coverage.example"
      ? { mta_sts_policy: "not_applicable", robots: "checked", rdap: "checked" }
      : { mta_sts_policy: "not_applicable", robots: "unavailable", rdap: "unavailable" };
  const observation = observations.mta_sts_policy;
  observations.mta_sts_policy = observation;
  return { ...result, observations };
}
export async function buckets(domain, q) {
  return { ...(await legacy.buckets(domain, q)), lanes: { ...BUCKET_LANES } };
}
`;
} else {
  const requiredAnchors = [
    'const AREA_LANES = Object.freeze({\n  SPF: "outbound_auth",',
    "observations.mta_sts_policy = observation;",
  ];
  const missingAnchors = requiredAnchors.filter((anchor) => !portableEngine.includes(anchor));
  if (missingAnchors.length) {
    console.error(
      `FAIL  WHI-79 staged wrapper selection — contract ${declaredContractVersion} must expose real lane and observation anchors; refusing legacy wrapper`,
    );
    rmSync(temporary, { recursive: true, force: true });
    process.exit(2);
  }
}
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

function expectRedComparison(name, source, fixture, expectedText) {
  const result = execute(source, fixture);
  const output = (result.stdout || "") + (result.stderr || "");
  const ok = result.status !== 0 && output.includes(expectedText)
    && !output.includes(".execution: threw") && !output.includes("Error [")
    && !output.includes("SyntaxError:");
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`
    + (ok ? ` — ${expectedText}` : `\n  exit=${result.status}\n  ${output.trim()}`));
  if (ok) passed++;
  else failed++;
}

function requireGreen(name, source, fixture, runnerPath = runner) {
  const result = execute(source, fixture, runnerPath);
  const output = (result.stdout || "") + (result.stderr || "");
  if (result.status !== 0) {
    throw new Error(`${name}: healthy control failed\nexit=${result.status}\n${output.trim()}`);
  }
  console.log(`CONTROL ${name} — healthy target passes`);
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

  const removedAreaLane = replaceExactlyOnce(
    contractEngine,
    'const AREA_LANES = Object.freeze({\n  SPF: "outbound_auth",',
    "const AREA_LANES = Object.freeze({\n  // WHI-79 removed SPF lane canary",
    "SPF lane assignment",
  );
  expectRed(
    "O removed one area lane",
    removedAreaLane,
    "dkim-revoked-empty-p",
    "dkim-revoked-empty-p.execution: threw unknown finding area has no lane: SPF",
  );

  const mislabelledAreaLane = replaceExactlyOnce(
    contractEngine,
    'const AREA_LANES = Object.freeze({\n  SPF: "outbound_auth",',
    'const AREA_LANES = Object.freeze({\n  SPF: "inbound_transport",',
    "SPF valid wrong lane",
  );
  expectRed(
    "Q valid wrong lane reaches runner comparison",
    mislabelledAreaLane,
    "dkim-revoked-empty-p",
    'dkim-revoked-empty-p.findings[SPF|No SPF record].lane: expected "outbound_auth", got "inbound_transport"',
  );

  const conflatedObservation = replaceExactlyOnce(
    contractEngine,
    "observations.mta_sts_policy = observation;",
    'observations.mta_sts_policy = "unavailable"; // WHI-79 conflation canary',
    "MTA-STS observation assignment",
  );
  expectRed(
    "P conflated absent with unavailable",
    conflatedObservation,
    "mta-sts-policy-absent",
    'mta-sts-policy-absent.observations: expected {"mta_sts_policy":"checked","robots":"checked","rdap":"checked"}, got {"mta_sts_policy":"unavailable","robots":"checked","rdap":"checked"}',
  );

  requireGreen(
    "WHI-176 five-lane contract",
    contractEngine,
    "lane-closed-world-coverage",
  );

  const revertedCaaLane = replaceExactlyOnce(
    contractEngine,
    '  CAA: "domain_posture",',
    '  CAA: "brand_optional",',
    "CAA domain-posture lane",
  );
  expectRed(
    "R CAA reverted to brand optional",
    revertedCaaLane,
    "lane-closed-world-coverage",
    'lane-closed-world-coverage.findings[CAA|No CAA records].lane: expected "domain_posture", got "brand_optional"',
  );

  const revertedDnssecLane = replaceExactlyOnce(
    contractEngine,
    '  DNSSEC: "domain_posture",',
    '  DNSSEC: "outside_sending_posture",',
    "DNSSEC domain-posture lane",
  );
  expectRed(
    "S DNSSEC reverted to outside sending posture",
    revertedDnssecLane,
    "lane-closed-world-coverage",
    'lane-closed-world-coverage.findings[DNSSEC|DNSSEC not enabled].lane: expected "domain_posture", got "outside_sending_posture"',
  );

  const removedReverseDnsException = replaceExactlyOnce(
    contractEngine,
    '  if (finding.area === "Transport" && title.includes("reverse dns")) {',
    '  if (false) { // WHI-176 removed reverse-DNS exception canary',
    "reverse-DNS lane exception",
  );
  expectRed(
    "T removed reverse-DNS lane exception",
    removedReverseDnsException,
    "lane-closed-world-coverage",
    'lane-closed-world-coverage.findings[Transport|Mail server has no reverse DNS (PTR)].lane: expected "outside_sending_posture", got "inbound_transport"',
  );

  const i20Condition = "if (m.error || m.status === 2 || m.status === 5) {";
  const i20Order = 'for (const [n, t] of [[domain, "TXT"], ["_dmarc." + domain, "TXT"], [domain, "MX"]]) {';
  requireGreen("I20 apex TXT failure", contractEngine, "inconclusive-apex-txt-servfail");
  expectRedComparison(
    "U I20 flag forced false",
    replaceExactlyOnce(contractEngine, i20Condition, "if (false) { // I20 forced false", "I20 false flag"),
    "inconclusive-apex-txt-servfail",
    "inconclusive-apex-txt-servfail.inconclusive: expected true, got false",
  );
  requireGreen("I20 healthy domain", contractEngine, "dane-unvalidated-tlsa");
  expectRedComparison(
    "V I20 flag forced true",
    replaceExactlyOnce(contractEngine, "let inconclusive = false, inconclusiveReason = null;",
      'let inconclusive = true, inconclusiveReason = "TXT ex.com: lookup error";', "I20 true flag"),
    "dane-unvalidated-tlsa",
    "dane-unvalidated-tlsa.inconclusive: expected false, got true",
  );
  requireGreen("I20 non-critical MTA-STS failure", contractEngine, "mta-sts-lookup-servfail");
  expectRedComparison(
    "W I20 non-critical lookup drives flag",
    replaceExactlyOnce(contractEngine, i20Order,
      'for (const [n, t] of [["_mta-sts." + domain, "TXT"], [domain, "TXT"], ["_dmarc." + domain, "TXT"], [domain, "MX"]]) {',
      "I20 non-critical lookup"),
    "mta-sts-lookup-servfail",
    "mta-sts-lookup-servfail.inconclusive: expected false, got true",
  );
  requireGreen("I20 order", contractEngine, "inconclusive-apex-txt-before-mx");
  expectRedComparison(
    "X I20 MX before TXT",
    replaceExactlyOnce(contractEngine, i20Order,
      'for (const [n, t] of [[domain, "MX"], [domain, "TXT"], ["_dmarc." + domain, "TXT"]]) {',
      "I20 check order"),
    "inconclusive-apex-txt-before-mx",
    'inconclusive-apex-txt-before-mx.inconclusive_reason: expected "TXT ex.com: SERVFAIL/REFUSED", got "MX ex.com: SERVFAIL/REFUSED"',
  );
  requireGreen("I20 NXDOMAIN", contractEngine, "inconclusive-dmarc-nxdomain");
  expectRedComparison(
    "Y I20 NXDOMAIN treated as failure",
    replaceExactlyOnce(contractEngine, i20Condition,
      "if (m.error || m.status === 2 || m.status === 5 || m.status === 3) {", "I20 NXDOMAIN"),
    "inconclusive-dmarc-nxdomain",
    "inconclusive-dmarc-nxdomain.inconclusive: expected false, got true",
  );
  requireGreen("I20 reason forms", contractEngine, "inconclusive-apex-txt-servfail");
  expectRedComparison(
    "Z I20 reason forms swapped",
    replaceExactlyOnce(contractEngine,
      '(m.error ? "lookup error" : "SERVFAIL/REFUSED")',
      '(m.error ? "SERVFAIL/REFUSED" : "lookup error")', "I20 reason forms"),
    "inconclusive-apex-txt-servfail",
    'inconclusive-apex-txt-servfail.inconclusive_reason: expected "TXT ex.com: SERVFAIL/REFUSED", got "TXT ex.com: lookup error"',
  );
  requireGreen("I20 AAAA-only website failure", contractEngine, "robots-aaaa-lookup-failed");
  expectRedComparison(
    "AA I20 website consults only A metadata",
    replaceExactlyOnce(contractEngine,
      "return dnsMetaFailed(aMeta) || dnsMetaFailed(aaaaMeta)\n        ? \"lookup_failed\" : \"no_answers\";",
      'return dnsMetaFailed(aMeta)\n        ? "lookup_failed" : "no_answers";', "I20 address-family metadata"),
    "robots-aaaa-lookup-failed",
    'robots-aaaa-lookup-failed.observations: expected {"mta_sts_policy":"not_applicable","robots":"unavailable","rdap":"unavailable"}, got {"mta_sts_policy":"not_applicable","robots":"not_applicable","rdap":"unavailable"}',
  );
  requireGreen("I20 website apex NXDOMAIN", contractEngine, "robots-apex-nxdomain");
  expectRedComparison(
    "AB I20 website accepts NOERROR only",
    replaceExactlyOnce(contractEngine,
      "return !!meta?.error || ![0, 3].includes(meta?.status);",
      "return !!meta?.error || meta?.status !== 0;", "I20 website NXDOMAIN"),
    "robots-apex-nxdomain",
    'robots-apex-nxdomain.observations: expected {"mta_sts_policy":"not_applicable","robots":"not_applicable","rdap":"unavailable"}, got {"mta_sts_policy":"not_applicable","robots":"unavailable","rdap":"unavailable"}',
  );
  requireGreen("I20 NXDOMAIN reason", contractEngine, "inconclusive-dmarc-nxdomain");
  expectRedComparison(
    "AC I20 every non-zero rcode counts",
    replaceExactlyOnce(contractEngine, i20Condition,
      "if (m.error || m.status !== 0) {", "I20 every non-zero rcode"),
    "inconclusive-dmarc-nxdomain",
    "inconclusive-dmarc-nxdomain.inconclusive: expected false, got true",
  );

  const originalRunner = readFileSync(runner, "utf8");
  const stubbedRunner = replaceExactlyOnce(
    originalRunner,
    "    ...compareContract(fx, result, score, SURFACE, ledger),",
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

console.log(`\nCanaries (${surface}): ${passed} passed, ${failed} failed; expected 27 cases.`);
if (passed + failed !== 27) {
  console.error(`FAIL  canary count: expected 27, got ${passed + failed}`);
  process.exit(1);
}
process.exit(failed ? 1 : 0);
