#!/usr/bin/env node
/**
 * Closed-world conformance runner for the two shipping JavaScript engines.
 *
 * Every dns-engine fixture keeps the original present/absent guards and also
 * asserts the reviewed material contract: exact finding identity, severity,
 * action, explicit-null/fix substring, selectively exact detail and effort/value,
 * and the complete score object.
 *
 *   SURFACE=web    ENGINE=../amino-site/functions/audit.js node conformance/run.mjs
 *   SURFACE=action ENGINE=../amino-audit-action/src/engine.mjs node conformance/run.mjs
 *
 * The resolver is fixture-backed, so the runner performs no network I/O.
 */
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ENGINE = resolve(process.env.ENGINE || resolve(here, "../../amino-site/functions/audit.js"));
const inferredSurface = /(?:^|\/)functions\/audit\.js$/.test(ENGINE)
  ? "web"
  : /(?:^|\/)src\/engine\.mjs$/.test(ENGINE) ? "action" : "";
const SURFACE = process.env.SURFACE || inferredSurface;
if (!["web", "action"].includes(SURFACE)) {
  console.error(`SURFACE must be web or action (could not infer it from ${ENGINE})`);
  process.exit(2);
}

const engine = await import(pathToFileURL(ENGINE).href);
if (typeof engine.auditDomain !== "function" || typeof engine.buckets !== "function") {
  console.error(`Engine must export auditDomain() and buckets(): ${ENGINE}`);
  process.exit(2);
}
let { fixtures } = JSON.parse(readFileSync(resolve(here, "fixtures.json"), "utf8"));
const CONTRACT_MODES = new Set(["dns-engine", "http-observation"]);
const LANES = new Set(["outbound_auth", "inbound_transport", "brand_optional", "outside_sending_posture"]);
const OBSERVATION_KEYS = ["mta_sts_policy", "rdap", "robots"];
const OBSERVATION_STATES = new Set(["checked", "unavailable", "not_applicable"]);
const onlyFixture = process.env.CONFORMANCE_FIXTURE;
if (onlyFixture) {
  fixtures = fixtures.filter((fixture) => fixture.id === onlyFixture);
  if (!fixtures.length) {
    console.error(`Unknown CONFORMANCE_FIXTURE: ${onlyFixture}`);
    process.exit(2);
  }
}

function mockQ(dns, http = {}, nowMs = 1767225600000) {
  const norm = (name) => name.replace(/\.+$/, "").toLowerCase();
  const map = {};
  for (const [name, records] of Object.entries(dns || {})) map[norm(name)] = records;
  const q = async (name, type) => {
    name = norm(name);
    if (map[name] && map[name][type]) return map[name][type];
    for (const key of Object.keys(map)) {
      if (key.startsWith("*._domainkey.") && name.endsWith(key.slice(1)) && map[key][type]) {
        return map[key][type];
      }
    }
    return [];
  };
  q.meta = async (name) => {
    const entry = map[norm(name)] || {};
    return { status: entry.status !== undefined ? entry.status : 0, ad: !!entry.ad, error: false };
  };
  const response = (name) => http[name] === "unavailable" || http[name] === undefined
    ? null : structuredClone(http[name]);
  q.http = {
    mtaSts: async () => response("mta_sts_policy"),
    robots: async () => response("robots"),
    rdap: async () => response("rdap"),
  };
  q.clock = { nowMs: () => nowMs };
  return q;
}

const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const shown = (value) => JSON.stringify(value);
const findingKey = (finding) => `${finding.area}\u0000${finding.title}`;
const findingLabel = (finding) => `${finding.area}|${finding.title}`;

function expectedFindings(fx, surface) {
  if (!Array.isArray(fx.expect?.findings)) {
    throw new Error(`${fx.id}.expect.findings must be a reviewed closed list`);
  }
  const expected = [];
  let notApplicable = 0;
  for (const finding of fx.expect.findings) {
    for (const field of ["area", "title", "severity", "lane", "action", "fixIncludes"]) {
      if (!own(finding, field)) throw new Error(`${fx.id}.expect.findings missing ${field}`);
    }
    if (!LANES.has(finding.lane)) {
      throw new Error(`${fx.id}.findings[${findingLabel(finding)}].lane: unknown contract value ${shown(finding.lane)}`);
    }
    if (finding.severity !== "pass" && finding.fixIncludes === null) {
      throw new Error(`${fx.id}.findings[${findingLabel(finding)}].fix: non-pass finding must declare a non-null fixIncludes`);
    }
    if (own(finding, "detail") && typeof finding.detail !== "string") {
      throw new Error(`${fx.id}.findings[${findingLabel(finding)}].detail: expected an exact string`);
    }
    const hasEffort = own(finding, "effort");
    const hasValue = own(finding, "value");
    if (hasEffort !== hasValue) {
      throw new Error(`${fx.id}.findings[${findingLabel(finding)}].effort/value: must be declared together`);
    }
    const surfaces = finding.surfaces || ["skill", "web", "action"];
    if (surfaces.includes(surface)) {
      expected.push(finding);
    } else {
      const reason = finding.notApplicable?.[surface];
      if (!reason) {
        throw new Error(`${fx.id}.expect.findings[${findingLabel(finding)}] omits ${surface} without a notApplicable reason`);
      }
      notApplicable++;
    }
  }
  return { expected, notApplicable };
}

function compareLegacy(fx, findings) {
  const problems = [];
  const titles = findings.map((finding) => `${finding.area}:${finding.title}`);
  for (const present of fx.expect.present || []) {
    if (!findings.some((finding) => finding.area === present.area && finding.title.includes(present.includes))) {
      problems.push(`legacy.present[${present.area}~${shown(present.includes)}]: missing`);
    }
  }
  for (const absent of fx.expect.absent || []) {
    if (titles.some((title) => title.includes(absent))) {
      problems.push(`legacy.absent[${shown(absent)}]: unexpected match`);
    }
  }
  return problems;
}

function compareContract(fx, result, score, surface, ledger) {
  const problems = [];
  const findings = result.findings || [];
  const { expected } = expectedFindings(fx, surface);
  const actualByKey = new Map();
  for (const actual of findings) {
    const key = findingKey(actual);
    if (actualByKey.has(key)) {
      problems.push(`findings[${findingLabel(actual)}].identity: duplicate actual finding`);
    } else {
      actualByKey.set(key, actual);
    }
  }

  const expectedKeys = new Set();
  for (const wanted of expected) {
    ledger.identity++;
    ledger.severity++;
    ledger.action++;
    ledger.fix++;
    ledger.lane++;
    if (own(wanted, "detail")) ledger.detail++;
    if (own(wanted, "effort")) {
      ledger.effort++;
      ledger.value++;
    }
    const key = findingKey(wanted);
    if (expectedKeys.has(key)) {
      problems.push(`findings[${findingLabel(wanted)}].identity: duplicate expectation`);
      continue;
    }
    expectedKeys.add(key);
    const actual = actualByKey.get(key);
    if (!actual) {
      problems.push(`findings[${findingLabel(wanted)}].identity: expected finding, got missing`);
      continue;
    }
    if (actual.severity !== wanted.severity) {
      problems.push(`findings[${findingLabel(wanted)}].severity: expected ${shown(wanted.severity)}, got ${shown(actual.severity)}`);
    }
    if (actual.lane !== wanted.lane) {
      problems.push(`findings[${findingLabel(wanted)}].lane: expected ${shown(wanted.lane)}, got ${shown(actual.lane)}`);
    }
    if (own(wanted, "detail")) {
      if (actual.detail !== wanted.detail) {
        problems.push(`findings[${findingLabel(wanted)}].detail: expected ${shown(wanted.detail)}, got ${shown(actual.detail)}`);
      }
    }
    if (own(wanted, "effort")) {
      if (actual.effort !== wanted.effort) {
        problems.push(`findings[${findingLabel(wanted)}].effort: expected ${shown(wanted.effort)}, got ${shown(actual.effort)}`);
      }
      if (actual.value !== wanted.value) {
        problems.push(`findings[${findingLabel(wanted)}].value: expected ${shown(wanted.value)}, got ${shown(actual.value)}`);
      }
    }
    const actualAction = actual.action ?? null;
    if (actualAction !== wanted.action) {
      problems.push(`findings[${findingLabel(wanted)}].action: expected ${shown(wanted.action)}, got ${shown(actualAction)}`);
    }
    const actualFix = actual.fix ?? null;
    if (wanted.fixIncludes === null) {
      if (actualFix !== null) {
        problems.push(`findings[${findingLabel(wanted)}].fix: expected null, got ${shown(actualFix)}`);
      }
    } else if (typeof actualFix !== "string" || !actualFix.includes(wanted.fixIncludes)) {
      problems.push(`findings[${findingLabel(wanted)}].fix: expected substring ${shown(wanted.fixIncludes)}, got ${shown(actualFix)}`);
    }
  }

  ledger.closedWorld++;
  for (const actual of findings) {
    if (!expectedKeys.has(findingKey(actual))) {
      problems.push(`findings[${findingLabel(actual)}].identity: unexpected finding`);
    }
  }

  if (!fx.expect.score || typeof fx.expect.score !== "object" || Array.isArray(fx.expect.score)) {
    problems.push("score: missing reviewed score object");
    return problems;
  }
  const wantedScoreKeys = Object.keys(fx.expect.score).sort();
  const actualScoreKeys = Object.keys(score || {}).sort();
  ledger.scoreFields += wantedScoreKeys.length;
  if (shown(actualScoreKeys) !== shown(wantedScoreKeys)) {
    problems.push(`score.keys: expected ${shown(wantedScoreKeys)}, got ${shown(actualScoreKeys)}`);
  }
  for (const field of wantedScoreKeys) {
    if (shown(score?.[field]) !== shown(fx.expect.score[field])) {
      problems.push(`score.${field}: expected ${shown(fx.expect.score[field])}, got ${shown(score?.[field])}`);
    }
  }
  ledger.observations++;
  const wantedObservationKeys = Object.keys(fx.expect.observations || {}).sort();
  if (shown(wantedObservationKeys) !== shown(OBSERVATION_KEYS)
      || !Object.values(fx.expect.observations || {}).every((state) => OBSERVATION_STATES.has(state))) {
    problems.push("observations: expected the closed mta_sts_policy/robots/rdap map and enum values");
  }
  if (shown(result.observations) !== shown(fx.expect.observations)) {
    problems.push(`observations: expected ${shown(fx.expect.observations)}, got ${shown(result.observations)}`);
  }
  return problems;
}

function assertionPlan(surface) {
  const plan = { identity: 0, severity: 0, action: 0, fix: 0, lane: 0, detail: 0, effort: 0, value: 0, scoreFields: 0, closedWorld: 0, observations: 0 };
  for (const fx of fixtures.filter((fixture) => CONTRACT_MODES.has(fixture.mode))) {
    const { expected } = expectedFindings(fx, surface);
    plan.identity += expected.length;
    plan.severity += expected.length;
    plan.action += expected.length;
    plan.fix += expected.length;
    plan.lane += expected.length;
    plan.detail += expected.filter((finding) => own(finding, "detail")).length;
    plan.effort += expected.filter((finding) => own(finding, "effort")).length;
    plan.value += expected.filter((finding) => own(finding, "value")).length;
    plan.scoreFields += Object.keys(fx.expect.score || {}).length;
    plan.closedWorld++;
    plan.observations++;
  }
  return plan;
}

let pass = 0;
let fail = 0;
let skip = 0;
let notApplicable = 0;
const failures = [];
const ledger = { identity: 0, severity: 0, action: 0, fix: 0, lane: 0, detail: 0, effort: 0, value: 0, scoreFields: 0, closedWorld: 0, observations: 0 };

for (const fx of fixtures) {
  if (!CONTRACT_MODES.has(fx.mode)) {
    skip++;
    console.log(`  SKIP  ${fx.id} (${fx.invariant}) — ${fx.skip_reason || fx.mode}`);
    continue;
  }

  let result;
  let findings;
  let score;
  try {
    const q = mockQ(fx.input.dns, fx.input.http, fx.input.nowMs);
    result = await engine.auditDomain(fx.input.domain, q);
    findings = result.findings || [];
    score = await engine.buckets(fx.input.domain, q);
    notApplicable += expectedFindings(fx, SURFACE).notApplicable;
  } catch (error) {
    fail++;
    const message = `${fx.id}.execution: threw ${error?.message || error}`;
    failures.push(message);
    console.log(`  FAIL  ${fx.id} (${fx.invariant}) — ${message}`);
    continue;
  }

  const problems = [
    ...compareLegacy(fx, findings),
    ...compareContract(fx, result, score, SURFACE, ledger),
  ];
  if (problems.length) {
    fail++;
    failures.push(...problems.map((problem) => `${fx.id}.${problem}`));
    console.log(`  FAIL  ${fx.id} (${fx.invariant}) — ${problems.join("; ")}`);
  } else {
    pass++;
    console.log(`  PASS  ${fx.id} (${fx.invariant})`);
  }
}

const plan = assertionPlan(SURFACE);
for (const field of Object.keys(plan)) {
  if (ledger[field] !== plan[field]) {
    fail++;
    const message = `runner.assertions.${field}: expected ${plan[field]}, got ${ledger[field]}`;
    failures.push(message);
    console.log(`  FAIL  ${message}`);
  }
}

console.log(`\nSurface: ${SURFACE}`);
console.log(`Engine: ${ENGINE}`);
console.log(`Results: ${pass} passed, ${fail} failed, ${skip} skipped, ${notApplicable} N/A.`);
if (failures.length) console.log(`Failures:\n- ${failures.join("\n- ")}`);
process.exit(fail ? 1 : 0);
