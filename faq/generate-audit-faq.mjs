#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ARTIFACT = resolve(HERE, "audit-faq.json");
const START = "// BEGIN GENERATED AUDIT FAQ\n";
const END = "// END GENERATED AUDIT FAQ\n";
const LEGACY_START = "const FAQ = [";
const LEGACY_END = "\n\nfunction faqJsonLd";

function fail(message) {
  console.error(`FAIL WHI-273 audit FAQ generator: ${message}`);
  process.exit(1);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArgs(argv) {
  const check = argv.includes("--check");
  const targetAt = argv.indexOf("--target");
  if (targetAt < 0 || !argv[targetAt + 1]) {
    fail("usage: generate-audit-faq.mjs --target PATH [--check]");
  }
  const allowed = new Set(["--check", "--target", argv[targetAt + 1]]);
  const unknown = argv.filter((arg) => !allowed.has(arg));
  if (unknown.length) fail(`unknown argument ${JSON.stringify(unknown[0])}`);
  return { check, target: resolve(argv[targetAt + 1]) };
}

function readArtifact() {
  const bytes = readFileSync(ARTIFACT);
  let entries;
  try {
    entries = JSON.parse(bytes);
  } catch (error) {
    fail(`artifact is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(entries) || entries.length !== 14) {
    fail(`artifact must contain exactly 14 ordered entries, got ${Array.isArray(entries) ? entries.length : "non-array"}`);
  }
  const questions = new Set();
  for (const [index, entry] of entries.entries()) {
    const keys = entry && typeof entry === "object" && !Array.isArray(entry) ? Object.keys(entry) : [];
    if (keys.join(",") !== "question,answer") {
      fail(`entry ${index + 1} must contain only question then answer`);
    }
    if (typeof entry.question !== "string" || !entry.question.trim()) fail(`entry ${index + 1} has no question`);
    if (typeof entry.answer !== "string" || !entry.answer.trim()) fail(`entry ${index + 1} has no answer`);
    if (questions.has(entry.question)) fail(`duplicate question ${JSON.stringify(entry.question)}`);
    questions.add(entry.question);
  }
  const canonical = `${JSON.stringify(entries, null, 2)}\n`;
  if (!bytes.equals(Buffer.from(canonical, "utf8"))) fail("artifact is not canonical pretty-printed JSON");
  return { bytes, entries };
}

function generatedBlock(entries) {
  const rows = entries
    .map(({ question, answer }) => `  Object.freeze(${JSON.stringify([question, answer])}),`)
    .join("\n");
  return `${START}const FAQ = Object.freeze([\n${rows}\n]);\n${END}`;
}

function generate(source, block) {
  const starts = source.split(START).length - 1;
  const ends = source.split(END).length - 1;
  if (starts || ends) {
    if (starts !== 1 || ends !== 1) fail("generated delimiters must each occur exactly once");
    const startAt = source.indexOf(START);
    const endAt = source.indexOf(END, startAt) + END.length;
    if (endAt <= startAt) fail("generated delimiters are reversed");
    return source.slice(0, startAt) + block + source.slice(endAt);
  }

  const startAt = source.indexOf(LEGACY_START);
  const endAt = source.indexOf(LEGACY_END, startAt);
  if (startAt < 0 || endAt < 0 || source.indexOf(LEGACY_START, startAt + 1) >= 0) {
    fail("target must contain exactly one generated block or legacy FAQ block");
  }
  return source.slice(0, startAt) + block + source.slice(endAt + 1);
}

const { check, target } = parseArgs(process.argv.slice(2));
const { bytes, entries } = readArtifact();
const source = readFileSync(target, "utf8");
const generated = generate(source, generatedBlock(entries));
const identity = `${entries.length} entries / ${bytes.length} bytes / ${sha256(bytes)}`;

if (check) {
  if (source !== generated) fail("target is not the deterministic output of the pinned FAQ artifact");
  console.log(`WHI-273 audit FAQ generator CHECK PASS: ${identity}`);
} else {
  writeFileSync(target, generated);
  console.log(`WHI-273 audit FAQ generator WRITE PASS: ${identity}`);
}
