#!/usr/bin/env node
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "whi-273-faq-generator-"));
const faqDir = join(temporary, "faq");
const target = join(temporary, "audit.js");

function run(...args) {
  return spawnSync(process.execPath, [join(faqDir, "generate-audit-faq.mjs"), "--target", target, ...args], {
    encoding: "utf8",
  });
}

function output(result) {
  return `${result.stdout || ""}\n${result.stderr || ""}`;
}

function requireResult(name, condition, detail) {
  if (!condition) throw new Error(`FAIL WHI-273 ${name}\n${detail}`);
  console.log(`PASS WHI-273 ${name}`);
}

try {
  cpSync(HERE, faqDir, { recursive: true });
  writeFileSync(target, 'const FAQ = [["stale question", "stale answer"]];\n\nfunction faqJsonLd() {}\n');

  const write = run();
  requireResult("generator writes the canonical artifact", write.status === 0 && /WRITE PASS: 14 entries/.test(output(write)), output(write));
  const generated = readFileSync(target, "utf8");
  requireResult("generated block has exact delimiters", generated.split("// BEGIN GENERATED AUDIT FAQ").length === 2
    && generated.split("// END GENERATED AUDIT FAQ").length === 2, generated);

  const healthy = run("--check");
  requireResult("generator check accepts its exact output", healthy.status === 0 && /CHECK PASS: 14 entries/.test(output(healthy)), output(healthy));

  writeFileSync(target, generated.replace("Why are my emails going to spam?", "Why do messages go to spam?"));
  const handEdit = run("--check");
  requireResult(
    "hand edit fails check by name",
    handEdit.status !== 0 && output(handEdit).includes("FAIL WHI-273 audit FAQ generator: target is not the deterministic output of the pinned FAQ artifact"),
    output(handEdit),
  );

  writeFileSync(target, generated);
  const artifactPath = join(faqDir, "audit-faq.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  artifact[0].answer += " Reviewed artifact mutation.";
  writeFileSync(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);
  const artifactChange = run("--check");
  requireResult(
    "artifact change without regeneration fails check by name",
    artifactChange.status !== 0 && output(artifactChange).includes("FAIL WHI-273 audit FAQ generator: target is not the deterministic output of the pinned FAQ artifact"),
    output(artifactChange),
  );

  console.log("WHI-273 audit FAQ generator tests: 5 passed, 0 failed.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
