#!/usr/bin/env node
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLAIM_GATE = join(ROOT, "conformance", "dmarc-discovery-claims.mjs");
const PUBLISHED = join("amino-deliverability-audit", "skills", "amino-deliverability-audit");
const temporary = mkdtempSync(join(tmpdir(), "whi-273-faq-claim-"));

function run() {
  return spawnSync(process.execPath, [CLAIM_GATE, "--surface", "skill", "--root", temporary], {
    encoding: "utf8",
  });
}

function output(result) {
  return `${result.stdout || ""}\n${result.stderr || ""}`;
}

try {
  mkdirSync(join(temporary, "faq"), { recursive: true });
  cpSync(join(ROOT, "FAQ.md"), join(temporary, "FAQ.md"));
  cpSync(join(ROOT, "faq", "audit-faq.json"), join(temporary, "faq", "audit-faq.json"));
  mkdirSync(dirname(join(temporary, PUBLISHED)), { recursive: true });
  cpSync(join(ROOT, PUBLISHED), join(temporary, PUBLISHED), { recursive: true });

  const healthy = run();
  if (healthy.status !== 0 || !output(healthy).includes("PASS published skill makes no false tree-walk compliance claim")) {
    throw new Error(`FAIL WHI-273 FAQ claim canary healthy control\n${output(healthy)}`);
  }
  console.log("PASS WHI-273 FAQ claim canary healthy control");

  const artifactPath = join(temporary, "faq", "audit-faq.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const rows = artifact.filter((entry) => entry.question === "What is DMARCbis?");
  if (rows.length !== 1) {
    throw new Error(`FAIL WHI-273 FAQ claim canary mutation anchor: expected 1 DMARCbis row, got ${rows.length}`);
  }
  const [row] = rows;
  if (!row.answer.includes("This is a deliberate compatibility divergence")) {
    throw new Error("FAIL WHI-273 FAQ claim canary mutation anchor: reviewed DMARCbis answer missing");
  }
  row.answer = "The audit follows the complete DMARCbis DNS Tree Walk all the way to the root.";
  writeFileSync(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);

  const mutated = run();
  const diagnostic = "FAIL published skill makes no false tree-walk compliance claim";
  if (mutated.status === 0 || !output(mutated).includes(diagnostic)) {
    throw new Error(`FAIL WHI-273 FAQ artifact was not scanned by the public-claim gate\n${output(mutated)}`);
  }
  console.log(`PASS WHI-273 FAQ artifact claim canary: ${diagnostic}`);
  console.log("WHI-273 FAQ claim canary: 1/1 named mutation rejected.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
