#!/usr/bin/env node
// Official-vector adapter for amino-audit-engine's current private orgBase().
import { readFile } from "node:fs/promises";

if (process.argv.length !== 3) throw new Error("usage: engine.mjs /path/to/engine.mjs");
const source = await readFile(process.argv[2], "utf8");
const encoded = Buffer.from(`${source}\nexport { orgBase };\n`).toString("base64");
const { orgBase } = await import(`data:text/javascript;base64,${encoded}`);
let input = "";
for await (const chunk of process.stdin) input += chunk;
const results = JSON.parse(input).map((domain) => {
  try {
    return orgBase(domain);
  } catch (error) {
    return { error: error?.constructor?.name || "Error" };
  }
});
process.stdout.write(JSON.stringify(results));
