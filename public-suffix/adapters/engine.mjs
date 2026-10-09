#!/usr/bin/env node
// Official-vector adapter for amino-audit-engine's public registrableDomain().
import { pathToFileURL } from "node:url";

if (process.argv.length !== 3) throw new Error("usage: engine.mjs /path/to/engine.mjs");
const { registrableDomain } = await import(pathToFileURL(process.argv[2]).href);
if (typeof registrableDomain !== "function") {
  throw new Error("engine does not export registrableDomain");
}
let input = "";
for await (const chunk of process.stdin) input += chunk;
const results = JSON.parse(input).map((domain) => {
  try {
    return registrableDomain(domain);
  } catch (error) {
    return { error: error?.constructor?.name || "Error" };
  }
});
process.stdout.write(JSON.stringify(results));
