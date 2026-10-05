#!/usr/bin/env node
// Official-vector adapter for amino-monitor's current private regDomain().
import { readFile } from "node:fs/promises";
import vm from "node:vm";

if (process.argv.length !== 3) throw new Error("usage: monitor.mjs /path/to/src/index.js");
const source = await readFile(process.argv[2], "utf8");
const match = source.match(/const MULTI_TLD = new Set\([\s\S]*?\nfunction regDomain\(host\)\{[\s\S]*?\n\}/);
if (!match || (source.match(/function regDomain\(host\)/g) || []).length !== 1) {
  throw new Error("could not extract the single reviewed regDomain implementation");
}
const regDomain = vm.runInNewContext(`${match[0]}\nregDomain`);
let input = "";
for await (const chunk of process.stdin) input += chunk;
const results = JSON.parse(input).map((domain) => {
  try {
    return regDomain(domain);
  } catch (error) {
    return { error: error?.constructor?.name || "Error" };
  }
});
process.stdout.write(JSON.stringify(results));
