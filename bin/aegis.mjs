#!/usr/bin/env node
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist", "cli.mjs");

try {
  let main;
  if (existsSync(dist)) {
    ({ main } = await import(pathToFileURL(dist).href));
  } else {
    // Local checkout without a build: load TypeScript through tsx.
    const { tsImport } = await import("tsx/esm/api");
    ({ main } = await tsImport("../src/cli/index.ts", import.meta.url));
  }
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  console.error(`aegis: ${err instanceof Error ? err.message : err}`);
  process.exitCode = 2;
}
