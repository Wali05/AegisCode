#!/usr/bin/env node
// Runs the TypeScript CLI through tsx's loader — no build step needed.
import { tsImport } from "tsx/esm/api";

try {
  const { main } = await tsImport("../src/cli/index.ts", import.meta.url);
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  console.error(`aegis: ${err instanceof Error ? err.message : err}`);
  process.exitCode = 2;
}
