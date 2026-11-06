import { build } from "esbuild";
import { mkdir, rm } from "node:fs/promises";

await mkdir("dist", { recursive: true });
await rm("dist/cli.mjs", { force: true });
await rm("dist/cli.mjs.map", { force: true });

// Bundle the CLI + MCP entry only. Keep npm packages external so the install
// still supplies @modelcontextprotocol/sdk, zod, typescript, etc. Do not pull
// the Next.js app or the LLM swarm into this file.
await build({
  entryPoints: ["src/cli/index.ts"],
  outfile: "dist/cli.mjs",
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  sourcemap: true,
  packages: "external",
  logLevel: "info",
  // MCP stdio must never receive bundler banners on stdout.
  banner: { js: "" },
});

console.log("CLI + MCP bundle written to dist/cli.mjs");
