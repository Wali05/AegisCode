#!/usr/bin/env node
/**
 * Spawns the real aegis MCP binary over stdio and checks tools + scan_code.
 * Requires dist/cli.mjs (run `npm run build:cli` first, or `npm prepare`).
 */
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bin = join(root, "bin", "aegis.mjs");
const dist = join(root, "dist", "cli.mjs");

if (!existsSync(bin)) {
  console.error("bin/aegis.mjs is missing.");
  process.exit(1);
}
if (!existsSync(dist)) {
  console.error("dist/cli.mjs is missing. Run npm run build:cli first.");
  process.exit(1);
}

const REQUIRED = ["check_packages", "explain_rule", "scan_changes", "scan_code", "scan_paths"];
const SNIPPET = `app.get("/", (req, res) => res.redirect(req.query.next));`;

let stderr = "";
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [bin, "mcp"],
  cwd: root,
  stderr: "pipe",
  env: { ...process.env } ,
});
transport.stderr?.on("data", (chunk) => {
  stderr += chunk.toString();
});

const client = new Client({ name: "aegis-mcp-smoke", version: "0.1.0" }, { capabilities: {} });
let exitCode = 0;

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  for (const required of REQUIRED) {
    if (!names.includes(required)) throw new Error(`missing tool ${required}; got: ${names.join(", ")}`);
  }

  const result = await client.callTool({
    name: "scan_code",
    arguments: { filename: "api.ts", code: SNIPPET },
  });
  const text = (result.content && result.content[0] && result.content[0].text) || "";
  if (!/\[MEDIUM\] api\.ts:1 Open redirect/.test(text)) {
    throw new Error(`scan_code did not report the open redirect:\n${text}`);
  }

  console.log(`mcp-smoke ok: ${names.length} tools (${REQUIRED.join(", ")}); scan_code found [MEDIUM] Open redirect`);
} catch (error) {
  exitCode = 1;
  console.error(`mcp-smoke failed: ${error instanceof Error ? error.message : error}`);
  if (stderr.trim()) console.error(stderr.trim().slice(-2000));
} finally {
  await client.close().catch(() => undefined);
}

process.exit(exitCode);
