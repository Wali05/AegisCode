import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { attachFixes, scanFile, scanProject } from "../lib/engine";
import type { Finding } from "../lib/engine/types";
import { compareFindings } from "../lib/engine/finding";
import { checkPackages, extractPackageRefs, type PackageRef } from "../lib/deps/packages";
import { detectLanguage } from "../lib/engine/language";
import { ruleCatalog } from "../lib/catalog";
import { ENGINE_VERSION } from "../lib/pipeline";
import { scanChanges } from "./changes";

/**
 * MCP server for coding agents. An agent calls these tools on code it has just
 * written — before committing — and gets back a short, actionable list of
 * what to fix. Everything runs locally; only the package check talks to the
 * npm / PyPI registries.
 */

const MAX_LISTED = 25;

/** Compact, model-friendly rendering: one block per finding with the fix inline. */
export function formatForAgent(findings: Finding[], heading: string): string {
  const open = findings.filter((f) => f.status !== "dismissed" && f.severity !== "info").sort(compareFindings);
  if (!open.length) return `${heading}\nNo issues found.`;
  const blocks = open.slice(0, MAX_LISTED).map((f) => {
    const flow = f.trace?.length ? `\n  flow: ${f.trace.map((s) => `${s.file && s.file !== f.file ? `${s.file}:` : "L"}${s.line} ${s.label}`).join(" → ")}` : "";
    const fix = f.fix?.verified ? `\n  verified fix (${f.fix.title}), replace line ${f.fix.diff.line} with:\n    ${f.fix.diff.added.join("\n    ")}` : `\n  fix: ${f.remediation.split("\n")[0]}`;
    return `- [${f.severity.toUpperCase()}] ${f.file}:${f.location.line} ${f.title} (${f.ruleId}${f.cwe[0] ? `, ${f.cwe[0]}` : ""})${flow}${fix}`;
  });
  const more = open.length > MAX_LISTED ? `\n…and ${open.length - MAX_LISTED} more.` : "";
  return `${heading}\n${blocks.join("\n")}${more}`;
}

const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });

/** Resolves a user-supplied path and refuses anything outside the project root. */
function insideRoot(root: string, p: string): string {
  const abs = resolve(root, p);
  if (abs !== root && !abs.startsWith(root + sep)) throw new Error(`${p} is outside the project`);
  return abs;
}

export function createServer(root = process.cwd()): McpServer {
  const server = new McpServer({ name: "aegiscode", version: ENGINE_VERSION });

  server.registerTool(
    "scan_code",
    {
      title: "Scan a code snippet",
      description:
        "Run AegisCode's security analysis (taint tracking, CWE-mapped rules, secret detection, package check) on a piece of code before writing or committing it. Returns each issue with its location, data-flow path and the fix.",
      inputSchema: {
        code: z.string().max(300_000).describe("The full file contents"),
        filename: z.string().max(300).describe("File name with extension, e.g. src/routes/users.ts — used to pick the language"),
      },
    },
    async ({ code, filename }) => {
      const report = attachFixes(scanFile(filename, code), code);
      const refs = extractPackageRefs(filename, code, report.language);
      const pkg = refs.length ? await checkPackages(refs) : { findings: [] as Finding[] };
      return text(formatForAgent([...report.findings, ...pkg.findings], `AegisCode: ${filename} — score ${report.score}/100 (${report.grade})`));
    }
  );

  server.registerTool(
    "scan_changes",
    {
      title: "Scan uncommitted or staged changes",
      description:
        "Scan only what changed in the git repository and report the issues those changes introduce (pre-existing issues are ignored). Use this before committing.",
      inputSchema: {
        scope: z.enum(["staged", "working", "since"]).default("working").describe("staged = git index; working = all uncommitted changes; since = everything since `ref`"),
        ref: z.string().max(200).optional().describe("Branch or commit to compare with when scope is 'since', e.g. main"),
      },
    },
    async ({ scope, ref }) => {
      if (scope === "since" && !ref) return text("`ref` is required when scope is 'since'.");
      const mode = scope === "since" ? { kind: "since" as const, ref: ref! } : scope === "staged" ? { kind: "staged" as const } : { kind: "working" as const };
      const res = await scanChanges(root, mode);
      const heading = `AegisCode: ${res.files.length} changed file(s) — ${res.added.length} new issue(s), ${res.fixed.length} fixed, ${res.existing.length} pre-existing (not shown).`;
      return text(formatForAgent(res.added, heading));
    }
  );

  server.registerTool(
    "scan_paths",
    {
      title: "Scan files or folders",
      description: "Scan specific files or folders in the project (relative paths). Follows data flow across the files you include.",
      inputSchema: { paths: z.array(z.string().max(500)).min(1).max(200) },
    },
    async ({ paths }) => {
      const files: Array<{ path: string; code: string }> = [];
      const walk = (abs: string) => {
        const st = statSync(abs);
        if (st.isDirectory()) {
          for (const name of readdirSync(abs)) if (!name.startsWith(".") && name !== "node_modules") walk(resolve(abs, name));
        } else if (st.isFile() && st.size < 500_000 && detectLanguage(abs) !== "unknown" && files.length < 400) {
          files.push({ path: relative(root, abs), code: readFileSync(abs, "utf8") });
        }
      };
      for (const p of paths) walk(insideRoot(root, p));
      const findings = scanProject(files).flatMap((r) => r.findings);
      return text(formatForAgent(findings, `AegisCode: scanned ${files.length} file(s).`));
    }
  );

  server.registerTool(
    "check_packages",
    {
      title: "Check package names before adding them",
      description:
        "Check that packages you are about to import or install actually exist on npm / PyPI and aren't lookalikes of popular packages, brand new, deprecated or running install scripts. Call this before adding a dependency.",
      inputSchema: {
        packages: z.array(z.string().max(214)).min(1).max(50),
        registry: z.enum(["npm", "PyPI"]).default("npm"),
      },
    },
    async ({ packages, registry }) => {
      const refs: PackageRef[] = packages.map((name, i) => ({ name, registry, file: "(request)", line: i + 1, snippet: name, via: "manifest" }));
      const res = await checkPackages(refs);
      const flagged = new Set(res.findings.map((f) => f.snippet));
      const ok = packages.filter((p) => !flagged.has(p) && !res.unchecked.includes(p));
      const lines = res.findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title.replace(/`/g, "")} (${f.ruleId}) — ${f.remediation}`);
      return text(
        [`AegisCode package check (${registry}):`, ...(lines.length ? lines : ["No problems found."]), ok.length ? `OK: ${ok.join(", ")}` : "", res.unchecked.length ? `NOT CHECKED (registry unreachable): ${res.unchecked.join(", ")} — verify these by hand before installing.` : ""]
          .filter(Boolean)
          .join("\n")
      );
    }
  );

  server.registerTool(
    "explain_rule",
    {
      title: "Explain a rule",
      description: "Explain an AegisCode rule id (e.g. AEG-TAINT-SQL): what it detects, why it matters and how to fix it.",
      inputSchema: { id: z.string().max(40) },
    },
    async ({ id }) => {
      const rule = ruleCatalog().find((r) => r.id.toLowerCase() === id.toLowerCase());
      if (!rule) return text(`Unknown rule ${id}.`);
      return text(`${rule.id} — ${rule.title} (${rule.severity}, ${rule.cwe.join(", ")}${rule.owasp ? `, ${rule.owasp}` : ""})\n${rule.description}\nFix: ${rule.remediation}`);
    }
  );

  return server;
}

export async function runMcpServer() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  // stdout belongs to the protocol; diagnostics go to stderr.
  console.error(`aegiscode MCP server ${ENGINE_VERSION} ready on stdio`);
  await new Promise<void>((resolveClose) => process.stdin.on("close", resolveClose));
}
