import { chmodSync, existsSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { applyEdits, scanFile, scanProject } from "../lib/engine";
import type { Finding, Severity } from "../lib/engine/types";
import { SEVERITIES } from "../lib/engine/types";
import { compareFindings, SEVERITY_RANK } from "../lib/engine/finding";
import { aggregateScore, gradeFor } from "../lib/engine/score";
import type { FileReport } from "../lib/engine/types";
import { selectFiles, type TreeEntry } from "../lib/github";
import { isManifest, parseManifest } from "../lib/deps/manifests";
import { scanDependencies } from "../lib/deps/osv";
import { checkPackages, extractPackageRefs } from "../lib/deps/packages";
import { detectLanguage } from "../lib/engine/language";
import { toMarkdown, toSarif } from "../lib/report/export";
import { ENGINE_VERSION, RULE_COUNT } from "../lib/pipeline";
import { diffFindings, toBaseline, type BaselineFile } from "../lib/baseline";
import { repoRoot, scanChanges, type ChangeMode } from "./changes";

const USAGE = `AegisCode ${ENGINE_VERSION} — static security analysis (taint flows, ${RULE_COUNT} rules, secrets, packages, OSV)

Usage
  aegis scan [path...] [options]     scan files or folders (default: .)
  aegis scan --staged                only what you're about to commit; reports new issues only
  aegis scan --changed               uncommitted changes vs HEAD
  aegis scan --since <ref>           everything changed since a branch, e.g. --since main
  aegis hook install [--force]       block commits that add high-severity issues
  aegis hook uninstall
  aegis mcp                          run as an MCP server for coding agents (stdio)

Scan options
  --sarif <file>            write SARIF 2.1.0 (GitHub Code Scanning)
  --json <file>             write findings as JSON
  --md <file>               write a Markdown report
  --fail-on <sev>           exit 1 if a (new) finding is at or above: critical | high | medium | low
  --baseline <file>         only report findings that aren't in this baseline
  --write-baseline <file>   save the current findings as a baseline
  --fix                     apply quick fixes that passed verification (edits files in place)
  --max-files <n>           scan at most n files, ranked by attack surface (default 1000)
  --no-deps                 skip network checks (OSV advisories and the npm / PyPI package check)
  --quiet                   only print the summary line
`;

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = { dim: paint("2"), bold: paint("1"), red: paint("38;5;204"), orange: paint("38;5;208"), yellow: paint("38;5;221"), blue: paint("38;5;75"), gray: paint("38;5;245"), lime: paint("38;5;154") };
const SEV_COLOR: Record<Severity, (s: string) => string> = { critical: c.red, high: c.orange, medium: c.yellow, low: c.blue, info: c.gray };

interface Args {
  paths: string[];
  mode?: ChangeMode;
  baseline?: string;
  writeBaseline?: string;
  fix: boolean;
  sarif?: string;
  json?: string;
  md?: string;
  failOn?: Severity;
  maxFiles: number;
  deps: boolean;
  quiet: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { paths: [], maxFiles: 1000, deps: true, quiet: false, fix: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === "--sarif") args.sarif = next();
    else if (a === "--json") args.json = next();
    else if (a === "--md") args.md = next();
    else if (a === "--fail-on") {
      const v = next() as Severity;
      if (!SEVERITIES.includes(v)) throw new Error(`--fail-on must be one of ${SEVERITIES.join(", ")}`);
      args.failOn = v;
    } else if (a === "--max-files") args.maxFiles = Math.max(1, Number(next()) || 1000);
    else if (a === "--no-deps") args.deps = false;
    else if (a === "--staged") args.mode = { kind: "staged" };
    else if (a === "--changed") args.mode = { kind: "working" };
    else if (a === "--since") args.mode = { kind: "since", ref: next() };
    else if (a === "--baseline") args.baseline = next();
    else if (a === "--write-baseline") args.writeBaseline = next();
    else if (a === "--fix") args.fix = true;
    else if (a === "--quiet") args.quiet = true;
    else if (a.startsWith("--")) throw new Error(`Unknown option ${a}`);
    else args.paths.push(a);
  }
  if (!args.paths.length) args.paths.push(".");
  return args;
}

function walk(root: string): TreeEntry[] {
  const out: TreeEntry[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (name.startsWith(".") || name === "node_modules") continue;
      const full = join(dir, name);
      const st = statSync(full);
      if (st.isDirectory()) visit(full);
      else if (st.isFile()) out.push({ path: relative(root, full).split("\\").join("/"), size: st.size, sha: "" });
    }
  };
  if (statSync(root).isFile()) return [{ path: root.split("/").pop()!, size: statSync(root).size, sha: "" }];
  visit(root);
  return out;
}

function printFinding(f: Finding, tag = "") {
  const sev = SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
  console.log(`${sev} ${tag}${c.bold(f.title)}`);
  console.log(`         ${c.dim(`${f.file}:${f.location.line}  ${f.ruleId}  ${f.cwe.join(",")}  conf ${Math.round(f.confidence * 100)}%`)}`);
  if (f.trace?.length) console.log(`         ${c.gray(f.trace.map((s) => `${s.file && s.file !== f.file ? `${s.file}:` : "L"}${s.line} ${s.label}`).join(" → "))}`);
  if (f.fix?.verified) console.log(`         ${c.lime("✓ verified fix:")} ${f.fix.title} ${c.dim("(aegis scan --fix applies it)")}`);
}

/**
 * Applies verified quick fixes in place. Fixes in one file are applied together
 * when they don't overlap, and the file is re-scanned: anything that still
 * reports the issue, or introduces a new one, is backed out one fix at a time.
 */
function applyVerifiedFixes(reports: FileReport[], base: string): { files: number; fixes: number } {
  let files = 0;
  let fixes = 0;
  for (const r of reports) {
    const candidates = r.findings.filter((f) => f.fix?.verified && f.file === r.path);
    if (!candidates.length) continue;
    const abs = join(base, r.path);
    const original = readFileSync(abs, "utf8");
    const ok = (code: string, wanted: Finding[]) => {
      const after = scanFile(r.path, code, { language: r.language }).findings.filter((f) => f.status !== "dismissed" && f.severity !== "info");
      const before = new Set(r.findings.map((f) => `${f.ruleId}:${f.location.line}`));
      const fixedGone = wanted.every((w) => !after.some((a) => a.ruleId === w.ruleId && a.location.line === w.location.line));
      return fixedGone && after.every((a) => before.has(`${a.ruleId}:${a.location.line}`));
    };
    let chosen: Finding[] = [];
    for (const f of candidates) {
      const next = [...chosen, f];
      const edits = next.flatMap((x) => x.fix!.edits).sort((a, b) => a.start - b.start);
      if (edits.some((e, i) => i > 0 && e.start < edits[i - 1].end)) continue; // overlapping edits
      if (ok(applyEdits(original, edits), next)) chosen = next;
    }
    if (!chosen.length) continue;
    writeFileSync(abs, applyEdits(original, chosen.flatMap((x) => x.fix!.edits)));
    files++;
    fixes += chosen.length;
    for (const f of chosen) console.log(`${c.lime("fixed")} ${r.path}:${f.location.line} ${f.fix!.title}`);
  }
  return { files, fixes };
}

function blockingExit(findings: Finding[], failOn: Severity | undefined, what: string): number {
  if (!failOn) return 0;
  const blocking = findings.filter((f) => f.status !== "dismissed" && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);
  if (!blocking.length) return 0;
  console.error(c.red(`✖ ${blocking.length} ${what}finding${blocking.length === 1 ? "" : "s"} at or above ${failOn}`));
  return 1;
}

export async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === "mcp") {
    const { runMcpServer } = await import("./mcp");
    await runMcpServer();
    return 0;
  }
  if (cmd === "hook") return hook(rest);
  if (cmd !== "scan" || argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(USAGE);
    return cmd === "scan" || argv.includes("--help") || argv.includes("-h") ? 0 : 2;
  }
  const args = parseArgs(rest);
  if (args.mode) return scanChangeSet(args);
  const t0 = performance.now();
  const findings: Finding[] = [];
  const reports: FileReport[] = [];
  const depFindings: Finding[] = [];
  let files = 0;
  let loc = 0;

  for (const p of args.paths) {
    const root = resolve(p);
    const isFile = statSync(root).isFile();
    const base = isFile ? resolve(root, "..") : root;
    const entries = walk(root);
    const { sources, manifests } = selectFiles(entries, args.maxFiles);
    const sourceFiles = sources.map((e) => ({ path: e.path, code: readFileSync(join(base, e.path), "utf8") }));
    const projectReports = scanProject(sourceFiles);
    for (const report of projectReports) {
      files++;
      loc += report.metrics.loc;
      findings.push(...report.findings);
      reports.push(report);
    }
    if (args.fix) {
      const applied = applyVerifiedFixes(projectReports, base);
      console.log(c.dim(`fix: applied ${applied.fixes} verified fix${applied.fixes === 1 ? "" : "es"} in ${applied.files} file${applied.files === 1 ? "" : "s"}${applied.fixes ? " — review the diff before committing" : ""}`));
    }
    const manifestPaths = [...manifests.map((m) => m.path), ...(isFile && isManifest(root) ? [entries[0].path] : [])];
    if (args.deps && manifestPaths.length) {
      const deps = manifestPaths.flatMap((m) => parseManifest(m, readFileSync(join(base, m), "utf8")));
      try {
        const res = await scanDependencies(deps);
        findings.push(...res.findings);
        depFindings.push(...res.findings);
        if (!args.quiet) console.log(c.dim(`osv: ${res.vulnerable}/${res.scanned} packages with advisories`));
      } catch (err) {
        console.error(c.yellow(`osv: skipped (${err instanceof Error ? err.message : "unreachable"})`));
      }
    }
    if (args.deps) {
      const all = [...sourceFiles, ...manifestPaths.map((m) => ({ path: m, code: readFileSync(join(base, m), "utf8") }))];
      const roots = new Set(entries.flatMap((e) => [e.path.split("/")[0], e.path.split("/").pop()!.replace(/\.\w+$/, "")]));
      const refs = all.flatMap((f) => extractPackageRefs(f.path, f.code, detectLanguage(f.path, f.code), roots));
      if (refs.length) {
        const res = await checkPackages(refs);
        findings.push(...res.findings);
        depFindings.push(...res.findings);
        if (!args.quiet) console.log(c.dim(`packages: ${res.checked} checked against npm / PyPI · ${res.findings.length} flagged${res.unreachable ? ` · ${res.unreachable} unreachable` : ""}`));
      }
    }
  }

  findings.sort(compareFindings);
  const report = { findings, engine: { version: ENGINE_VERSION, rules: RULE_COUNT } };
  const open = findings.filter((f) => f.status !== "dismissed");

  // With a baseline, only findings that aren't in it are reported and can fail the run.
  let reported = open;
  if (args.baseline) {
    const base = JSON.parse(readFileSync(args.baseline, "utf8")) as BaselineFile;
    const diff = diffFindings(base.findings.map((b) => ({ ...b, status: "open" }) as Finding), open);
    reported = diff.added;
    console.log(c.dim(`baseline: ${diff.added.length} new · ${diff.existing.length} known · ${diff.fixed.length} fixed since ${base.createdAt.slice(0, 10)}`));
  }
  if (args.writeBaseline) {
    writeFileSync(args.writeBaseline, JSON.stringify(toBaseline(open), null, 2));
    console.log(c.dim(`baseline: wrote ${open.length} findings to ${args.writeBaseline}`));
  }

  if (!args.quiet) {
    for (const f of reported) printFinding(f);
    if (reported.length) console.log("");
  }

  const score = aggregateScore(reports, depFindings, reports.flatMap((r) => r.findings));
  const counts = SEVERITIES.map((s) => `${SEV_COLOR[s](String(open.filter((f) => f.severity === s).length))} ${s}`).join(c.dim(" · "));
  const suppressed = findings.length - open.length;
  console.log(`${c.lime("aegis")} ${files} files · ${loc.toLocaleString()} lines · score ${c.bold(String(score))} (${gradeFor(score)}) · ${counts}${suppressed ? c.dim(` · ${suppressed} suppressed`) : ""} · ${Math.round(performance.now() - t0)} ms`);

  if (args.sarif) writeFileSync(args.sarif, JSON.stringify(toSarif(report), null, 2));
  if (args.json) writeFileSync(args.json, JSON.stringify(report, null, 2));
  if (args.md) {
    const counted = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])) as Record<Severity, number>;
    writeFileSync(
      args.md,
      toMarkdown({
        id: "cli",
        version: 2,
        createdAt: new Date().toISOString(),
        target: { label: args.paths.join(", "), kind: "repo" },
        summary: { score, grade: gradeFor(score), counts: counted, dismissed: suppressed, files, loc, languages: {}, durationMs: Math.round(performance.now() - t0) },
        findings,
        files: [],
        sources: {},
        dependencies: null,
        packages: null,
        swarm: { status: "skipped", reason: "CLI runs the deterministic engine only." },
        stages: [],
        engine: report.engine,
      })
    );
  }

  return blockingExit(reported, args.failOn, args.baseline ? "new " : "");
}

async function scanChangeSet(args: Args): Promise<number> {
  const t0 = performance.now();
  const res = await scanChanges(process.cwd(), args.mode!, { packages: args.deps });
  if (!args.quiet) {
    for (const f of res.added) printFinding(f, c.red("NEW "));
    if (res.added.length) console.log("");
  }
  const sev = SEVERITIES.map((s) => `${SEV_COLOR[s](String(res.added.filter((f) => f.severity === s).length))} ${s}`).join(c.dim(" · "));
  console.log(
    `${c.lime("aegis")} ${res.files.length} changed file${res.files.length === 1 ? "" : "s"} (${res.headLabel} vs ${res.baseLabel}) · ${c.bold(String(res.added.length))} new: ${sev} · ${c.lime(String(res.fixed.length))} fixed · ${res.existing.length} pre-existing · ${Math.round(performance.now() - t0)} ms`
  );
  const report = { findings: res.added, engine: { version: ENGINE_VERSION, rules: RULE_COUNT } };
  if (args.sarif) writeFileSync(args.sarif, JSON.stringify(toSarif(report), null, 2));
  if (args.json) writeFileSync(args.json, JSON.stringify({ ...report, fixed: res.fixed, existing: res.existing }, null, 2));
  return blockingExit(res.added, args.failOn, "new ");
}

const HOOK_MARKER = "# installed by aegiscode";

function hook(argv: string[]): number {
  const [action] = argv;
  const root = repoRoot(process.cwd());
  const path = join(root, ".git", "hooks", "pre-commit");
  if (action === "install") {
    if (existsSync(path) && !readFileSync(path, "utf8").includes(HOOK_MARKER) && !argv.includes("--force")) {
      console.error(c.yellow(`A pre-commit hook already exists at ${path}. Re-run with --force to replace it.`));
      return 1;
    }
    const bin = resolve(process.argv[1]);
    writeFileSync(
      path,
      `#!/bin/sh
${HOOK_MARKER}
# Blocks commits that add new issues at or above AEGIS_FAIL_ON (default: high).
# Bypass once with: git commit --no-verify
exec node "${bin}" scan --staged --fail-on "\${AEGIS_FAIL_ON:-high}"
`
    );
    chmodSync(path, 0o755);
    console.log(`${c.lime("aegis")} pre-commit hook installed → ${relative(process.cwd(), path)}`);
    return 0;
  }
  if (action === "uninstall") {
    if (existsSync(path) && readFileSync(path, "utf8").includes(HOOK_MARKER)) {
      unlinkSync(path);
      console.log(`${c.lime("aegis")} pre-commit hook removed`);
    } else console.log("No AegisCode hook installed.");
    return 0;
  }
  process.stdout.write(USAGE);
  return 2;
}
