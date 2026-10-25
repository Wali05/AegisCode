import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { scanProject } from "../lib/engine";
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

const USAGE = `AegisCode ${ENGINE_VERSION} — static security analysis (taint flows, ${RULE_COUNT} rules, secrets, OSV)

Usage
  aegis scan <path...> [options]

Options
  --sarif <file>      write SARIF 2.1.0 (GitHub Code Scanning)
  --json <file>       write the full findings as JSON
  --md <file>         write a Markdown report
  --fail-on <sev>     exit 1 if an open finding is at or above: critical | high | medium | low
  --max-files <n>     audit at most n files, ranked by attack surface (default 1000)
  --no-deps           skip network checks (OSV advisories and the npm / PyPI package check)
  --quiet             only print the summary line
`;

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = { dim: paint("2"), bold: paint("1"), red: paint("38;5;204"), orange: paint("38;5;208"), yellow: paint("38;5;221"), blue: paint("38;5;75"), gray: paint("38;5;245"), lime: paint("38;5;154") };
const SEV_COLOR: Record<Severity, (s: string) => string> = { critical: c.red, high: c.orange, medium: c.yellow, low: c.blue, info: c.gray };

interface Args {
  paths: string[];
  sarif?: string;
  json?: string;
  md?: string;
  failOn?: Severity;
  maxFiles: number;
  deps: boolean;
  quiet: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { paths: [], maxFiles: 1000, deps: true, quiet: false };
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

export async function main(argv: string[]): Promise<number> {
  if (argv[0] !== "scan" || argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(USAGE);
    return argv[0] === "scan" || argv.includes("--help") || argv.includes("-h") ? 0 : 2;
  }
  const args = parseArgs(argv.slice(1));
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
    for (const report of scanProject(sourceFiles)) {
      files++;
      loc += report.metrics.loc;
      findings.push(...report.findings);
      reports.push(report);
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

  if (!args.quiet) {
    for (const f of open) {
      const sev = SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
      console.log(`${sev} ${c.bold(f.title)}`);
      console.log(`         ${c.dim(`${f.file}:${f.location.line}  ${f.ruleId}  ${f.cwe.join(",")}  conf ${Math.round(f.confidence * 100)}%`)}`);
      if (f.trace?.length) console.log(`         ${c.gray(f.trace.map((s) => `${s.file && s.file !== f.file ? `${s.file}:` : "L"}${s.line} ${s.label}`).join(" → "))}`);
    }
    if (open.length) console.log("");
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

  if (args.failOn) {
    const threshold = SEVERITY_RANK[args.failOn];
    const blocking = open.filter((f) => SEVERITY_RANK[f.severity] >= threshold);
    if (blocking.length) {
      console.error(c.red(`✖ ${blocking.length} finding${blocking.length === 1 ? "" : "s"} at or above ${args.failOn}`));
      return 1;
    }
  }
  return 0;
}
