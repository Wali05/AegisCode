import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanProject } from "../src/lib/engine";
import type { Finding } from "../src/lib/engine/types";

/**
 * Accuracy benchmark over a hand-labelled corpus.
 *
 * Single-file cases declare their expected rules in the first lines
 * (`// expect: AEG-TAINT-SQL` or `// expect: none`). Multi-file cases are
 * folders under `multi/` with an `expect.txt` of `path RULE` lines.
 * Only security findings count: quality/performance and info-level notes are ignored.
 */

export interface CaseResult {
  name: string;
  expected: string[];
  predicted: string[];
  tp: number;
  fp: string[];
  fn: string[];
}

export interface BenchmarkResult {
  cases: CaseResult[];
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  /** Per vulnerability class (rule id with the `AEG-` prefix stripped of its number for pattern rules). */
  byClass: Array<{ cls: string; tp: number; fp: number; fn: number }>;
  ms: number;
}

const counts = (f: Finding) => f.status !== "dismissed" && f.severity !== "info" && f.detector !== "metric";

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function expectedFromHeader(code: string): string[] {
  const m = /expect:\s*([^\n]+)/.exec(code.split("\n").slice(0, 3).join("\n"));
  if (!m) throw new Error("missing `expect:` header");
  const v = m[1].trim();
  return v === "none" ? [] : v.split(/\s*,\s*/);
}

function score(name: string, expected: string[], predicted: string[]): CaseResult {
  const exp = new Set(expected);
  const pred = new Set(predicted);
  return {
    name,
    expected: [...exp],
    predicted: [...pred],
    tp: [...pred].filter((p) => exp.has(p)).length,
    fp: [...pred].filter((p) => !exp.has(p)),
    fn: [...exp].filter((e) => !pred.has(e)),
  };
}

const classOf = (key: string) => {
  const rule = key.split(" ").pop()!;
  return rule.startsWith("AEG-TAINT-") ? rule.slice(10) : rule.startsWith("AEG-SEC-") ? "SECRET" : rule.replace(/^AEG-/, "").replace(/-\d+$/, "") + " patterns";
};

export function runBenchmark(root = join(process.cwd(), "bench/cases")): BenchmarkResult {
  const t0 = performance.now();
  const cases: CaseResult[] = [];
  const multiRoot = join(root, "multi");

  for (const file of walk(root).filter((p) => !p.startsWith(multiRoot)).sort()) {
    const code = readFileSync(file, "utf8");
    const [report] = scanProject([{ path: file.split("/").pop()!, code }]);
    cases.push(score(relative(root, file), expectedFromHeader(code), report.findings.filter(counts).map((f) => f.ruleId)));
  }

  for (const dir of readdirSync(multiRoot).sort()) {
    const base = join(multiRoot, dir);
    const files = walk(base)
      .filter((p) => !p.endsWith("expect.txt"))
      .map((p) => ({ path: relative(base, p), code: readFileSync(p, "utf8") }));
    const expected = readFileSync(join(base, "expect.txt"), "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
    const predicted = scanProject(files).flatMap((r) => r.findings.filter(counts).map((f) => `${f.file} ${f.ruleId}`));
    cases.push(score(`multi/${dir}`, expected, predicted));
  }

  const tp = cases.reduce((n, c) => n + c.tp, 0);
  const fp = cases.reduce((n, c) => n + c.fp.length, 0);
  const fn = cases.reduce((n, c) => n + c.fn.length, 0);
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp + fn ? tp / (tp + fn) : 1;

  const classes = new Map<string, { tp: number; fp: number; fn: number }>();
  const bump = (key: string, field: "tp" | "fp" | "fn") => {
    const c = classes.get(classOf(key)) ?? { tp: 0, fp: 0, fn: 0 };
    c[field]++;
    classes.set(classOf(key), c);
  };
  for (const c of cases) {
    c.predicted.filter((p) => c.expected.includes(p)).forEach((p) => bump(p, "tp"));
    c.fp.forEach((p) => bump(p, "fp"));
    c.fn.forEach((p) => bump(p, "fn"));
  }

  return {
    cases,
    tp,
    fp,
    fn,
    precision,
    recall,
    f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    byClass: [...classes].map(([cls, v]) => ({ cls, ...v })).sort((a, b) => a.cls.localeCompare(b.cls)),
    ms: Math.round(performance.now() - t0),
  };
}

/**
 * How the corpus grew. The first-run scores are recorded by hand at the time a
 * round is added (the engine that produced them no longer exists once the
 * misses are fixed), so they are history, not something `npm run bench` can recompute.
 */
export const ROUNDS: Array<{ where: string; cases: number; written: string; precision: number | null; recall: number | null }> = [
  { where: "Tuning set (`js/`, `py/`, `php/`, `go/`, `c/`, `multi/xfile-*`)", cases: 61, written: "alongside the first engine", precision: null, recall: null },
  { where: "Held-out round 1 (`holdout/`, `multi/holdout-*`)", cases: 26, written: "after the first engine was finished", precision: 94.1, recall: 88.9 },
  { where: "Round 2 (`round2/`)", cases: 67, written: "adversarially, to find what round 1 missed", precision: 82.9, recall: 61.7 },
  { where: "Round 3 (`round3/`, `multi/round3-*`)", cases: 48, written: "after the rewrite that round 2 prompted", precision: 91.3, recall: 77.8 },
];

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

export function toMarkdown(r: BenchmarkResult): string {
  const vulnerable = r.cases.filter((c) => c.expected.length).length;
  const lines = [
    "# Benchmark results",
    "",
    `Generated by \`npm run bench\` over ${r.cases.length} hand-labelled cases (${vulnerable} vulnerable, ${r.cases.length - vulnerable} safe look-alikes) in \`bench/cases\`.`,
    "",
    "| Precision | Recall | F1 | True positives | False positives | False negatives |",
    "|---:|---:|---:|---:|---:|---:|",
    `| ${pct(r.precision)} | ${pct(r.recall)} | ${pct(r.f1)} | ${r.tp} | ${r.fp} | ${r.fn} |`,
    "",
    "## By class",
    "",
    "| Class | TP | FP | FN |",
    "|---|---:|---:|---:|",
    ...r.byClass.map((c) => `| ${c.cls} | ${c.tp} | ${c.fp} | ${c.fn} |`),
    "",
    "## Misses",
    "",
  ];
  const misses = r.cases.filter((c) => c.fp.length || c.fn.length);
  if (!misses.length) lines.push("None.");
  for (const c of misses) {
    if (c.fn.length) lines.push(`- \`${c.name}\` — missed ${c.fn.map((x) => `\`${x}\``).join(", ")}`);
    if (c.fp.length) lines.push(`- \`${c.name}\` — false alarm ${c.fp.map((x) => `\`${x}\``).join(", ")}`);
  }
  lines.push(
    "",
    "## How to read this",
    "",
    "The corpus was written in four rounds. Each later round was run once, before anything was changed, and that first run is the only number here that says something about code the engine hasn't seen.",
    "",
    "| Round | Cases | Written | First run: precision / recall |",
    "|---|---:|---|---:|",
    ...ROUNDS.map((r) => `| ${r.where} | ${r.cases} | ${r.written} | ${r.precision === null ? "n/a" : `${r.precision}% / ${r.recall}%`} |`),
    "",
    "What each first run got wrong:",
    "",
    "- **Held-out round 1**: one false alarm (an imported helper named `execute` mistaken for a database call) and two misses (barrel re-exports, and HTML built inside a helper).",
    "- **Round 2** was written to break the engine rather than to describe it, and it did: 18 misses and 6 false alarms. The analyser applied assignments in program order, so a value tainted in one branch and overwritten in the other came out clean; an HTML escaper cleared a value for SQL; NestJS decorators, Server Actions and Hono weren't sources; one tainted field made a whole object literal tainted. That led to a rewrite of the flow analysis (branch joins, context-aware sanitisers, per-field objects).",
    "- **Round 3** checked the rewrite against patterns it hadn't been tuned on: 6 misses (calls into class-based services, `promisify(exec)`, GraphQL resolver arguments, a TypeORM `.where()` string, a `Location` header) and 2 false alarms (a Zod enum, and a redirect to a fixed path prefix).",
    "",
    "Every miss was fixed after it was recorded, which is why the table at the top shows no misses now. Read the first-run column, not the top table, as the estimate for new code: precision around 90%, recall around 80%.",
    "",
    "None of this is a comparison with other tools; for that you would need an external corpus such as the OWASP Benchmark.",
    ""
  );
  return lines.join("\n");
}
