import type { FileReport, Finding, Language } from "./types";
import { buildViews, LineIndex } from "./lexer";
import { detectLanguage, isJsFamily } from "./language";
import { runPatternRules } from "./rules/run-patterns";
import { scanSecrets } from "./secrets";
import { analyzeTaint, parseSource } from "./taint/analyzer";
import { ProjectIndex } from "./taint/project";
import { lexicalTaint } from "./taint/lexical";
import { computeMetrics } from "./metrics";
import { analyzeQuality, lexicalQuality } from "./quality";
import { dedupeFindings } from "./finding";
import { PATTERN_RULES } from "./rules/patterns";
import { gradeFor, securityScore, triage } from "./score";

export * from "./types";
export { detectLanguage, LANGUAGE_LABELS } from "./language";
export { securityScore, gradeFor } from "./score";
export { ProjectIndex } from "./taint/project";

export interface ScanOptions {
  language?: Language;
  /** Skip quality/performance checks (used when re-scanning patches). */
  securityOnly?: boolean;
  /** Other files of the same project, so taint can follow imports. */
  project?: ProjectIndex;
}

export interface EngineStage {
  stage: "parse" | "taint" | "patterns" | "secrets" | "metrics";
  ms: number;
  detail: string;
}

/**
 * Runs the full deterministic pipeline on one file. Pure and synchronous —
 * no network, no LLM — so it is safe to run in CI, in the browser, or in tests.
 */
export function scanFile(path: string, code: string, opts: ScanOptions = {}, onStage?: (s: EngineStage) => void): FileReport {
  const t0 = performance.now();
  const lang = opts.language && opts.language !== "unknown" ? opts.language : detectLanguage(path, code);
  const index = new LineIndex(code);
  const views = buildViews(code, lang);
  let mark = performance.now();
  const lap = (stage: EngineStage["stage"], detail: string) => {
    const now = performance.now();
    onStage?.({ stage, ms: Math.round((now - mark) * 10) / 10, detail });
    mark = now;
  };

  let sf = null;
  if (isJsFamily(lang)) {
    sf = parseSource(path, code);
    lap("parse", `${lang} AST · ${sf.statements.length} top-level statements`);
  } else {
    lap("parse", `${lang === "unknown" ? "plain text" : lang} lexical scan`);
  }

  const findings: Finding[] = [];
  const taint = sf ? analyzeTaint(sf, path, opts.project?.importsFor(path)) : lexicalTaint(views, lang, path);
  findings.push(...taint);
  lap("taint", `${taint.length} source→sink flow${taint.length === 1 ? "" : "s"}`);

  const patterns = runPatternRules(views, lang, path, index);
  // JS/TS (AST) and Python/PHP (lexical) have taint analysis; elsewhere patterns are the only signal.
  findings.push(...(sf || lang === "python" || lang === "php" ? demoteUntraced(patterns, taint) : patterns));
  lap("patterns", `${patterns.length} pattern match${patterns.length === 1 ? "" : "es"}`);

  const secrets = scanSecrets(code, path, index);
  findings.push(...secrets);
  lap("secrets", `${secrets.length} credential${secrets.length === 1 ? "" : "s"}`);

  const metrics = computeMetrics(views, lang, sf, index);
  if (!opts.securityOnly) {
    findings.push(...(sf ? analyzeQuality(sf, path, metrics) : lexicalQuality(path, metrics, (l) => index.lineText(l))));
  }
  lap("metrics", `${metrics.functions.length} functions · MI ${metrics.maintainability}`);

  const deduped = applySuppressions(dedupeFindings(findings), code);
  const score = securityScore(deduped);
  return {
    path,
    language: lang,
    findings: deduped,
    metrics,
    triage: triage(path, deduped, metrics),
    score,
    grade: gradeFor(score),
    durationMs: Math.round((performance.now() - t0) * 10) / 10,
  };
}

const TAINT_COVERED = new Set(PATTERN_RULES.filter((r) => r.taintCovered).map((r) => r.id));

/**
 * Where the AST taint engine ran, a dangerous-looking call it could not connect
 * to untrusted input is a review hint, not a vulnerability. Keeps the signal
 * (e.g. stored XSS from a database value) without inflating the score.
 */
function demoteUntraced(patterns: Finding[], taint: Finding[]): Finding[] {
  const traced = new Set(taint.map((t) => `${t.location.line}:${t.category}`));
  return patterns.map((f) =>
    TAINT_COVERED.has(f.ruleId) && !traced.has(`${f.location.line}:${f.category}`)
      ? {
          ...f,
          severity: "info" as const,
          confidence: Math.round(f.confidence * 50) / 100,
          title: `Review: ${f.title.charAt(0).toLowerCase()}${f.title.slice(1)}`,
          description: `${f.description} Data-flow analysis did not trace untrusted input to this line, so it is listed for review rather than as a vulnerability.`,
        }
      : f
  );
}

/**
 * Scans a set of files as one project. JS/TS taint analysis follows imports
 * between the files, and findings are filed under the file that contains the
 * sink (cross-file flows are discovered while analysing the caller).
 */
export function scanProject(files: Array<{ path: string; code: string }>, opts: Omit<ScanOptions, "project"> = {}, onStage?: (s: EngineStage, path: string) => void): FileReport[] {
  const jsFiles = files.filter((f) => isJsFamily(detectLanguage(f.path, f.code)));
  const project = jsFiles.length > 1 ? new ProjectIndex(jsFiles) : undefined;
  const reports = files.map((f) => scanFile(f.path, f.code, { ...opts, project }, onStage ? (s) => onStage(s, f.path) : undefined));
  if (!project) return reports;

  const byPath = new Map(reports.map((r) => [r.path, r]));
  const moved = new Map<string, Finding[]>();
  for (const r of reports) {
    const keep: Finding[] = [];
    for (const f of r.findings) {
      if (f.file === r.path || !byPath.has(f.file)) keep.push(f);
      else moved.set(f.file, [...(moved.get(f.file) ?? []), f]);
    }
    r.findings = keep;
  }
  for (const [path, extra] of moved) {
    const r = byPath.get(path)!;
    const code = files.find((f) => f.path === path)!.code;
    r.findings = applySuppressions(dedupeFindings([...r.findings, ...extra]), code);
    r.score = securityScore(r.findings);
    r.grade = gradeFor(r.score);
    r.triage = triage(r.path, r.findings, r.metrics);
  }
  return reports;
}

const SUPPRESS = /aegis-ignore(-file)?(?:[:\s]+((?:AEG-[\w-]+|GHSA-[\w-]+|CVE-[\d-]+)(?:\s*,\s*(?:AEG-[\w-]+|GHSA-[\w-]+|CVE-[\d-]+))*))?(?:\s+--\s*(.*?))?(?:\*\/|-->|$)/;

/**
 * Inline suppressions, in any comment syntax:
 *   // aegis-ignore AEG-JS-008 -- output is escaped    (this line and the next)
 *   # aegis-ignore-file -- intentionally vulnerable fixtures
 * Suppressed findings stay in the report as dismissed, with the justification.
 */
export function applySuppressions(findings: Finding[], code: string): Finding[] {
  if (!code.includes("aegis-ignore")) return findings;
  const lines = code.split("\n");
  const rules: Array<{ line: number; file: boolean; ids: string[] | null; reason: string }> = [];
  lines.forEach((text, i) => {
    const m = SUPPRESS.exec(text);
    if (m) rules.push({ line: i + 1, file: !!m[1], ids: m[2] ? m[2].split(/\s*,\s*/) : null, reason: m[3]?.trim() || "no justification given" });
  });
  return findings.map((f) => {
    const hit = rules.find((r) => (r.file || f.location.line === r.line || f.location.line === r.line + 1) && (!r.ids || r.ids.includes(f.ruleId)));
    return hit ? { ...f, status: "dismissed" as const, ruling: { upheld: false, rationale: `Suppressed inline (line ${hit.line}): ${hit.reason}` } } : f;
  });
}
