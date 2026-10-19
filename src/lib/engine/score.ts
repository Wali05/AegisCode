import type { FileMetrics, FileReport, Finding, Grade, Severity, Triage, TriageSignal } from "./types";

const WEIGHT: Record<Severity, number> = { critical: 30, high: 14, medium: 6, low: 1.5, info: 0 };

/**
 * Security score in [0, 100]. Within each severity, confidence-weighted counts
 * grow with a square root (diminishing returns), and the total penalty saturates
 * hyperbolically — so forty lows never outweigh one critical. Any open critical
 * caps the score at 59, any open high at 79.
 */
export function securityScore(findings: Finding[]): number {
  const open = findings.filter((f) => f.status !== "dismissed");
  const mass: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  // Code-quality and performance findings count, but far less than security weaknesses.
  for (const f of open) mass[f.severity] += f.confidence * (f.detector === "metric" ? 0.35 : 1);
  const penalty = (Object.keys(mass) as Severity[]).reduce((sum, s) => sum + WEIGHT[s] * Math.sqrt(mass[s]), 0);
  let score = 100 / (1 + penalty / 45);
  if (open.some((f) => f.severity === "critical")) score = Math.min(score, 59);
  else if (open.some((f) => f.severity === "high")) score = Math.min(score, 79);
  return Math.round(score);
}

/**
 * Score for a set of files: the SLOC-weighted mean of per-file scores (so big
 * repositories aren't punished just for being big), then capped by the worst
 * open finding anywhere — including dependency advisories.
 */
export function aggregateScore(files: Pick<FileReport, "score" | "metrics">[], extra: Finding[] = [], all: Finding[] = []): number {
  if (!files.length) return securityScore(extra);
  const weight = (f: Pick<FileReport, "metrics">) => Math.max(1, f.metrics.sloc);
  const total = files.reduce((n, f) => n + weight(f), 0);
  let score = files.reduce((n, f) => n + f.score * weight(f), 0) / total;
  if (extra.length) score = Math.min(score, securityScore(extra));
  const open = [...all, ...extra].filter((f) => f.status !== "dismissed");
  if (open.some((f) => f.severity === "critical")) score = Math.min(score, 59);
  else if (open.some((f) => f.severity === "high")) score = Math.min(score, 79);
  return Math.round(score);
}

export function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 45) return "D";
  return "F";
}

const SENSITIVE_PATH = /auth|login|session|token|password|crypto|admin|payment|billing|checkout|upload|exec|shell|query|sql|db|database|api|route|controller|handler|middleware|webhook|server/i;

const sigmoid = (z: number) => 1 / (1 + Math.exp(-z));

/**
 * Decides whether a file deserves the (expensive) adversarial LLM review.
 * A transparent logistic model over static signals — every signal is shown to
 * the user so the gate is explainable, not a black box.
 */
export function triage(path: string, findings: Finding[], metrics: FileMetrics): Triage {
  const signals: TriageSignal[] = [];
  const add = (label: string, weight: number) => signals.push({ label, weight: Math.round(weight * 100) / 100 });
  const open = findings.filter((f) => f.status !== "dismissed");
  const count = (s: Severity) => open.filter((f) => f.severity === s).length;

  const taint = open.filter((f) => f.detector === "taint").length;
  if (taint) add(`${taint} source→sink data flow${taint > 1 ? "s" : ""}`, 1.6 + 0.3 * Math.min(taint - 1, 3));
  if (count("critical")) add(`${count("critical")} critical finding${count("critical") > 1 ? "s" : ""}`, 2.2);
  if (count("high")) add(`${count("high")} high-severity finding${count("high") > 1 ? "s" : ""}`, 1.2 + 0.2 * Math.min(count("high") - 1, 3));
  if (count("medium")) add(`${count("medium")} medium finding${count("medium") > 1 ? "s" : ""}`, 0.5 + 0.15 * Math.min(count("medium") - 1, 3));
  if (open.some((f) => f.detector === "secret")) add("hardcoded credential", 1.0);
  if (SENSITIVE_PATH.test(path)) add("security-sensitive path", 0.6);
  const maxCC = Math.max(0, ...metrics.functions.map((f) => f.complexity));
  if (maxCC > 15) add(`function complexity ${maxCC}`, 0.4 + Math.min((maxCC - 15) / 30, 0.6));
  if (metrics.maintainability < 50) add(`maintainability ${metrics.maintainability}/100`, 0.4);
  if (metrics.sloc > 300) add(`${metrics.sloc} SLOC`, 0.3);
  if (metrics.sloc < 15) add("very small file", -0.8);

  const z = -2.4 + signals.reduce((s, x) => s + x.weight, 0);
  const risk = Math.round(sigmoid(z) * 1000) / 1000;
  return { risk, escalate: risk >= 0.5, signals: signals.sort((a, b) => b.weight - a.weight) };
}
