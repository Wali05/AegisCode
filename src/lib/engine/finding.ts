import type { Finding, RuleMeta, Severity, SourceLocation, TraceStep, Detector } from "./types";

/** 32-bit FNV-1a, rendered as base36. Deterministic across runtimes. */
export function fnv1a(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

export function fingerprint(ruleId: string, file: string, snippet: string, line: number): string {
  const norm = snippet.replace(/\s+/g, " ").trim();
  return `${ruleId}-${fnv1a(`${file}|${norm}|${line}`)}`;
}

export interface FindingInput {
  rule: Pick<RuleMeta, "id" | "title" | "severity" | "category" | "cwe" | "owasp" | "description" | "remediation">;
  file: string;
  location: SourceLocation;
  snippet: string;
  confidence: number;
  detector: Detector;
  trace?: TraceStep[];
  severity?: Severity;
  title?: string;
  description?: string;
}

export function makeFinding(input: FindingInput): Finding {
  const { rule } = input;
  const snippet = input.snippet.trim().slice(0, 240);
  return {
    id: fingerprint(rule.id, input.file, snippet, input.location.line),
    ruleId: rule.id,
    title: input.title ?? rule.title,
    description: input.description ?? rule.description,
    severity: input.severity ?? rule.severity,
    confidence: Math.round(Math.max(0, Math.min(1, input.confidence)) * 100) / 100,
    category: rule.category,
    cwe: rule.cwe,
    owasp: rule.owasp,
    file: input.file,
    location: input.location,
    snippet,
    remediation: rule.remediation,
    detector: input.detector,
    trace: input.trace,
    status: "open",
  };
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    b.confidence - a.confidence ||
    a.location.line - b.location.line
  );
}

/**
 * Collapse findings that describe the same issue on the same line. Taint
 * findings carry a full source→sink trace, so they win over the pattern rule
 * that flagged the same sink.
 */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const priority: Record<Detector, number> = { taint: 5, swarm: 4, secret: 3, osv: 3, supply: 3, pattern: 2, metric: 1 };
  const byKey = new Map<string, Finding>();
  for (const f of findings) {
    // Quality findings are distinct per rule; security findings collapse per weakness class.
    const key = `${f.file}:${f.location.line}:${f.detector === "metric" ? f.ruleId : f.category}`;
    const existing = byKey.get(key);
    if (!existing || priority[f.detector] > priority[existing.detector] || (priority[f.detector] === priority[existing.detector] && SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity])) {
      byKey.set(key, f);
    }
  }
  return [...byKey.values()].sort(compareFindings);
}
