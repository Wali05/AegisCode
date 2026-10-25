export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type Language =
  | "javascript"
  | "typescript"
  | "python"
  | "go"
  | "java"
  | "php"
  | "ruby"
  | "csharp"
  | "rust"
  | "c"
  | "cpp"
  | "shell"
  | "json"
  | "unknown";

export type FindingCategory =
  | "injection"
  | "xss"
  | "secrets"
  | "crypto"
  | "ssrf"
  | "path-traversal"
  | "deserialization"
  | "auth"
  | "config"
  | "dos"
  | "prototype-pollution"
  | "redirect"
  | "memory-safety"
  | "code-quality"
  | "performance"
  | "dependency";

/** Which part of the pipeline produced a finding. */
export type Detector = "taint" | "pattern" | "secret" | "metric" | "swarm" | "osv";

export type FindingStatus = "open" | "confirmed" | "disputed" | "dismissed";

export interface SourceLocation {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface TraceStep {
  kind: "source" | "propagation" | "sink";
  line: number;
  label: string;
  snippet: string;
  /** Set when the step lives in a different file from the finding (cross-file flows). */
  file?: string;
}

export interface Ruling {
  upheld: boolean;
  rationale: string;
  defenderStance?: "concede" | "dispute" | "mitigate";
}

export interface Finding {
  /** Stable fingerprint, independent of run order. */
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  /** 0..1 — how sure the detector is that this is a true positive. */
  confidence: number;
  category: FindingCategory;
  cwe: string[];
  owasp?: string;
  file: string;
  location: SourceLocation;
  snippet: string;
  remediation: string;
  detector: Detector;
  trace?: TraceStep[];
  status: FindingStatus;
  ruling?: Ruling;
}

export interface FunctionMetric {
  name: string;
  line: number;
  endLine: number;
  loc: number;
  complexity: number;
  maxNesting: number;
  params: number;
}

export interface FileMetrics {
  loc: number;
  sloc: number;
  commentLines: number;
  functions: FunctionMetric[];
  /** Whole-file McCabe complexity (sum of decision points + 1). */
  complexity: number;
  /** Microsoft-normalised maintainability index, 0..100. */
  maintainability: number;
  halsteadVolume: number;
}

export interface TriageSignal {
  label: string;
  weight: number;
}

export interface Triage {
  /** Probability (0..1) that the file deserves adversarial review. */
  risk: number;
  escalate: boolean;
  signals: TriageSignal[];
}

export interface FileReport {
  path: string;
  language: Language;
  findings: Finding[];
  metrics: FileMetrics;
  triage: Triage;
  score: number;
  grade: Grade;
  durationMs: number;
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string[];
  owasp?: string;
  languages: Language[] | "*";
  detector: Detector;
  description: string;
  remediation: string;
}
