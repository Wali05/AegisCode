import type { FileReport, Finding, Grade, Language, Ruling, Severity } from "../engine/types";
import type { CommitInfo, RepoInfo } from "../github";

export type StageId =
  | "ingest"
  | "parse"
  | "taint"
  | "patterns"
  | "secrets"
  | "metrics"
  | "deps"
  | "packages"
  | "triage"
  | "critic"
  | "defender"
  | "judge"
  | "verify";

export type StageStatus = "pending" | "running" | "done" | "skipped" | "error";

export interface StageRecord {
  id: StageId;
  status: StageStatus;
  ms?: number;
  detail?: string;
}

export interface DebateClaim {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cwe: string;
  line_start: number;
  line_end: number;
  evidence: string;
  exploit: string;
  related_finding: string;
  grounding: { grounded: boolean; relocated: boolean; note: string };
  defender?: { stance: "concede" | "dispute" | "mitigate"; argument: string; fix: string };
  ruling?: { upheld: boolean; severity: Severity; confidence: number; rationale: string };
}

export interface AgentRun {
  agent: "critic" | "defender" | "judge";
  model: string;
  ms: number;
  inputTokens: number;
  outputTokens: number;
  repaired: boolean;
}

export interface PatchVerification {
  code: string;
  parses: boolean | null;
  diagnostics: string[];
  before: { score: number; grade: Grade; findings: number };
  after: { score: number; grade: Grade; findings: number };
  resolved: number;
  introduced: number;
}

export interface SwarmResult {
  status: "completed";
  file: string;
  provider: string;
  model: string;
  summary: string;
  claims: DebateClaim[];
  stats: { claims: number; grounded: number; ungrounded: number; upheld: number; overruled: number; confirmedStatic: number; dismissedStatic: number; novel: number };
  agents: AgentRun[];
  patch: PatchVerification | null;
}

export interface SwarmSkipped {
  status: "skipped" | "failed";
  reason: string;
}

export interface AuditTarget {
  label: string;
  kind: "file" | "repo" | "snippet";
  url?: string;
  owner?: string;
  repo?: string;
  ref?: string;
  path?: string;
  commit?: CommitInfo | null;
  repoInfo?: RepoInfo | null;
}

export interface AuditSummary {
  score: number;
  grade: Grade;
  counts: Record<Severity, number>;
  dismissed: number;
  files: number;
  loc: number;
  languages: Partial<Record<Language, number>>;
  durationMs: number;
}

export interface AuditReport {
  id: string;
  version: 2;
  createdAt: string;
  target: AuditTarget;
  summary: AuditSummary;
  findings: Finding[];
  files: FileReport[];
  /** File contents for the source viewer (all of them for single files; only files with findings for repos). */
  sources: Record<string, string>;
  dependencies: { scanned: number; vulnerable: number; manifests: string[]; error?: string } | null;
  /** Registry check of every imported / declared package (hallucinated, lookalike, brand-new…). */
  packages: { checked: number; flagged: number; skippedPopular: number; unreachable: number } | null;
  swarm: SwarmResult | SwarmSkipped;
  stages: StageRecord[];
  engine: { version: string; rules: number };
  cached?: boolean;
}

export type PipelineEvent =
  | { type: "stage"; stage: StageRecord }
  | { type: "log"; level: "info" | "warn" | "error" | "success"; scope: string; message: string; t: number }
  | { type: "file"; path: string; score: number; grade: Grade; findings: number; index: number; total: number }
  | { type: "claim"; claim: DebateClaim }
  | { type: "report"; report: AuditReport }
  | { type: "error"; message: string; hint?: string; status: number };

export type { Ruling };
