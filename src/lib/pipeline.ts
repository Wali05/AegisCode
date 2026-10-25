import { scanProject, type EngineStage } from "./engine";
import type { FileReport, Finding, Language, Severity } from "./engine/types";
import { SEVERITIES } from "./engine/types";
import { compareFindings } from "./engine/finding";
import { aggregateScore, gradeFor, securityScore } from "./engine/score";
import { PATTERN_RULES } from "./engine/rules/patterns";
import { SECRET_RULES } from "./engine/secrets";
import { SINKS } from "./engine/taint/model";
import { QUALITY_RULES } from "./engine/quality";
import { isManifest, parseManifest } from "./deps/manifests";
import { scanDependencies } from "./deps/osv";
import { checkPackages, extractPackageRefs, PACKAGE_RULE_LIST } from "./deps/packages";
import { detectLanguage } from "./engine/language";
import { GitHubClient, GitHubError, parseGitHubUrl, selectFiles } from "./github";
import type { LlmProvider } from "./swarm/provider";
import { runSwarm } from "./swarm/run";
import { mapLimit } from "./util/concurrency";
import type { AuditReport, AuditTarget, PipelineEvent, StageId, StageRecord, StageStatus, SwarmResult, SwarmSkipped } from "./report/types";

export const ENGINE_VERSION = "2.0.0";
export const RULE_COUNT = PATTERN_RULES.length + SECRET_RULES.length + new Set(SINKS.map((s) => s.id)).size + Object.keys(QUALITY_RULES).length + PACKAGE_RULE_LIST.length;

export type SwarmMode = "auto" | "force" | "off";

export interface AuditInput {
  url?: string;
  code?: string;
  filename?: string;
  swarm: SwarmMode;
}

export interface PipelineDeps {
  github: GitHubClient;
  provider: LlmProvider | null;
  maxRepoFiles: number;
  signal?: AbortSignal;
}

const MAX_SOURCE_BYTES = 1_500_000;
const ENGINE_STAGES: StageId[] = ["parse", "taint", "patterns", "secrets", "metrics"];

export async function runAudit(input: AuditInput, deps: PipelineDeps, emit: (e: PipelineEvent) => void): Promise<AuditReport> {
  const started = Date.now();
  const stages = new Map<StageId, StageRecord>();
  const stage = (id: StageId, status: StageStatus, detail?: string, ms?: number) => {
    const rec: StageRecord = { id, status, detail, ms };
    stages.set(id, rec);
    emit({ type: "stage", stage: rec });
  };
  const log = (level: "info" | "warn" | "error" | "success", scope: string, message: string) => emit({ type: "log", level, scope, message, t: Date.now() });

  // ── Ingest ────────────────────────────────────────────────────────────────
  stage("ingest", "running");
  const tIngest = Date.now();
  let target: AuditTarget;
  let files: Array<{ path: string; content: string }> = [];
  let manifests: Array<{ path: string; content: string }> = [];

  if (input.code !== undefined) {
    const path = input.filename?.trim() || "snippet.ts";
    target = { label: path, kind: "snippet", path };
    files = [{ path, content: input.code }];
    log("info", "ingest", `Received ${input.code.split("\n").length} lines pasted as ${path}.`);
  } else {
    const parsed = parseGitHubUrl(input.url ?? "");
    if (parsed.kind === "file") {
      log("info", "github", `Resolving ${parsed.owner}/${parsed.repo}/${parsed.segments.join("/")}…`);
      const file = await deps.github.resolveFile(parsed.owner, parsed.repo, parsed.segments);
      const commit = await deps.github.lastCommit(parsed.owner, parsed.repo, file.ref, file.path);
      target = { label: `${parsed.owner}/${parsed.repo} · ${file.path}`, kind: "file", url: input.url, owner: parsed.owner, repo: parsed.repo, ref: file.ref, path: file.path, commit };
      files = [{ path: file.path, content: file.content }];
      log("info", "github", `Fetched ${file.path} @ ${file.ref} (${(file.content.length / 1024).toFixed(1)} KB)${commit ? ` — last touched by ${commit.author}` : ""}.`);
    } else {
      log("info", "github", `Reading repository ${parsed.owner}/${parsed.repo}…`);
      const info = await deps.github.repoInfo(parsed.owner, parsed.repo);
      const { ref, subpath } = await deps.github.resolveTreeRef(parsed.owner, parsed.repo, parsed.segments, info.defaultBranch);
      const tree = await deps.github.tree(parsed.owner, parsed.repo, ref);
      const selection = selectFiles(tree.entries, deps.maxRepoFiles, subpath);
      if (!selection.sources.length && !selection.manifests.length) throw new GitHubError("No analysable source files found.", 422, "AegisCode reads JS/TS, Python, Go, Java/Kotlin, PHP, Ruby, C#, Rust, C/C++ and shell.");
      log("info", "triage", `Ranked ${selection.considered} files by attack surface → auditing the top ${selection.sources.length}${selection.skipped ? ` (${selection.skipped} lower-risk files skipped)` : ""}.`);
      const fetched = await mapLimit([...selection.sources, ...selection.manifests], 8, async (e) => ({ path: e.path, content: (await deps.github.raw(parsed.owner, parsed.repo, ref, e.path)) ?? "" }));
      files = fetched.slice(0, selection.sources.length).filter((f) => f.content);
      manifests = fetched.slice(selection.sources.length).filter((f) => f.content);
      target = { label: `${parsed.owner}/${parsed.repo}${subpath ? `/${subpath}` : ""}`, kind: "repo", url: input.url, owner: parsed.owner, repo: parsed.repo, ref, path: subpath || undefined, repoInfo: info };
      if (tree.truncated) log("warn", "github", "Repository tree is very large; GitHub truncated the listing.");
    }
  }
  stage("ingest", "done", target.kind === "repo" ? `${files.length} files · ${manifests.length} manifests` : `${files[0].content.split("\n").length} lines`, Date.now() - tIngest);

  // ── Static engine ─────────────────────────────────────────────────────────
  const single = files.length === 1;
  const stageTotals = new Map<StageId, { ms: number; detail: string }>();
  const reports: FileReport[] = [];
  if (single) for (const s of ENGINE_STAGES) stage(s, "running");

  const progress = new Set<string>();
  const projectReports = scanProject(
    files.map((f) => ({ path: f.path, code: f.content })),
    {},
    (s: EngineStage, path: string) => {
      const prev = stageTotals.get(s.stage) ?? { ms: 0, detail: "" };
      stageTotals.set(s.stage, { ms: prev.ms + s.ms, detail: s.detail });
      if (single) stage(s.stage, "done", s.detail, s.ms);
      else if (!progress.has(path)) {
        if (!progress.size) for (const st of ENGINE_STAGES) stage(st, "running");
        progress.add(path);
      }
    }
  );
  reports.push(...projectReports);
  if (!single) {
    reports.forEach((r, i) => emit({ type: "file", path: r.path, score: r.score, grade: r.grade, findings: r.findings.length, index: i + 1, total: reports.length }));
    const crossFile = reports.flatMap((r) => r.findings).filter((f) => f.trace?.some((st) => st.file && st.file !== f.file)).length;
    if (crossFile) log("info", "engine", `Followed ${crossFile} data flow${crossFile === 1 ? "" : "s"} across file boundaries.`);
  }

  if (!single) {
    const all = reports.flatMap((r) => r.findings);
    const counts = (pred: (f: Finding) => boolean) => all.filter(pred).length;
    const details: Record<string, string> = {
      parse: `${reports.length} files parsed`,
      taint: `${counts((f) => f.detector === "taint")} source→sink flows`,
      patterns: `${counts((f) => f.detector === "pattern")} pattern matches`,
      secrets: `${counts((f) => f.detector === "secret")} credentials`,
      metrics: `${reports.reduce((n, r) => n + r.metrics.functions.length, 0)} functions measured`,
    };
    for (const s of ENGINE_STAGES) stage(s, "done", details[s], Math.round((stageTotals.get(s)?.ms ?? 0) * 10) / 10);
  }
  const staticCount = reports.reduce((n, r) => n + r.findings.length, 0);
  log("success", "engine", `Static engine finished: ${staticCount} finding${staticCount === 1 ? "" : "s"} across ${reports.length} file${reports.length === 1 ? "" : "s"}.`);

  // ── Dependencies ──────────────────────────────────────────────────────────
  const manifestFiles = [...files.filter((f) => isManifest(f.path)), ...manifests];
  let dependencies: AuditReport["dependencies"] = null;
  let depFindings: Finding[] = [];
  if (manifestFiles.length) {
    stage("deps", "running");
    const t0 = Date.now();
    const parsedDeps = manifestFiles.flatMap((m) => parseManifest(m.path, m.content));
    try {
      const res = await scanDependencies(parsedDeps, deps.signal);
      depFindings = res.findings;
      dependencies = { scanned: res.scanned, vulnerable: res.vulnerable, manifests: manifestFiles.map((m) => m.path) };
      stage("deps", "done", `${res.scanned} packages · ${res.vulnerable} vulnerable`, Date.now() - t0);
      log(res.vulnerable ? "warn" : "success", "osv", `OSV.dev: ${res.vulnerable} of ${res.scanned} packages have known advisories.`);
    } catch (err) {
      dependencies = { scanned: parsedDeps.length, vulnerable: 0, manifests: manifestFiles.map((m) => m.path), error: err instanceof Error ? err.message : "OSV unavailable" };
      stage("deps", "error", "OSV.dev unreachable", Date.now() - t0);
      log("warn", "osv", "Dependency advisories unavailable (OSV.dev unreachable); continuing without them.");
    }
  } else {
    stage("deps", "skipped", "no manifests");
  }

  // ── Package check ─────────────────────────────────────────────────────────
  let packages: AuditReport["packages"] = null;
  const localRoots = new Set([...files, ...manifests].flatMap((f) => [f.path.split("/")[0], f.path.split("/").pop()!.replace(/\.\w+$/, "")]));
  const refs = [...files, ...manifests].flatMap((f) => extractPackageRefs(f.path, f.content, detectLanguage(f.path, f.content), localRoots));
  if (refs.length) {
    stage("packages", "running");
    const t0 = Date.now();
    const res = await checkPackages(refs, { signal: deps.signal });
    depFindings = [...depFindings, ...res.findings];
    packages = { checked: res.checked, flagged: new Set(res.findings.map((f) => f.snippet)).size, skippedPopular: res.skippedPopular, unreachable: res.unreachable };
    const detail = res.unreachable === res.checked && res.checked > 0 ? "registries unreachable" : `${res.checked + res.skippedPopular} packages · ${res.findings.length} flagged`;
    stage("packages", res.unreachable === res.checked && res.checked > 0 ? "error" : "done", detail, Date.now() - t0);
    const missing = res.findings.filter((f) => f.ruleId === "AEG-PKG-001").length;
    if (missing) log("warn", "packages", `${missing} imported package${missing === 1 ? " does" : "s do"} not exist on the registry — likely invented by an AI assistant.`);
    else log("success", "packages", `Checked ${res.checked} package${res.checked === 1 ? "" : "s"} against npm / PyPI (${res.skippedPopular} well-known ones skipped).`);
  } else {
    stage("packages", "skipped", "no third-party imports");
  }

  // ── Triage + swarm ────────────────────────────────────────────────────────
  stage("triage", "running");
  const candidate = [...reports].sort((a, b) => b.triage.risk - a.triage.risk)[0];
  let swarm: SwarmResult | SwarmSkipped;
  let mergedForCandidate: Finding[] | null = null;
  const pct = candidate ? Math.round(candidate.triage.risk * 100) : 0;

  const skip = (reason: string, short: string) => {
    swarm = { status: "skipped", reason };
    for (const s of ["critic", "defender", "judge", "verify"] as StageId[]) stage(s, "skipped", short);
  };

  if (!candidate) {
    stage("triage", "done", "nothing to triage");
    skip("No source files to review.", "no source files");
  } else if (input.swarm === "off") {
    stage("triage", "done", `risk ${pct}% · swarm disabled`);
    skip("Adversarial swarm disabled for this run.", "disabled");
  } else if (!deps.provider) {
    stage("triage", "done", `risk ${pct}% · no LLM configured`);
    skip("Static-only mode: set GEMINI_API_KEY on the server to enable the Critic → Defender → Judge swarm.", "static-only mode");
  } else if (!candidate.triage.escalate && input.swarm !== "force") {
    stage("triage", "done", `risk ${pct}% < 50% — LLM review not needed`);
    log("success", "triage", `Risk model scored ${candidate.path} at ${pct}% — below the escalation threshold, saving 3 LLM calls.`);
    skip(`Triage risk ${pct}% is below the 50% escalation threshold, so the LLM swarm was not needed.`, "not escalated");
  } else {
    stage("triage", "done", `risk ${pct}% → escalating ${candidate.path}`);
    log("info", "triage", `Risk ${pct}% (${candidate.triage.signals.slice(0, 3).map((s) => s.label).join(", ")}) — deploying the adversarial swarm.`);
    try {
      const source = files.find((f) => f.path === candidate.path)!.content;
      const outcome = await runSwarm({ provider: deps.provider, report: candidate, code: source, signal: deps.signal, emit, stage });
      swarm = outcome.result;
      mergedForCandidate = outcome.findings;
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown error";
      log("error", "swarm", `Swarm failed: ${message}. Static results are still complete.`);
      swarm = { status: "failed", reason: `The LLM swarm failed (${message}). Static analysis results are unaffected.` };
      for (const s of ["critic", "defender", "judge", "verify"] as StageId[]) if (stages.get(s)?.status !== "done") stage(s, "error", "swarm failed");
    }
  }

  // ── Assemble ──────────────────────────────────────────────────────────────
  if (mergedForCandidate && candidate) {
    candidate.findings = mergedForCandidate;
    candidate.score = securityScore(mergedForCandidate);
    candidate.grade = gradeFor(candidate.score);
  }
  const findings = [...reports.flatMap((r) => r.findings), ...depFindings].sort(compareFindings);
  const open = findings.filter((f) => f.status !== "dismissed");
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  const languages: Partial<Record<Language, number>> = {};
  for (const r of reports) languages[r.language] = (languages[r.language] ?? 0) + r.metrics.loc;
  const score = aggregateScore(reports, depFindings, reports.flatMap((r) => r.findings));

  const sources: Record<string, string> = {};
  let budget = MAX_SOURCE_BYTES;
  const withFindings = new Set(findings.map((f) => f.file));
  for (const f of [...files, ...manifests]) {
    if (!single && !withFindings.has(f.path)) continue;
    if (f.content.length > budget) continue;
    sources[f.path] = f.content;
    budget -= f.content.length;
  }

  return {
    id: crypto.randomUUID(),
    version: 2,
    createdAt: new Date().toISOString(),
    target: target!,
    summary: {
      score,
      grade: gradeFor(score),
      counts,
      dismissed: findings.length - open.length,
      files: reports.length,
      loc: reports.reduce((n, r) => n + r.metrics.loc, 0),
      languages,
      durationMs: Date.now() - started,
    },
    findings,
    files: reports,
    sources,
    dependencies,
    packages,
    swarm: swarm!,
    stages: [...stages.values()],
    engine: { version: ENGINE_VERSION, rules: RULE_COUNT },
  };
}
