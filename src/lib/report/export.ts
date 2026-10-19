import type { Finding, Severity } from "../engine/types";
import type { AuditReport } from "./types";

const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };
const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

/** SARIF 2.1.0 — uploadable to GitHub Code Scanning via github/codeql-action/upload-sarif. */
export function toSarif(report: Pick<AuditReport, "findings" | "engine">, uriPrefix = ""): object {
  const rules = new Map<string, Finding>();
  for (const f of report.findings) if (!rules.has(f.ruleId)) rules.set(f.ruleId, f);

  const location = (file: string, line: number, column = 1, endLine = line, endColumn?: number) => ({
    physicalLocation: {
      artifactLocation: { uri: `${uriPrefix}${file}`.replace(/^\/+/, ""), uriBaseId: "%SRCROOT%" },
      region: { startLine: Math.max(1, line), startColumn: Math.max(1, column), endLine: Math.max(line, endLine), ...(endColumn && endColumn > 1 ? { endColumn } : {}) },
    },
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AegisCode",
            semanticVersion: report.engine.version,
            informationUri: "https://github.com/Wali05/AegisCode",
            rules: [...rules.values()].map((f) => ({
              id: f.ruleId,
              name: f.ruleId.replace(/[^A-Za-z0-9]/g, ""),
              shortDescription: { text: f.title.split(":")[0] },
              fullDescription: { text: f.description },
              help: { text: f.remediation, markdown: `**Remediation**\n\n${f.remediation}\n\n${f.cwe.map((c) => `- [${c}](https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html)`).join("\n")}` },
              defaultConfiguration: { level: LEVEL[f.severity] },
              properties: {
                tags: ["security", f.category, ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`)],
                "security-severity": SECURITY_SEVERITY[f.severity],
                precision: f.confidence >= 0.8 ? "high" : f.confidence >= 0.5 ? "medium" : "low",
              },
            })),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.description}` },
          locations: [location(f.file, f.location.line, f.location.column, f.location.endLine, f.location.endColumn)],
          partialFingerprints: { aegisFingerprint: f.id },
          ...(f.trace?.length
            ? {
                codeFlows: [
                  {
                    threadFlows: [
                      {
                        locations: f.trace.map((s) => ({ location: { ...location(f.file, s.line), message: { text: s.label } } })),
                      },
                    ],
                  },
                ],
              }
            : {}),
          ...(f.status === "dismissed" ? { suppressions: [{ kind: "external", justification: f.ruling?.rationale ?? "Dismissed by adversarial review." }] } : {}),
          properties: { confidence: f.confidence, detector: f.detector, status: f.status, owasp: f.owasp },
        })),
      },
    ],
  };
}

const ICON: Record<Severity, string> = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };

export function toMarkdown(report: AuditReport): string {
  const { summary, target } = report;
  const open = report.findings.filter((f) => f.status !== "dismissed");
  const lines: string[] = [];
  lines.push(`# AegisCode audit — ${target.label}`, "");
  lines.push(`**Score ${summary.score}/100 · Grade ${summary.grade}** · ${summary.files} file${summary.files === 1 ? "" : "s"} · ${summary.loc.toLocaleString()} lines · ${(summary.durationMs / 1000).toFixed(1)}s`, "");
  lines.push("| Critical | High | Medium | Low | Info | Dismissed |", "|---:|---:|---:|---:|---:|---:|");
  lines.push(`| ${summary.counts.critical} | ${summary.counts.high} | ${summary.counts.medium} | ${summary.counts.low} | ${summary.counts.info} | ${summary.dismissed} |`, "");

  if (report.swarm.status === "completed") {
    const s = report.swarm;
    lines.push("## Adversarial review", "", s.summary, "");
    lines.push(`Critic raised ${s.stats.claims} claims; ${s.stats.ungrounded} rejected by the grounding check, ${s.stats.upheld} upheld by the Judge, ${s.stats.overruled} overruled.`, "");
    if (s.patch) lines.push(`Patched file re-scanned: **${s.patch.before.score} → ${s.patch.after.score}** (${s.patch.resolved} resolved, ${s.patch.introduced} introduced).`, "");
  }

  lines.push("## Findings", "");
  if (!open.length) lines.push("_No open findings._", "");
  for (const f of open) {
    lines.push(`### ${ICON[f.severity]} ${f.title}`, "");
    lines.push(`\`${f.ruleId}\` · ${f.severity} · confidence ${Math.round(f.confidence * 100)}% · ${f.cwe.join(", ")}${f.owasp ? ` · ${f.owasp}` : ""} · \`${f.file}:${f.location.line}\``, "");
    lines.push(f.description, "");
    lines.push("```", f.snippet, "```", "");
    if (f.trace?.length) lines.push(`**Data flow:** ${f.trace.map((s) => `L${s.line} ${s.label}`).join(" → ")}`, "");
    lines.push(`**Fix:** ${f.remediation}`, "");
  }
  return lines.join("\n");
}
