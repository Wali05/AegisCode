"use client";

import { useMemo, useState } from "react";
import { Check, Copy, Download, ExternalLink, FileJson, FileText, ShieldCheck } from "lucide-react";
import type { FileReport, Finding } from "@/lib/engine/types";
import { LANGUAGE_LABELS } from "@/lib/engine/language";
import type { AuditReport } from "@/lib/report/types";
import { toMarkdown, toSarif } from "@/lib/report/export";
import { CodeView } from "./CodeView";
import { GRADE_COLOR, StageTimeline } from "./charts";
import { Button, SeverityBadge, SectionLabel, cn } from "../ui";

// ─── Source browser ──────────────────────────────────────────────────────────

export function SourcePanel({ report, file, line, onFile, onSelectLine }: { report: AuditReport; file: string; line: number | null; onFile: (f: string) => void; onSelectLine: (file: string, line: number) => void }) {
  const files = Object.keys(report.sources);
  const code = report.sources[file];
  const findings = report.findings.filter((f) => f.file === file);
  return (
    <div className="space-y-3">
      {files.length > 1 && (
        <select value={file} onChange={(e) => onFile(e.target.value)} className="h-9 max-w-full rounded-lg border border-line-strong bg-s2 px-2.5 font-mono text-[12.5px] focus:outline-none" aria-label="File">
          {files.map((f) => (
            <option key={f} value={f}>
              {f} ({report.findings.filter((x) => x.file === f && x.status !== "dismissed").length})
            </option>
          ))}
        </select>
      )}
      {code !== undefined ? (
        <CodeView code={code} findings={findings} focus={line ? { start: line, end: line } : null} onSelectLine={(l) => onSelectLine(file, l)} maxHeight="75vh" />
      ) : (
        <p className="text-[13px] text-fg-3">Source not included in this report.</p>
      )}
    </div>
  );
}

// ─── Dependencies ────────────────────────────────────────────────────────────

export function DependenciesPanel({ report }: { report: AuditReport }) {
  const deps = report.findings.filter((f) => f.detector === "osv");
  const info = report.dependencies;
  if (!info) return null;
  return (
    <div className="space-y-4">
      <div className="panel flex flex-wrap items-center gap-6 p-5 text-[13px]">
        <Stat label="Packages checked" value={info.scanned} />
        <Stat label="Vulnerable" value={info.vulnerable} />
        <Stat label="Advisories" value={deps.length} />
        <div className="min-w-0 flex-1 text-fg-3">
          Source: <a className="text-fg-2 underline decoration-line-strong underline-offset-2 hover:text-fg" href="https://osv.dev" target="_blank" rel="noreferrer">OSV.dev</a> · {info.manifests.join(", ")}
          {info.error && <div className="mt-1 text-sev-medium">Advisory lookup failed: {info.error}</div>}
        </div>
      </div>
      {deps.length > 0 ? (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead className="border-b border-line text-[11.5px] text-fg-3">
              <tr>
                <th className="px-4 py-2.5 font-normal">Package</th>
                <th className="px-4 py-2.5 font-normal">Advisory</th>
                <th className="px-4 py-2.5 font-normal">Severity</th>
                <th className="px-4 py-2.5 font-normal">Fix</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {deps.map((f) => (
                <tr key={f.id} className="align-top">
                  <td className="px-4 py-3 font-mono text-[12.5px] whitespace-nowrap">{f.snippet}</td>
                  <td className="px-4 py-3">
                    <a href={`https://osv.dev/vulnerability/${f.ruleId}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-[12px] text-fg-2 hover:text-fg">
                      {f.ruleId} <ExternalLink className="size-3" />
                    </a>
                    <div className="mt-0.5 text-[12.5px] text-fg-2">{f.title.split(": ").slice(1).join(": ")}</div>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-4 py-3 text-[12.5px] text-fg-2">{f.remediation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !info.error && (
          <p className="flex items-center gap-2 text-[13px] text-fg-2">
            <ShieldCheck className="size-4 text-accent" /> No known advisories for the pinned versions.
          </p>
        )
      )}
    </div>
  );
}

// ─── Files (repository mode) ─────────────────────────────────────────────────

export function FilesPanel({ files, onOpen }: { files: FileReport[]; onOpen: (path: string) => void }) {
  const sorted = useMemo(() => [...files].sort((a, b) => a.score - b.score || b.findings.length - a.findings.length), [files]);
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-[13px]">
        <thead className="border-b border-line text-[11.5px] text-fg-3">
          <tr>
            <th className="px-4 py-2.5 font-normal">File</th>
            <th className="px-4 py-2.5 font-normal">Score</th>
            <th className="px-4 py-2.5 font-normal">Findings</th>
            <th className="px-4 py-2.5 font-normal">Risk</th>
            <th className="px-4 py-2.5 text-right font-normal">LOC</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {sorted.map((f) => (
            <tr key={f.path} className="cursor-pointer hover:bg-s2/60" onClick={() => onOpen(f.path)}>
              <td className="max-w-[22rem] px-4 py-2.5">
                <div className="truncate font-mono text-[12.5px]">{f.path}</div>
                <div className="text-[11px] text-fg-3">{LANGUAGE_LABELS[f.language]}</div>
              </td>
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="w-7 font-mono tabular-nums" style={{ color: GRADE_COLOR[f.grade] }}>
                    {f.score}
                  </span>
                  <div className="h-1 w-20 rounded-full bg-s3">
                    <div className="h-full rounded-full" style={{ width: `${f.score}%`, background: GRADE_COLOR[f.grade] }} />
                  </div>
                </div>
              </td>
              <td className="px-4 py-2.5">
                <FindingDots findings={f.findings} />
              </td>
              <td className="px-4 py-2.5 font-mono text-[12px] text-fg-2 tabular-nums">{Math.round(f.triage.risk * 100)}%</td>
              <td className="px-4 py-2.5 text-right font-mono text-[12px] text-fg-3 tabular-nums">{f.metrics.loc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingDots({ findings }: { findings: Finding[] }) {
  const open = findings.filter((f) => f.status !== "dismissed" && f.severity !== "info");
  if (!open.length) return <span className="text-[12px] text-fg-3">—</span>;
  return (
    <div className="flex flex-wrap gap-2">
      {(["critical", "high", "medium", "low"] as const).map((s) => {
        const n = open.filter((f) => f.severity === s).length;
        return n ? (
          <span key={s} className="inline-flex items-center gap-1">
            <SeverityBadge severity={s} compact />
            <span className="font-mono text-[11.5px] text-fg-2">{n}</span>
          </span>
        ) : null;
      })}
    </div>
  );
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

export function MetricsPanel({ files }: { files: FileReport[] }) {
  const fns = files.flatMap((f) => f.metrics.functions.map((fn) => ({ ...fn, file: f.path }))).sort((a, b) => b.complexity - a.complexity).slice(0, 40);
  const maxCC = Math.max(16, ...fns.map((f) => f.complexity));
  const sloc = files.reduce((n, f) => n + f.metrics.sloc, 0);
  const mi = files.length ? Math.round(files.reduce((n, f) => n + f.metrics.maintainability * f.metrics.sloc, 0) / Math.max(1, sloc)) : 100;
  const comments = files.reduce((n, f) => n + f.metrics.commentLines, 0);

  return (
    <div className="space-y-4">
      <div className="panel grid grid-cols-2 gap-5 p-5 sm:grid-cols-4">
        <Stat label="Maintainability index" value={`${mi}/100`} hint={mi >= 65 ? "maintainable" : mi >= 40 ? "moderate" : "hard to maintain"} />
        <Stat label="Source lines" value={sloc.toLocaleString()} />
        <Stat label="Functions" value={files.reduce((n, f) => n + f.metrics.functions.length, 0)} />
        <Stat label="Comment lines" value={comments.toLocaleString()} />
      </div>
      <div className="panel p-5">
        <SectionLabel className="mb-1">Cyclomatic complexity by function</SectionLabel>
        <p className="mb-4 text-[12px] text-fg-3">Budget line at 15. Functions above it are hard to test exhaustively.</p>
        {fns.length === 0 ? (
          <p className="text-[13px] text-fg-3">No functions detected.</p>
        ) : (
          <ul className="space-y-1">
            {fns.map((fn) => (
              <li key={`${fn.file}:${fn.line}`} className="group grid grid-cols-[minmax(0,14rem)_1fr_3rem] items-center gap-3 text-[12.5px]" title={`${fn.file}:${fn.line} · ${fn.loc} lines · nesting ${fn.maxNesting} · ${fn.params} params`}>
                <span className="truncate font-mono text-fg-2">
                  {fn.name}
                  <span className="text-fg-3"> :{fn.line}</span>
                </span>
                <div className="relative h-4">
                  <div className="absolute inset-y-0 border-l border-dashed border-sev-medium/50" style={{ left: `${(15 / maxCC) * 100}%` }} aria-hidden />
                  <div className={cn("absolute inset-y-[4px] left-0 rounded-r-[4px] transition-opacity group-hover:opacity-80", fn.complexity > 15 ? "bg-sev-high" : "bg-fg-3/60")} style={{ width: `${(fn.complexity / maxCC) * 100}%`, minWidth: 3 }} />
                </div>
                <span className="text-right font-mono text-fg tabular-nums">{fn.complexity}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div>
      <div className="text-[11.5px] text-fg-3">{label}</div>
      <div className="mt-0.5 font-mono text-xl tabular-nums">{value}</div>
      {hint && <div className="text-[11.5px] text-fg-3">{hint}</div>}
    </div>
  );
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

export function PipelinePanel({ report }: { report: AuditReport }) {
  const triaged = [...report.files].sort((a, b) => b.triage.risk - a.triage.risk)[0];
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,22rem)]">
      <div className="panel p-5">
        <SectionLabel className="mb-4">Stage timings</SectionLabel>
        <StageTimeline stages={report.stages} />
      </div>
      {triaged && (
        <div className="panel p-5">
          <SectionLabel className="mb-1">Risk triage</SectionLabel>
          <p className="mb-4 text-[12px] text-fg-3">Logistic model over static signals decides whether the LLM swarm is worth running.</p>
          <div className="mb-3 flex items-baseline gap-2">
            <span className="font-mono text-3xl tabular-nums">{Math.round(triaged.triage.risk * 100)}%</span>
            <span className={cn("text-[12.5px]", triaged.triage.escalate ? "text-sev-high" : "text-accent")}>{triaged.triage.escalate ? "escalated" : "below threshold"}</span>
          </div>
          <div className="mb-1 truncate font-mono text-[11.5px] text-fg-3">{triaged.path}</div>
          <ul className="mt-3 space-y-1.5">
            {triaged.triage.signals.map((s) => (
              <li key={s.label} className="flex items-center justify-between gap-3 text-[12.5px]">
                <span className="text-fg-2">{s.label}</span>
                <span className={cn("font-mono tabular-nums", s.weight >= 0 ? "text-fg" : "text-accent")}>{s.weight >= 0 ? "+" : ""}{s.weight.toFixed(2)}</span>
              </li>
            ))}
            <li className="flex items-center justify-between gap-3 border-t border-line pt-1.5 text-[12.5px]">
              <span className="text-fg-3">bias</span>
              <span className="font-mono text-fg-3">−2.40</span>
            </li>
          </ul>
        </div>
      )}
    </div>
  );
}

// ─── Export ──────────────────────────────────────────────────────────────────

function save(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const ACTION_SNIPPET = `name: AegisCode
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: |
          git clone --depth 1 https://github.com/Wali05/AegisCode .aegis
          npm ci --prefix .aegis --omit=dev --ignore-scripts
      - run: node .aegis/bin/aegis.mjs scan . --sarif aegis.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with: { sarif_file: aegis.sarif }`;

export function ExportPanel({ report }: { report: AuditReport }) {
  const base = (report.target.repo ?? report.target.path ?? "audit").replace(/[^\w.-]+/g, "-");
  const [copied, setCopied] = useState(false);
  const items = [
    { label: "SARIF 2.1.0", desc: "Upload to GitHub Code Scanning, Azure DevOps or any SARIF viewer. Includes code flows for taint traces.", Icon: FileJson, run: () => save(`${base}.sarif`, JSON.stringify(toSarif(report), null, 2), "application/sarif+json") },
    { label: "Markdown report", desc: "Human-readable summary for a PR description, ticket or wiki.", Icon: FileText, run: () => save(`${base}-aegis.md`, toMarkdown(report), "text/markdown") },
    { label: "Raw JSON", desc: "The complete AuditReport, including traces, metrics and the debate transcript.", Icon: FileJson, run: () => save(`${base}-aegis.json`, JSON.stringify(report, null, 2), "application/json") },
  ];
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-2">
        {items.map((it) => (
          <button key={it.label} onClick={it.run} className="panel flex w-full items-start gap-3.5 p-4 text-left transition-colors hover:bg-s2">
            <it.Icon className="mt-0.5 size-4.5 text-accent" />
            <div className="flex-1">
              <div className="text-[14px] font-medium">{it.label}</div>
              <div className="mt-0.5 text-[12.5px] text-fg-2">{it.desc}</div>
            </div>
            <Download className="size-4 text-fg-3" />
          </button>
        ))}
      </div>
      <div className="panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <span className="text-[13px] font-medium">Run it in CI</span>
          <Button
            size="sm"
            variant="ghost"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(ACTION_SNIPPET);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              } catch {
                /* ignore */
              }
            }}
          >
            {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <pre className="code overflow-x-auto px-4 py-3 text-[11.5px] text-fg-2">{ACTION_SNIPPET}</pre>
      </div>
    </div>
  );
}
