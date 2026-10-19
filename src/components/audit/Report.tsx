"use client";

import { useEffect, useMemo, useState } from "react";
import { Bot, Code2, Download, ExternalLink, FileStack, Gauge, GitCommitHorizontal, ListChecks, Package, RotateCcw, Scale, Star, Timer, Wand2 } from "lucide-react";
import type { Finding } from "@/lib/engine/types";
import { LANGUAGE_LABELS } from "@/lib/engine/language";
import type { AuditReport } from "@/lib/report/types";
import { ScoreRing, SeverityBar, formatMs } from "./charts";
import { FindingsPanel } from "./Findings";
import { DebateView } from "./Debate";
import { PatchView } from "./PatchView";
import { DependenciesPanel, ExportPanel, FilesPanel, MetricsPanel, PipelinePanel, SourcePanel } from "./Panels";
import { Button, Tabs, SectionLabel, cn } from "../ui";

type Tab = "findings" | "source" | "debate" | "patch" | "deps" | "files" | "metrics" | "pipeline" | "export";

export function Report({ report, onReset }: { report: AuditReport; onReset: () => void }) {
  const swarm = report.swarm.status === "completed" ? report.swarm : null;
  const firstFile = Object.keys(report.sources)[0] ?? report.files[0]?.path ?? "";
  const [tab, setTab] = useState<Tab>("findings");
  const [sourceFile, setSourceFile] = useState(firstFile);
  const [sourceLine, setSourceLine] = useState<number | null>(null);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [report.id]);

  const open = report.findings.filter((f) => f.status !== "dismissed");
  const flows = open.filter((f) => f.detector === "taint").length;
  const { target, summary } = report;

  const jump = (f: Finding) => {
    if (report.sources[f.file] === undefined) return;
    setSourceFile(f.file);
    setSourceLine(f.location.line);
    setTab("source");
  };

  const tabs = useMemo(
    () => [
      { id: "findings" as const, label: "Findings", count: open.length, icon: <ListChecks className="size-3.5" /> },
      { id: "source" as const, label: "Source", icon: <Code2 className="size-3.5" />, hidden: !Object.keys(report.sources).length },
      { id: "debate" as const, label: "Debate", count: swarm?.claims.length, icon: <Scale className="size-3.5" />, hidden: !swarm },
      { id: "patch" as const, label: "Patch", icon: <Wand2 className="size-3.5" />, hidden: !swarm?.patch },
      { id: "deps" as const, label: "Dependencies", count: report.findings.filter((f) => f.detector === "osv").length, icon: <Package className="size-3.5" />, hidden: !report.dependencies },
      { id: "files" as const, label: "Files", count: report.files.length, icon: <FileStack className="size-3.5" />, hidden: report.files.length < 2 },
      { id: "metrics" as const, label: "Metrics", icon: <Gauge className="size-3.5" /> },
      { id: "pipeline" as const, label: "Pipeline", icon: <Timer className="size-3.5" /> },
      { id: "export" as const, label: "Export", icon: <Download className="size-3.5" /> },
    ],
    [open.length, report, swarm]
  );

  const langs = Object.entries(summary.languages)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .map(([l]) => LANGUAGE_LABELS[l as keyof typeof LANGUAGE_LABELS])
    .slice(0, 3)
    .join(", ");
  const githubUrl = target.owner && target.repo ? `https://github.com/${target.owner}/${target.repo}${target.path ? `/${target.kind === "file" ? "blob" : "tree"}/${target.ref}/${target.path}` : ""}` : undefined;

  return (
    <div className="animate-fade-up space-y-5">
      {/* ── Summary ── */}
      <section className="panel panel-glow grid gap-6 p-5 sm:p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <ScoreRing score={summary.score} grade={summary.grade} />
        <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <SectionLabel>{target.kind === "repo" ? "Repository audit" : target.kind === "file" ? "File audit" : "Snippet audit"}{report.cached ? " · cached" : ""}</SectionLabel>
              <h2 className="mt-1 flex items-center gap-2 truncate font-mono text-[17px] text-fg">
                {target.label}
                {githubUrl && (
                  <a href={githubUrl} target="_blank" rel="noreferrer" className="text-fg-3 hover:text-fg" aria-label="Open on GitHub">
                    <ExternalLink className="size-4" />
                  </a>
                )}
              </h2>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px] text-fg-3">
                <span>
                  {summary.files} file{summary.files === 1 ? "" : "s"} · {summary.loc.toLocaleString()} lines · {langs || "—"}
                </span>
                <span>{formatMs(summary.durationMs)}</span>
                {target.ref && <span className="font-mono">@{target.ref}</span>}
                {target.repoInfo && (
                  <span className="flex items-center gap-1">
                    <Star className="size-3" /> {target.repoInfo.stars.toLocaleString()}
                  </span>
                )}
                {target.commit && (
                  <a href={target.commit.url} target="_blank" rel="noreferrer" className="flex min-w-0 items-center gap-1.5 hover:text-fg-2">
                    <GitCommitHorizontal className="size-3.5" />
                    {/* eslint-disable-next-line @next/next/no-img-element -- 16px GitHub avatar, not worth an image-optimiser round trip */}
                    {target.commit.avatar && <img src={target.commit.avatar} alt="" className="size-4 rounded-full" />}
                    <span className="truncate">
                      {target.commit.author} · {target.commit.message}
                    </span>
                  </a>
                )}
              </div>
            </div>
            <Button size="sm" variant="outline" onClick={onReset}>
              <RotateCcw className="size-3.5" /> New audit
            </Button>
          </div>
          <SeverityBar counts={summary.counts} />
          <div className="flex flex-wrap gap-2 text-[12px]">
            <Chip>{flows} source→sink flow{flows === 1 ? "" : "s"}</Chip>
            <Chip>{report.engine.rules} rules · engine v{report.engine.version}</Chip>
            {summary.dismissed > 0 && <Chip>{summary.dismissed} dismissed as false positives</Chip>}
            {report.dependencies && <Chip>{report.dependencies.scanned} packages checked on OSV</Chip>}
          </div>
        </div>
      </section>

      {/* ── Swarm verdict ── */}
      {swarm ? (
        <section className="panel grid gap-5 p-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[12.5px] text-judge">
              <Scale className="size-4" /> Adversarial verdict · {swarm.file}
            </div>
            <p className="mt-2 text-[14px] leading-relaxed text-fg">{swarm.summary}</p>
          </div>
          <div className="flex flex-wrap gap-2 md:justify-end">
            <MiniStat label="claims" value={swarm.stats.claims} />
            <MiniStat label="hallucinations blocked" value={swarm.stats.ungrounded} tone={swarm.stats.ungrounded ? "warn" : undefined} />
            <MiniStat label="upheld" value={swarm.stats.upheld} />
            <MiniStat label="overruled" value={swarm.stats.overruled} />
            {swarm.patch && (
              <button onClick={() => setTab("patch")} className="rounded-xl border border-accent/30 bg-accent/[0.06] px-3 py-2 text-left hover:bg-accent/10">
                <div className="font-mono text-lg text-accent tabular-nums">
                  {swarm.patch.before.score}→{swarm.patch.after.score}
                </div>
                <div className="text-[11px] text-fg-2">verified patch</div>
              </button>
            )}
          </div>
        </section>
      ) : (
        <section className="flex items-start gap-3 rounded-2xl border border-dashed border-line-strong px-5 py-4 text-[13px] text-fg-2">
          <Bot className="mt-0.5 size-4 shrink-0 text-fg-3" />
          <span>{report.swarm.status !== "completed" && report.swarm.reason}</span>
        </section>
      )}

      {/* ── Tabs ── */}
      <div className="sticky top-14 z-30 -mx-4 border-b border-line bg-bg/80 px-4 py-2 backdrop-blur-xl sm:mx-0 sm:rounded-xl sm:border sm:px-2">
        <Tabs items={tabs} value={tab} onChange={setTab} />
      </div>

      <div key={tab} className="animate-fade-up">
        {tab === "findings" && <FindingsPanel findings={report.findings} sources={report.sources} onJump={jump} />}
        {tab === "source" && (
          <SourcePanel
            report={report}
            file={sourceFile}
            line={sourceLine}
            onFile={(f) => {
              setSourceFile(f);
              setSourceLine(null);
            }}
            onSelectLine={(_, l) => setSourceLine(l)}
          />
        )}
        {tab === "debate" && swarm && <DebateView swarm={swarm} />}
        {tab === "patch" && swarm?.patch && <PatchView patch={swarm.patch} original={report.sources[swarm.file] ?? ""} filename={swarm.file} />}
        {tab === "deps" && <DependenciesPanel report={report} />}
        {tab === "files" && (
          <FilesPanel
            files={report.files}
            onOpen={(p) => {
              if (report.sources[p] === undefined) return;
              setSourceFile(p);
              setSourceLine(null);
              setTab("source");
            }}
          />
        )}
        {tab === "metrics" && <MetricsPanel files={report.files} />}
        {tab === "pipeline" && <PipelinePanel report={report} />}
        {tab === "export" && <ExportPanel report={report} />}
      </div>
    </div>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return <span className="rounded-full border border-line bg-s2/70 px-2.5 py-1 text-fg-2">{children}</span>;
}

function MiniStat({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <div className="rounded-xl border border-line bg-s2/60 px-3 py-2">
      <div className={cn("font-mono text-lg tabular-nums", tone === "warn" ? "text-sev-medium" : "text-fg")}>{value}</div>
      <div className="text-[11px] text-fg-3">{label}</div>
    </div>
  );
}
