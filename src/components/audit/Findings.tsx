"use client";

import { useMemo, useState } from "react";
import { ArrowDown, Bot, Check, ExternalLink, Fingerprint, GitBranch, KeyRound, Package, Ruler, Search, ShieldCheck, Workflow, X } from "lucide-react";
import type { Detector, Finding, Severity } from "@/lib/engine/types";
import { SEVERITIES } from "@/lib/engine/types";
import { CodeView } from "./CodeView";
import { Badge, SeverityBadge, SEVERITY_META, SectionLabel, cn } from "../ui";

export const DETECTOR_META: Record<Detector, { label: string; Icon: typeof Bot }> = {
  taint: { label: "Taint flow", Icon: Workflow },
  pattern: { label: "Pattern", Icon: Fingerprint },
  secret: { label: "Secret", Icon: KeyRound },
  metric: { label: "Quality", Icon: Ruler },
  swarm: { label: "AI swarm", Icon: Bot },
  osv: { label: "Dependency", Icon: Package },
};

const cweUrl = (c: string) => `https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`;

export function TraceView({ finding }: { finding: Finding }) {
  if (!finding.trace?.length) return null;
  return (
    <ol className="relative space-y-0">
      {finding.trace.map((s, i) => {
        const color = s.kind === "source" ? "border-sev-high text-sev-high" : s.kind === "sink" ? "border-sev-critical text-sev-critical" : "border-fg-3 text-fg-3";
        return (
          <li key={i} className="relative flex gap-3 pb-3 last:pb-0">
            {i < finding.trace!.length - 1 && <span className="absolute top-5 bottom-0 left-[9px] w-px bg-line-strong" aria-hidden />}
            <span className={cn("z-10 mt-0.5 flex size-[19px] shrink-0 items-center justify-center rounded-full border-2 bg-s1 text-[9px] font-bold", color)}>{s.kind === "source" ? "S" : s.kind === "sink" ? "!" : <ArrowDown className="size-2.5" />}</span>
            <div className="min-w-0">
              <div className="text-[12.5px] text-fg">
                <span className="font-mono text-fg-3">
                  {s.file && s.file !== finding.file ? `${s.file.split("/").slice(-2).join("/")}:` : "L"}
                  {s.line}
                </span>{" "}
                · {s.label}
              </div>
              <code className="mt-0.5 block truncate font-mono text-[11.5px] text-fg-2">{s.snippet}</code>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function FindingDetail({ finding, source, onJump }: { finding: Finding; source?: string; onJump?: (f: Finding) => void }) {
  const D = DETECTOR_META[finding.detector];
  const focus = { start: finding.location.line, end: Math.max(finding.location.line, Math.min(finding.location.endLine, finding.location.line + 8)), trace: finding.trace?.map((t) => t.line) };
  const isDismissed = finding.status === "dismissed";
  return (
    <div className="space-y-5">
      <div>
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Badge>
            <D.Icon className="size-3" /> {D.label}
          </Badge>
          <Badge>{finding.ruleId}</Badge>
          {finding.cwe.map((c) => (
            <a key={c} href={cweUrl(c)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md border border-line bg-s2 px-1.5 py-0.5 font-mono text-[11px] text-fg-2 hover:text-fg">
              {c} <ExternalLink className="size-2.5" />
            </a>
          ))}
          {finding.status === "confirmed" && (
            <span className="inline-flex items-center gap-1 rounded-md bg-accent/10 px-1.5 py-0.5 text-[11px] text-accent ring-1 ring-accent/25 ring-inset">
              <Check className="size-3" /> Confirmed by swarm
            </span>
          )}
          {isDismissed && (
            <span className="inline-flex items-center gap-1 rounded-md bg-s3 px-1.5 py-0.5 text-[11px] text-fg-2 ring-1 ring-line-strong ring-inset">
              <X className="size-3" /> Dismissed
            </span>
          )}
        </div>
        <h3 className={cn("mt-3 text-[17px] leading-snug font-medium text-balance", isDismissed && "text-fg-2 line-through decoration-fg-3/60")}>{finding.title}</h3>
        <div className="mt-1 flex flex-wrap gap-x-3 font-mono text-[11.5px] text-fg-3">
          <button className="hover:text-fg" onClick={() => onJump?.(finding)}>
            {finding.file}:{finding.location.line}
          </button>
          <span>confidence {Math.round(finding.confidence * 100)}%</span>
          {finding.owasp && <span>{finding.owasp}</span>}
        </div>
      </div>

      <p className="text-[13.5px] leading-relaxed text-fg-2">{finding.description}</p>

      {source ? <CodeView code={source} findings={[finding]} focus={focus} window={4} maxHeight="22rem" /> : <pre className="code overflow-x-auto rounded-xl border border-line bg-s1 px-4 py-3 text-fg-2">{finding.snippet}</pre>}

      {finding.trace && finding.trace.length > 0 && (
        <div>
          <SectionLabel className="mb-3">Attack path · source → sink</SectionLabel>
          <TraceView finding={finding} />
        </div>
      )}

      {finding.ruling && (
        <div className={cn("rounded-xl border p-3.5", finding.ruling.upheld ? "border-accent/25 bg-accent/[0.04]" : "border-line bg-s2/60")}>
          <SectionLabel className="mb-1.5">Judge&apos;s ruling{finding.ruling.defenderStance ? ` · defender ${finding.ruling.defenderStance}d` : ""}</SectionLabel>
          <p className="text-[13px] leading-relaxed text-fg-2">{finding.ruling.rationale}</p>
        </div>
      )}

      <div className="rounded-xl border border-line bg-s2/50 p-3.5">
        <SectionLabel className="mb-1.5 flex items-center gap-1.5">
          <ShieldCheck className="size-3.5" /> Remediation
        </SectionLabel>
        <p className="text-[13px] leading-relaxed whitespace-pre-wrap text-fg-2">{finding.remediation}</p>
      </div>
    </div>
  );
}

export function FindingsPanel({ findings, sources, onJump }: { findings: Finding[]; sources: Record<string, string>; onJump: (f: Finding) => void }) {
  const [sev, setSev] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [query, setQuery] = useState("");
  const [showDismissed, setShowDismissed] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter(
      (f) =>
        sev.has(f.severity) &&
        (showDismissed || f.status !== "dismissed") &&
        (!q || `${f.title} ${f.ruleId} ${f.cwe.join(" ")} ${f.file}`.toLowerCase().includes(q))
    );
  }, [findings, sev, query, showDismissed]);

  const selected = filtered.find((f) => f.id === selectedId) ?? filtered[0];
  const dismissedCount = findings.filter((f) => f.status === "dismissed").length;
  const multiFile = new Set(findings.map((f) => f.file)).size > 1;

  if (!findings.length) {
    return (
      <div className="panel flex flex-col items-center px-6 py-16 text-center">
        <span className="flex size-12 items-center justify-center rounded-2xl bg-accent/10 text-accent ring-1 ring-accent/30">
          <ShieldCheck className="size-6" />
        </span>
        <h3 className="mt-4 text-lg font-medium">No findings</h3>
        <p className="mt-1 max-w-md text-[13.5px] text-fg-2">Every rule, taint flow and secret detector came back clean. That doesn&apos;t prove the code is secure — but nothing here matched a known weakness.</p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,25rem)_minmax(0,1fr)]">
      <div className="panel flex max-h-[78vh] min-w-0 flex-col overflow-hidden">
        <div className="space-y-2.5 border-b border-line p-3">
          <label className="flex h-9 items-center gap-2 rounded-lg border border-line bg-bg/60 px-2.5 focus-within:border-line-strong">
            <Search className="size-3.5 text-fg-3" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by title, rule, CWE, file" className="min-w-0 flex-1 bg-transparent text-[12.5px] placeholder:text-fg-3 focus:outline-none" aria-label="Filter findings" />
          </label>
          <div className="flex flex-wrap items-center gap-1">
            {SEVERITIES.map((s) => {
              const n = findings.filter((f) => f.severity === s && (showDismissed || f.status !== "dismissed")).length;
              const on = sev.has(s);
              return (
                <button
                  key={s}
                  aria-pressed={on}
                  onClick={() => {
                    const next = new Set(sev);
                    if (on) next.delete(s);
                    else next.add(s);
                    setSev(next.size ? next : new Set(SEVERITIES));
                  }}
                  className={cn("flex h-7 items-center gap-1.5 rounded-md border px-2 text-[11.5px] transition-colors", on ? "border-line-strong bg-s3 text-fg" : "border-transparent text-fg-3")}
                >
                  <span className={cn("size-1.5 rounded-full", SEVERITY_META[s].dot)} />
                  {SEVERITY_META[s].label}
                  <span className="font-mono text-fg-3">{n}</span>
                </button>
              );
            })}
            {dismissedCount > 0 && (
              <button onClick={() => setShowDismissed(!showDismissed)} className={cn("ml-auto h-7 rounded-md px-2 text-[11.5px]", showDismissed ? "bg-s3 text-fg" : "text-fg-3 hover:text-fg-2")}>
                {showDismissed ? "Hide" : "Show"} {dismissedCount} dismissed
              </button>
            )}
          </div>
        </div>
        <ul className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {filtered.map((f) => {
            const D = DETECTOR_META[f.detector];
            const active = selected?.id === f.id;
            return (
              <li key={f.id}>
                <button
                  onClick={() => setSelectedId(f.id)}
                  className={cn("w-full rounded-lg px-2.5 py-2.5 text-left transition-colors", active ? "bg-s3 shadow-[inset_0_0_0_1px_rgb(255_255_255/0.07)]" : "hover:bg-s2")}
                >
                  <div className="flex items-start gap-2.5">
                    <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", SEVERITY_META[f.severity].dot)} aria-label={SEVERITY_META[f.severity].label} />
                    <div className="min-w-0 flex-1">
                      <div className={cn("text-[13px] leading-snug", f.status === "dismissed" ? "text-fg-3 line-through" : "text-fg")}>{f.title}</div>
                      <div className="mt-1 flex items-center gap-2 font-mono text-[11px] text-fg-3">
                        <D.Icon className="size-3" />
                        <span className="truncate">
                          {multiFile ? `${f.file.split("/").pop()}:` : "L"}
                          {f.location.line}
                        </span>
                        <span>{f.cwe[0]}</span>
                        {f.status === "confirmed" && <Check className="size-3 text-accent" aria-label="confirmed" />}
                        {f.trace && <GitBranch className="size-3" aria-label="has data-flow trace" />}
                      </div>
                    </div>
                  </div>
                </button>
              </li>
            );
          })}
          {!filtered.length && <li className="px-3 py-6 text-center text-[12.5px] text-fg-3">No findings match the filters.</li>}
        </ul>
      </div>
      <div className="panel min-w-0 p-5">{selected ? <FindingDetail finding={selected} source={sources[selected.file]} onJump={onJump} /> : null}</div>
    </div>
  );
}
