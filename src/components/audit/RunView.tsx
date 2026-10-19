"use client";

import { useEffect, useRef, useState } from "react";
import { Check, CircleDashed, Loader2, Minus, X } from "lucide-react";
import type { StageId, StageRecord } from "@/lib/report/types";
import type { AuditState } from "./useAudit";
import { formatMs, stageLabel } from "./charts";
import { ClaimCard } from "./Debate";
import { Button, SectionLabel, cn } from "../ui";

const GROUPS: Array<{ label: string; stages: StageId[] }> = [
  { label: "Ingest", stages: ["ingest"] },
  { label: "Static engine", stages: ["parse", "taint", "patterns", "secrets", "metrics"] },
  { label: "Supply chain", stages: ["deps"] },
  { label: "Gate", stages: ["triage"] },
  { label: "Adversarial swarm", stages: ["critic", "defender", "judge", "verify"] },
];

function StageIcon({ status }: { status?: StageRecord["status"] }) {
  if (status === "running") return <Loader2 className="size-3.5 animate-spin text-accent" />;
  if (status === "done") return <Check className="size-3.5 text-accent" />;
  if (status === "skipped") return <Minus className="size-3.5 text-fg-3" />;
  if (status === "error") return <X className="size-3.5 text-sev-critical" />;
  return <CircleDashed className="size-3.5 text-fg-3/60" />;
}

export function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(t);
  }, []);
  return <span className="font-mono tabular-nums">{((now - since) / 1000).toFixed(1)}s</span>;
}

const LEVEL_COLOR = { info: "text-fg-2", warn: "text-sev-medium", error: "text-sev-critical", success: "text-accent" } as const;
const SCOPE_COLOR: Record<string, string> = { critic: "text-critic", defender: "text-defender", judge: "text-judge", grounding: "text-sev-medium", verify: "text-accent" };

export function RunView({ state, onCancel }: { state: AuditState; onCancel: () => void }) {
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [state.logs.length]);

  const target = state.request?.url ?? state.request?.filename ?? "pasted snippet";

  return (
    <div className="animate-fade-up">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <SectionLabel>Auditing</SectionLabel>
          <div className="mt-1 truncate font-mono text-[15px] text-fg">{target}</div>
        </div>
        <div className="flex items-center gap-3 text-[13px] text-fg-2">
          <span className="flex items-center gap-2">
            <span className="size-2 animate-pulse-dot rounded-full bg-accent" /> <Elapsed since={state.startedAt} />
          </span>
          <Button size="sm" variant="outline" onClick={onCancel}>
            Cancel <kbd className="kbd">esc</kbd>
          </Button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,19rem)_minmax(0,1fr)]">
        <div className="panel p-4">
          {GROUPS.map((g) => (
            <div key={g.label} className="mb-4 last:mb-0">
              <SectionLabel className="mb-2">{g.label}</SectionLabel>
              <ul className="space-y-1">
                {g.stages.map((id) => {
                  const s = state.stages[id];
                  return (
                    <li key={id} className={cn("flex items-start gap-2.5 rounded-lg px-2 py-1.5 transition-colors", s?.status === "running" && "bg-accent/[0.06]")}>
                      <span className="mt-0.5">
                        <StageIcon status={s?.status} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2 text-[13px]">
                          <span className={cn(s?.status === "running" ? "shimmer-text" : s?.status ? "text-fg" : "text-fg-3")}>{stageLabel(id)}</span>
                          <span className="font-mono text-[11px] text-fg-3 tabular-nums">{s?.status === "done" ? formatMs(s.ms) : ""}</span>
                        </div>
                        {s?.detail && <div className="truncate text-[11.5px] text-fg-3">{s.detail}</div>}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          {state.progress && (
            <div className="mt-2 border-t border-line pt-3">
              <div className="mb-1.5 flex justify-between text-[11.5px] text-fg-3">
                <span>Files</span>
                <span className="font-mono">
                  {state.progress.index}/{state.progress.total}
                </span>
              </div>
              <div className="h-1 overflow-hidden rounded-full bg-s3">
                <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${(state.progress.index / state.progress.total) * 100}%` }} />
              </div>
              <div className="mt-1.5 truncate font-mono text-[11px] text-fg-3">{state.progress.path}</div>
            </div>
          )}
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <div className="panel overflow-hidden">
            <div className="flex items-center gap-1.5 border-b border-line px-4 py-2.5">
              <span className="size-2.5 rounded-full bg-[#ff5f57]/80" />
              <span className="size-2.5 rounded-full bg-[#febc2e]/80" />
              <span className="size-2.5 rounded-full bg-[#28c840]/80" />
              <span className="ml-3 font-mono text-[11.5px] text-fg-3">pipeline.log — live</span>
            </div>
            <div ref={logRef} className="code h-72 overflow-y-auto px-4 py-3" aria-live="polite">
              {state.logs.length === 0 && <div className="shimmer-text">Connecting to pipeline…</div>}
              {state.logs.map((l) => (
                <div key={l.id} className="flex gap-3 animate-fade-up">
                  <span className="shrink-0 text-fg-3 tabular-nums">+{((l.t - state.startedAt) / 1000).toFixed(2)}s</span>
                  <span className={cn("w-20 shrink-0 truncate uppercase", SCOPE_COLOR[l.scope] ?? "text-fg-3")}>{l.scope}</span>
                  <span className={cn("min-w-0 break-words whitespace-pre-wrap", LEVEL_COLOR[l.level])}>{l.message}</span>
                </div>
              ))}
            </div>
          </div>

          {state.claims.length > 0 && (
            <div>
              <SectionLabel className="mb-2">Live debate · {state.claims.length} claims</SectionLabel>
              <div className="space-y-2">
                {state.claims.map((c) => (
                  <ClaimCard key={c.id} claim={c} compact />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
