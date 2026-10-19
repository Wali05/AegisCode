"use client";

import { useState } from "react";
import type { Grade, Severity } from "@/lib/engine/types";
import { SEVERITIES } from "@/lib/engine/types";
import type { StageRecord } from "@/lib/report/types";
import { SEVERITY_META, cn } from "../ui";

export const GRADE_COLOR: Record<Grade, string> = {
  A: "#c6f432",
  B: "#9fd23a",
  C: "#e5c13c",
  D: "#f07c2a",
  F: "#e8417f",
};

/** Hero score: a single number with a ring that encodes the same value. */
export function ScoreRing({ score, grade, size = 132, label = "Security score" }: { score: number; grade: Grade; size?: number; label?: string }) {
  const stroke = 9;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = GRADE_COLOR[grade];
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`${label}: ${score} out of 100, grade ${grade}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(255 255 255 / 0.06)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          style={{ transition: "stroke-dashoffset 1.1s cubic-bezier(.2,.7,.2,1)", filter: `drop-shadow(0 0 10px ${color}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-[34px] leading-none font-semibold tracking-tight tabular-nums">{score}</span>
        <span className="mt-1 font-mono text-[11px] text-fg-3">
          grade <span style={{ color }}>{grade}</span>
        </span>
      </div>
    </div>
  );
}

/** Part-to-whole of open findings by severity, with a direct-labelled legend. */
export function SeverityBar({ counts, className }: { counts: Record<Severity, number>; className?: string }) {
  const [hover, setHover] = useState<Severity | null>(null);
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  return (
    <div className={className}>
      <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-full bg-s3" role="img" aria-label={SEVERITIES.map((s) => `${counts[s]} ${s}`).join(", ")}>
        {total === 0 ? (
          <div className="h-full w-full rounded-full bg-accent/50" />
        ) : (
          SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
            <div
              key={s}
              className={cn("h-full transition-opacity first:rounded-l-full last:rounded-r-full", SEVERITY_META[s].dot, hover && hover !== s && "opacity-35")}
              style={{ width: `${(counts[s] / total) * 100}%`, minWidth: 6 }}
              onMouseEnter={() => setHover(s)}
              onMouseLeave={() => setHover(null)}
              title={`${counts[s]} ${SEVERITY_META[s].label}`}
            />
          ))
        )}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
        {SEVERITIES.map((s) => (
          <li key={s} className={cn("flex items-center gap-1.5 text-[12px] transition-opacity", counts[s] === 0 && "opacity-40", hover && hover !== s && "opacity-40")} onMouseEnter={() => setHover(s)} onMouseLeave={() => setHover(null)}>
            <span className={cn("size-2 rounded-[3px]", SEVERITY_META[s].dot)} aria-hidden />
            <span className="text-fg-2">{SEVERITY_META[s].label}</span>
            <span className="font-mono text-fg tabular-nums">{counts[s]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const STAGE_LABEL: Record<string, string> = {
  ingest: "Ingest",
  parse: "Parse",
  taint: "Taint analysis",
  patterns: "Pattern rules",
  secrets: "Secret scan",
  metrics: "Metrics",
  deps: "Dependencies (OSV)",
  triage: "Risk triage",
  critic: "Critic",
  defender: "Defender",
  judge: "Judge",
  verify: "Patch verification",
};

export function stageLabel(id: string): string {
  return STAGE_LABEL[id] ?? id;
}

export function formatMs(ms?: number): string {
  if (ms === undefined) return "—";
  if (ms < 0.1) return "<0.1 ms";
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 1000) return `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

/** Stage durations on one linear axis — makes the engine-vs-LLM cost gap obvious. */
export function StageTimeline({ stages }: { stages: StageRecord[] }) {
  const [hover, setHover] = useState<string | null>(null);
  const timed = stages.filter((s) => s.status === "done" && s.ms !== undefined);
  const max = Math.max(1, ...timed.map((s) => s.ms!));
  const llm = timed.filter((s) => ["critic", "defender", "judge"].includes(s.id)).reduce((n, s) => n + s.ms!, 0);
  const engine = timed.filter((s) => ["parse", "taint", "patterns", "secrets", "metrics"].includes(s.id)).reduce((n, s) => n + s.ms!, 0);

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-6 text-[13px]">
        <div>
          <div className="text-fg-3">Static engine</div>
          <div className="font-mono text-lg text-fg tabular-nums">{formatMs(engine)}</div>
        </div>
        {llm > 0 && (
          <>
            <div>
              <div className="text-fg-3">LLM swarm</div>
              <div className="font-mono text-lg text-fg tabular-nums">{formatMs(llm)}</div>
            </div>
            <div>
              <div className="text-fg-3">Ratio</div>
              <div className="font-mono text-lg text-fg tabular-nums">{Math.round(llm / Math.max(engine, 0.1)).toLocaleString()}×</div>
            </div>
          </>
        )}
      </div>
      <ul className="space-y-1.5">
        {stages.map((s) => {
          const w = s.ms !== undefined && s.status === "done" ? Math.max(0.4, (s.ms / max) * 100) : 0;
          const isLlm = ["critic", "defender", "judge"].includes(s.id);
          return (
            <li key={s.id} className="grid grid-cols-[9.5rem_1fr_4.5rem] items-center gap-3 text-[12.5px]" onMouseEnter={() => setHover(s.id)} onMouseLeave={() => setHover(null)}>
              <span className={cn("truncate", s.status === "skipped" ? "text-fg-3" : "text-fg-2")}>{stageLabel(s.id)}</span>
              <div className="relative h-5 rounded-[4px] bg-white/[0.025]">
                {w > 0 && (
                  <div
                    className={cn("absolute inset-y-[5px] left-0 rounded-r-[4px] transition-opacity", isLlm ? "bg-judge" : "bg-accent", hover && hover !== s.id && "opacity-40")}
                    style={{ width: `${w}%`, minWidth: 3 }}
                  />
                )}
                {hover === s.id && s.detail && (
                  <div className="pointer-events-none absolute -top-8 left-0 z-20 rounded-md border border-line-strong bg-s3 px-2 py-1 text-[11.5px] whitespace-nowrap text-fg shadow-xl">{s.detail}</div>
                )}
                {s.status === "skipped" && <span className="absolute inset-y-0 left-2 flex items-center text-[11px] text-fg-3">skipped</span>}
              </div>
              <span className="text-right font-mono text-fg-2 tabular-nums">{s.status === "done" ? formatMs(s.ms) : s.status === "error" ? "error" : ""}</span>
            </li>
          );
        })}
      </ul>
      <div className="mt-3 flex gap-4 text-[11.5px] text-fg-3">
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-[3px] bg-accent" /> deterministic
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-[3px] bg-judge" /> LLM agent
        </span>
      </div>
    </div>
  );
}
