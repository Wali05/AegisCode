"use client";

import { Ban, Gavel, Scale, Shield, Swords } from "lucide-react";
import type { DebateClaim, SwarmResult } from "@/lib/report/types";
import { SeverityBadge, SectionLabel, cn } from "../ui";

const STANCE = {
  concede: { label: "Concedes", cls: "text-sev-critical bg-sev-critical/10 ring-sev-critical/25" },
  mitigate: { label: "Partly mitigated", cls: "text-sev-medium bg-sev-medium/10 ring-sev-medium/25" },
  dispute: { label: "Disputes", cls: "text-defender bg-defender/10 ring-defender/25" },
} as const;

function Snippet({ code }: { code: string }) {
  return <pre className="code mt-2 max-h-40 overflow-auto rounded-lg border border-line bg-bg/70 px-3 py-2 text-[11.5px] whitespace-pre text-fg-2">{code}</pre>;
}

export function ClaimCard({ claim, compact }: { claim: DebateClaim; compact?: boolean }) {
  const rejected = !claim.grounding.grounded;
  const verdict = claim.ruling;

  return (
    <article className={cn("panel animate-fade-up overflow-hidden", rejected && "opacity-70")}>
      <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
        <span className="font-mono text-[11px] text-fg-3">{claim.id}</span>
        <SeverityBadge severity={verdict?.severity ?? claim.severity} />
        <h4 className={cn("min-w-0 flex-1 text-[13.5px] font-medium", rejected && "line-through decoration-fg-3")}>{claim.title}</h4>
        <span className="font-mono text-[11px] text-fg-3">
          {claim.cwe} · L{claim.line_start}
          {claim.line_end > claim.line_start ? `–${claim.line_end}` : ""}
        </span>
        {rejected ? (
          <span className="inline-flex items-center gap-1 rounded-md bg-sev-medium/10 px-1.5 py-0.5 text-[11px] text-sev-medium ring-1 ring-sev-medium/25 ring-inset">
            <Ban className="size-3" /> Hallucination blocked
          </span>
        ) : verdict ? (
          <span className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] ring-1 ring-inset", verdict.upheld ? "bg-accent/10 text-accent ring-accent/25" : "bg-s3 text-fg-2 ring-line-strong")}>
            <Gavel className="size-3" /> {verdict.upheld ? `Upheld · ${Math.round(verdict.confidence * 100)}%` : "Overruled"}
          </span>
        ) : (
          <span className="shimmer-text text-[11px]">deliberating…</span>
        )}
      </header>

      <div className={cn("grid divide-line", compact ? "grid-cols-1 divide-y md:grid-cols-3 md:divide-x md:divide-y-0" : "grid-cols-1 divide-y lg:grid-cols-3 lg:divide-x lg:divide-y-0")}>
        <section className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] font-medium text-critic">
            <Swords className="size-3.5" /> Critic
            {claim.related_finding && <span className="ml-auto font-mono text-[10.5px] text-fg-3">confirms {claim.related_finding.split("-").slice(0, 3).join("-")}</span>}
          </div>
          <p className="mt-2 text-[12.5px] leading-relaxed text-fg-2">{claim.exploit}</p>
          {!compact && <Snippet code={claim.evidence} />}
          {rejected && <p className="mt-2 text-[11.5px] text-sev-medium">{claim.grounding.note}</p>}
          {claim.grounding.relocated && <p className="mt-2 text-[11.5px] text-fg-3">{claim.grounding.note}</p>}
        </section>

        <section className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] font-medium text-defender">
            <Shield className="size-3.5" /> Defender
            {claim.defender && <span className={cn("ml-auto rounded px-1.5 py-0.5 text-[10.5px] ring-1 ring-inset", STANCE[claim.defender.stance].cls)}>{STANCE[claim.defender.stance].label}</span>}
          </div>
          {rejected ? (
            <p className="mt-2 text-[12.5px] text-fg-3">Never reached the Defender — the claim quoted code that isn&apos;t in the file.</p>
          ) : claim.defender ? (
            <>
              <p className="mt-2 text-[12.5px] leading-relaxed text-fg-2">{claim.defender.argument}</p>
              {!compact && claim.defender.fix && <Snippet code={claim.defender.fix} />}
            </>
          ) : (
            <p className="shimmer-text mt-2 text-[12.5px]">preparing rebuttal…</p>
          )}
        </section>

        <section className="p-4">
          <div className="flex items-center gap-1.5 text-[12px] font-medium text-judge">
            <Scale className="size-3.5" /> Judge
          </div>
          {rejected ? (
            <p className="mt-2 text-[12.5px] text-fg-3">Dismissed automatically.</p>
          ) : verdict ? (
            <>
              <p className="mt-2 text-[12.5px] leading-relaxed text-fg-2">{verdict.rationale}</p>
              <div className="mt-3 flex items-center gap-2">
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-s3">
                  <div className={cn("h-full rounded-full", verdict.upheld ? "bg-accent" : "bg-fg-3")} style={{ width: `${verdict.confidence * 100}%` }} />
                </div>
                <span className="font-mono text-[11px] text-fg-3">{Math.round(verdict.confidence * 100)}%</span>
              </div>
            </>
          ) : (
            <p className="shimmer-text mt-2 text-[12.5px]">awaiting arguments…</p>
          )}
        </section>
      </div>
    </article>
  );
}

export function DebateView({ swarm }: { swarm: SwarmResult }) {
  const s = swarm.stats;
  const tokens = swarm.agents.reduce((n, a) => n + a.inputTokens + a.outputTokens, 0);
  const stats = [
    { label: "Claims raised", value: s.claims },
    { label: "Hallucinations blocked", value: s.ungrounded },
    { label: "Upheld", value: s.upheld },
    { label: "Overruled", value: s.overruled },
    { label: "Static findings dismissed", value: s.dismissedStatic },
    { label: "Novel issues", value: s.novel },
  ];
  return (
    <div className="space-y-4">
      <div className="panel p-5">
        <SectionLabel>Judge&apos;s summary</SectionLabel>
        <p className="mt-2 max-w-3xl text-[14px] leading-relaxed text-fg">{swarm.summary}</p>
        <dl className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {stats.map((x) => (
            <div key={x.label} className="rounded-xl border border-line bg-s2/60 px-3 py-2.5">
              <dt className="text-[11.5px] text-fg-3">{x.label}</dt>
              <dd className="mt-0.5 font-mono text-xl tabular-nums">{x.value}</dd>
            </div>
          ))}
        </dl>
        <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11.5px] text-fg-3">
          {swarm.agents.map((a) => (
            <span key={a.agent}>
              <span className={cn(a.agent === "critic" ? "text-critic" : a.agent === "defender" ? "text-defender" : "text-judge")}>{a.agent}</span> {(a.ms / 1000).toFixed(1)}s · {(a.inputTokens + a.outputTokens).toLocaleString()} tok
              {a.repaired ? " · self-repaired" : ""}
            </span>
          ))}
          <span>
            {swarm.model} · {tokens.toLocaleString()} tokens total
          </span>
        </div>
      </div>
      {swarm.claims.length === 0 ? (
        <p className="text-[13px] text-fg-3">The Critic raised no claims.</p>
      ) : (
        swarm.claims.map((c) => <ClaimCard key={c.id} claim={c} />)
      )}
    </div>
  );
}
