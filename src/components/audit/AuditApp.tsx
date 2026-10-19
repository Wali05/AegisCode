"use client";

import { useEffect, type ReactNode } from "react";
import { AlertOctagon, RotateCcw } from "lucide-react";
import { useAudit } from "./useAudit";
import { Console, useHealth } from "./Console";
import { RunView } from "./RunView";
import { Report } from "./Report";
import { Button } from "../ui";

export function AuditApp({ hero, children, initialUrl }: { hero: ReactNode; children: ReactNode; initialUrl?: string }) {
  const { state, run, cancel, reset } = useAudit();
  const health = useHealth();

  useEffect(() => {
    if (state.phase !== "running") return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && cancel();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state.phase, cancel]);

  if (state.phase === "running") {
    return (
      <main className="mx-auto w-full max-w-7xl px-4 pt-8 pb-24 sm:px-6">
        <RunView state={state} onCancel={cancel} />
      </main>
    );
  }

  if (state.phase === "done" && state.report) {
    return (
      <main className="mx-auto w-full max-w-7xl px-4 pt-8 pb-24 sm:px-6">
        <Report report={state.report} onReset={reset} />
      </main>
    );
  }

  return (
    <main>
      <section className="mx-auto w-full max-w-4xl px-4 pt-16 pb-10 sm:px-6 sm:pt-24">
        {hero}
        <div className="mt-10 animate-fade-up [animation-delay:120ms]">
          <Console onRun={run} health={health} busy={false} initialUrl={initialUrl} />
          {state.phase === "error" && state.error && (
            <div role="alert" className="mt-4 flex items-start gap-3 rounded-xl border border-sev-critical/30 bg-sev-critical/[0.06] p-4">
              <AlertOctagon className="mt-0.5 size-4 shrink-0 text-sev-critical" />
              <div className="min-w-0 flex-1">
                <div className="text-[13.5px] font-medium text-fg">{state.error.message}</div>
                {state.error.hint && <div className="mt-0.5 text-[12.5px] text-fg-2">{state.error.hint}</div>}
              </div>
              {state.request && (
                <Button size="sm" onClick={() => run(state.request!)}>
                  <RotateCcw className="size-3.5" /> Retry
                </Button>
              )}
            </div>
          )}
        </div>
      </section>
      {children}
    </main>
  );
}
