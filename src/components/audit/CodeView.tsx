"use client";

import { memo, useEffect, useMemo, useRef } from "react";
import { highlight } from "sugar-high";
import type { Finding } from "@/lib/engine/types";
import { SEVERITY_META, cn } from "../ui";
import { SEVERITY_RANK } from "@/lib/engine/finding";

const highlightCache = new Map<string, string[]>();

function highlightLines(code: string): string[] {
  const hit = highlightCache.get(code);
  if (hit) return hit;
  // sugar-high emits one <span class="sh__line"> per source line, so a split keeps spans balanced.
  const lines = highlight(code).split("\n");
  if (highlightCache.size > 30) highlightCache.clear();
  highlightCache.set(code, lines);
  return lines;
}

export interface CodeViewProps {
  code: string;
  findings?: Finding[];
  /** Lines to emphasise (e.g. the selected finding and its trace). */
  focus?: { start: number; end: number; trace?: number[] } | null;
  /** Show only a window around the focus instead of the whole file. */
  window?: number;
  onSelectLine?: (line: number) => void;
  className?: string;
  maxHeight?: string;
}

export const CodeView = memo(function CodeView({ code, findings = [], focus, window, onSelectLine, className, maxHeight = "70vh" }: CodeViewProps) {
  const lines = useMemo(() => highlightLines(code), [code]);
  const scroller = useRef<HTMLDivElement>(null);

  const byLine = useMemo(() => {
    const m = new Map<number, Finding[]>();
    for (const f of findings) {
      if (f.status === "dismissed") continue;
      m.set(f.location.line, [...(m.get(f.location.line) ?? []), f]);
    }
    return m;
  }, [findings]);

  const traceLines = useMemo(() => new Set(focus?.trace ?? []), [focus]);

  let from = 1;
  let to = lines.length;
  if (window && focus) {
    from = Math.max(1, focus.start - window);
    to = Math.min(lines.length, focus.end + window);
  }

  useEffect(() => {
    if (window || !focus || !scroller.current) return;
    const el = scroller.current.querySelector<HTMLElement>(`[data-line="${focus.start}"]`);
    if (el) scroller.current.scrollTo({ top: el.offsetTop - scroller.current.clientHeight / 3, behavior: "smooth" });
  }, [focus, window]);

  const rows = [];
  for (let n = from; n <= to; n++) {
    const hits = byLine.get(n);
    const worst = hits?.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
    const inFocus = !!focus && n >= focus.start && n <= focus.end;
    const inTrace = traceLines.has(n) && !inFocus;
    rows.push(
      <div
        key={n}
        data-line={n}
        className={cn(
          "group flex min-w-max",
          inFocus && "bg-accent/[0.07] shadow-[inset_2px_0_0_var(--color-accent)]",
          inTrace && "bg-judge/[0.06] shadow-[inset_2px_0_0_var(--color-judge)]",
          !inFocus && !inTrace && worst && "bg-white/[0.02]"
        )}
      >
        <button
          type="button"
          tabIndex={hits ? 0 : -1}
          onClick={() => hits && onSelectLine?.(n)}
          className={cn("sticky left-0 z-10 flex w-14 shrink-0 items-center justify-end gap-1.5 bg-s1 pr-3 text-right font-mono text-[11px] text-fg-3 tabular-nums select-none", hits && "cursor-pointer text-fg-2 hover:text-fg")}
          aria-label={hits ? `Line ${n}: ${hits.map((h) => h.title).join("; ")}` : undefined}
          title={hits?.map((h) => `${SEVERITY_META[h.severity].label}: ${h.title}`).join("\n")}
        >
          {worst && <span className={cn("size-1.5 rounded-full", SEVERITY_META[worst.severity].dot)} />}
          {n}
        </button>
        {/* aegis-ignore AEG-JS-008 -- sugar-high HTML-escapes every token (covered by a unit test) */}
        <span className="pr-6" dangerouslySetInnerHTML={{ __html: lines[n - 1] ?? "" }} />
      </div>
    );
  }

  return (
    <div ref={scroller} className={cn("code relative overflow-auto rounded-xl border border-line bg-s1 py-2", className)} style={{ maxHeight }}>
      {from > 1 && <div className="px-14 pb-1 font-mono text-[11px] text-fg-3">⋯ {from - 1} lines above</div>}
      {rows}
      {to < lines.length && <div className="px-14 pt-1 font-mono text-[11px] text-fg-3">⋯ {lines.length - to} lines below</div>}
    </div>
  );
});
