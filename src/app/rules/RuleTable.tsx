"use client";

import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import type { Detector, Severity } from "@/lib/engine/types";
import { DETECTOR_META } from "@/components/audit/Findings";
import { SeverityBadge, cn } from "@/components/ui";

interface Row {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cwe: string[];
  owasp?: string;
  languages: string;
  detector: Detector;
  description: string;
  remediation: string;
}

const DETECTORS: Array<Detector | "all"> = ["all", "taint", "pattern", "secret", "metric"];

export function RuleTable({ rules }: { rules: Row[] }) {
  const [q, setQ] = useState("");
  const [detector, setDetector] = useState<Detector | "all">("all");
  const [open, setOpen] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rules.filter((r) => (detector === "all" || r.detector === detector) && (!needle || `${r.id} ${r.title} ${r.cwe.join(" ")} ${r.languages} ${r.category}`.toLowerCase().includes(needle)));
  }, [rules, q, detector]);

  return (
    <div className="mt-10">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <label className="flex h-10 flex-1 items-center gap-2 rounded-xl border border-line-strong bg-s1 px-3 focus-within:border-accent/50">
          <Search className="size-4 text-fg-3" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rules, CWE ids, languages…" className="min-w-0 flex-1 bg-transparent text-[13.5px] placeholder:text-fg-3 focus:outline-none" aria-label="Search rules" />
        </label>
        <div className="flex gap-1 overflow-x-auto">
          {DETECTORS.map((d) => (
            <button key={d} onClick={() => setDetector(d)} className={cn("h-10 shrink-0 rounded-xl px-3 text-[12.5px]", detector === d ? "bg-s3 text-fg" : "text-fg-3 hover:text-fg-2")}>
              {d === "all" ? "All" : DETECTOR_META[d].label} <span className="font-mono text-fg-3">{d === "all" ? rules.length : rules.filter((r) => r.detector === d).length}</span>
            </button>
          ))}
        </div>
      </div>
      <ul className="panel mt-4 divide-y divide-line overflow-hidden">
        {filtered.map((r) => {
          const D = DETECTOR_META[r.detector];
          const expanded = open === r.id;
          return (
            <li key={r.id}>
              <button onClick={() => setOpen(expanded ? null : r.id)} aria-expanded={expanded} className="grid w-full gap-2 px-4 py-3 text-left hover:bg-s2/50 sm:grid-cols-[9.5rem_minmax(0,1fr)_auto] sm:items-center sm:gap-4">
                <span className="font-mono text-[12px] text-fg-3">{r.id}</span>
                <span className="min-w-0">
                  <span className="block truncate text-[13.5px] text-fg">{r.title}</span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-3 text-[11.5px] text-fg-3">
                    <span className="flex items-center gap-1">
                      <D.Icon className="size-3" /> {D.label}
                    </span>
                    <span className="font-mono">{r.cwe.join(", ")}</span>
                    <span className="truncate">{r.languages}</span>
                  </span>
                </span>
                <SeverityBadge severity={r.severity} />
              </button>
              {expanded && (
                <div className="grid gap-4 bg-s2/30 px-4 pt-1 pb-4 text-[13px] leading-relaxed text-fg-2 sm:grid-cols-2 sm:pl-[11.5rem]">
                  <p>{r.description}</p>
                  <p>
                    <span className="text-fg">Fix: </span>
                    {r.remediation}
                    {r.owasp && <span className="mt-2 block font-mono text-[11.5px] text-fg-3">{r.owasp}</span>}
                  </p>
                </div>
              )}
            </li>
          );
        })}
        {!filtered.length && <li className="px-4 py-10 text-center text-[13px] text-fg-3">No rules match.</li>}
      </ul>
    </div>
  );
}
