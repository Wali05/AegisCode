"use client";

import { useMemo, useState } from "react";
import { diffLines } from "diff";
import { ArrowRight, Check, Copy, Download, TriangleAlert } from "lucide-react";
import type { PatchVerification } from "@/lib/report/types";
import { GRADE_COLOR } from "./charts";
import { Button, SectionLabel, cn } from "../ui";

interface Row {
  kind: "add" | "del" | "ctx" | "gap";
  oldNo?: number;
  newNo?: number;
  text: string;
}

const CONTEXT = 3;

function buildRows(before: string, after: string): Row[] {
  const rows: Row[] = [];
  let o = 1;
  let n = 1;
  for (const part of diffLines(before, after)) {
    const lines = part.value.replace(/\n$/, "").split("\n");
    for (const text of lines) {
      if (part.added) rows.push({ kind: "add", newNo: n++, text });
      else if (part.removed) rows.push({ kind: "del", oldNo: o++, text });
      else rows.push({ kind: "ctx", oldNo: o++, newNo: n++, text });
    }
  }
  // Collapse long unchanged runs to CONTEXT lines either side of a change.
  const keep = rows.map((r) => r.kind !== "ctx");
  rows.forEach((r, i) => {
    if (r.kind !== "ctx") for (let k = Math.max(0, i - CONTEXT); k <= Math.min(rows.length - 1, i + CONTEXT); k++) keep[k] = true;
  });
  const out: Row[] = [];
  let skipped = 0;
  rows.forEach((r, i) => {
    if (keep[i]) {
      if (skipped) out.push({ kind: "gap", text: `${skipped} unchanged lines` });
      skipped = 0;
      out.push(r);
    } else skipped++;
  });
  if (skipped) out.push({ kind: "gap", text: `${skipped} unchanged lines` });
  return out;
}

export function PatchView({ patch, original, filename }: { patch: PatchVerification; original: string; filename: string }) {
  const rows = useMemo(() => buildRows(original, patch.code), [original, patch.code]);
  const [copied, setCopied] = useState(false);
  const adds = rows.filter((r) => r.kind === "add").length;
  const dels = rows.filter((r) => r.kind === "del").length;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(patch.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([patch.code], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename.split("/").pop() ?? "patched.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="panel grid gap-5 p-5 md:grid-cols-[auto_1fr_auto] md:items-center">
        <div className="flex items-center gap-4">
          <ScorePill label="Before" score={patch.before.score} grade={patch.before.grade} />
          <ArrowRight className="size-4 text-fg-3" />
          <ScorePill label="After" score={patch.after.score} grade={patch.after.grade} />
        </div>
        <div className="space-y-1.5 text-[13px]">
          <SectionLabel>Verified remediation</SectionLabel>
          <p className="text-fg-2">
            The Judge&apos;s patched file was re-scanned by the same deterministic engine:{" "}
            <span className="text-accent">{patch.resolved} resolved</span>,{" "}
            <span className={patch.introduced ? "text-sev-high" : "text-fg"}>{patch.introduced} introduced</span>.
          </p>
          <p className="flex items-center gap-1.5 text-fg-2">
            {patch.parses === null ? (
              <span className="text-fg-3">Syntax check not available for this language.</span>
            ) : patch.parses ? (
              <>
                <Check className="size-3.5 text-accent" /> Patch parses cleanly (TypeScript compiler)
              </>
            ) : (
              <>
                <TriangleAlert className="size-3.5 text-sev-high" /> Patch has syntax errors: {patch.diagnostics[0]}
              </>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" onClick={copy}>
            {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? "Copied" : "Copy"}
          </Button>
          <Button size="sm" onClick={download}>
            <Download className="size-3.5" /> Download
          </Button>
        </div>
      </div>

      <div className="panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5 font-mono text-[12px]">
          <span className="truncate text-fg-2">{filename}</span>
          <span>
            <span className="text-accent">+{adds}</span> <span className="text-sev-critical">−{dels}</span>
          </span>
        </div>
        <div className="code max-h-[70vh] overflow-auto py-1">
          {rows.map((r, i) =>
            r.kind === "gap" ? (
              <div key={i} className="my-1 bg-s2/70 px-4 py-1 text-[11px] text-fg-3">
                ⋯ {r.text}
              </div>
            ) : (
              <div key={i} className={cn("flex min-w-max", r.kind === "add" && "bg-accent/[0.07]", r.kind === "del" && "bg-sev-critical/[0.08]")}>
                <span className="w-11 shrink-0 pr-2 text-right text-[11px] text-fg-3 select-none">{r.oldNo ?? ""}</span>
                <span className="w-11 shrink-0 pr-2 text-right text-[11px] text-fg-3 select-none">{r.newNo ?? ""}</span>
                <span className={cn("w-5 shrink-0 text-center select-none", r.kind === "add" ? "text-accent" : r.kind === "del" ? "text-sev-critical" : "text-fg-3")}>{r.kind === "add" ? "+" : r.kind === "del" ? "−" : " "}</span>
                <span className={cn("pr-6 whitespace-pre", r.kind === "ctx" ? "text-fg-2" : "text-fg")}>{r.text}</span>
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}

function ScorePill({ label, score, grade }: { label: string; score: number; grade: keyof typeof GRADE_COLOR }) {
  return (
    <div className="text-center">
      <div className="text-[11px] text-fg-3">{label}</div>
      <div className="font-mono text-3xl font-semibold tabular-nums" style={{ color: GRADE_COLOR[grade] }}>
        {score}
      </div>
      <div className="font-mono text-[11px] text-fg-3">grade {grade}</div>
    </div>
  );
}
