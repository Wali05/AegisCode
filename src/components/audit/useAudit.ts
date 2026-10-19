"use client";

import { useCallback, useEffect, useReducer, useRef } from "react";
import { streamAudit, type AuditRequest } from "@/lib/client/stream";
import type { AuditReport, DebateClaim, PipelineEvent, StageId, StageRecord } from "@/lib/report/types";

export const STAGE_ORDER: StageId[] = ["ingest", "parse", "taint", "patterns", "secrets", "metrics", "deps", "triage", "critic", "defender", "judge", "verify"];

export type LogLine = Extract<PipelineEvent, { type: "log" }> & { id: number };

export interface AuditState {
  phase: "idle" | "running" | "done" | "error";
  request: AuditRequest | null;
  stages: Partial<Record<StageId, StageRecord>>;
  logs: LogLine[];
  claims: DebateClaim[];
  progress: { index: number; total: number; path: string } | null;
  report: AuditReport | null;
  error: { message: string; hint?: string; status: number } | null;
  startedAt: number;
}

type Action =
  | { type: "start"; request: AuditRequest }
  | { type: "event"; event: PipelineEvent }
  | { type: "fail"; message: string; hint?: string }
  | { type: "reset" }
  | { type: "restore"; report: AuditReport };

const initial: AuditState = { phase: "idle", request: null, stages: {}, logs: [], claims: [], progress: null, report: null, error: null, startedAt: 0 };

let logId = 0;

function reducer(state: AuditState, action: Action): AuditState {
  switch (action.type) {
    case "start":
      return { ...initial, phase: "running", request: action.request, startedAt: Date.now() };
    case "reset":
      return initial;
    case "restore":
      return { ...initial, phase: "done", report: action.report, stages: Object.fromEntries(action.report.stages.map((s) => [s.id, s])) };
    case "fail":
      return { ...state, phase: "error", error: { message: action.message, hint: action.hint, status: 0 } };
    case "event": {
      const e = action.event;
      switch (e.type) {
        case "stage":
          return { ...state, stages: { ...state.stages, [e.stage.id]: e.stage } };
        case "log":
          return { ...state, logs: [...state.logs, { ...e, id: logId++ }].slice(-400) };
        case "file":
          return { ...state, progress: { index: e.index, total: e.total, path: e.path } };
        case "claim": {
          const exists = state.claims.some((c) => c.id === e.claim.id);
          return { ...state, claims: exists ? state.claims.map((c) => (c.id === e.claim.id ? e.claim : c)) : [...state.claims, e.claim] };
        }
        case "report":
          return { ...state, phase: "done", report: e.report, stages: Object.fromEntries(e.report.stages.map((s) => [s.id, s])) };
        case "error":
          return { ...state, phase: "error", error: { message: e.message, hint: e.hint, status: e.status } };
      }
    }
  }
  return state;
}

const STORAGE_KEY = "aegis:last-report";

export function useAudit() {
  const [state, dispatch] = useReducer(reducer, initial);
  const controller = useRef<AbortController | null>(null);

  // Restore the last report after a refresh (best-effort; storage may be unavailable).
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(STORAGE_KEY);
      if (saved) dispatch({ type: "restore", report: JSON.parse(saved) as AuditReport });
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    if (state.phase !== "done" || !state.report) return;
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state.report));
    } catch {
      /* quota exceeded or storage disabled */
    }
  }, [state.phase, state.report]);

  const run = useCallback(async (request: AuditRequest) => {
    controller.current?.abort();
    const ac = new AbortController();
    controller.current = ac;
    dispatch({ type: "start", request });
    try {
      for await (const event of streamAudit(request, ac.signal)) dispatch({ type: "event", event });
    } catch (err) {
      if (ac.signal.aborted) return;
      dispatch({ type: "fail", message: err instanceof Error ? err.message : "Connection lost.", hint: "Check your connection and try again." });
    }
  }, []);

  const cancel = useCallback(() => {
    controller.current?.abort();
    dispatch({ type: "reset" });
  }, []);

  const reset = useCallback(() => {
    controller.current?.abort();
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
    dispatch({ type: "reset" });
  }, []);

  return { state, run, cancel, reset };
}
