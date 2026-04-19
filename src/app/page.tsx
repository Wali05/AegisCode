"use client";

import { useState, useRef, useEffect, useCallback, FormEvent } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";

// --- Types ---

interface AuditResult {
  file: string;
  repo: string;
  branch: string;
  verdict: string;
  culprit: string;
  confidence_score: number;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  original_code: string;
  optimized_code: string;
}

interface ApiSuccessResponse {
  success: true;
  ml_bypassed?: boolean;
  audit: AuditResult;
}

interface ApiErrorResponse {
  error: string;
  hint?: string;
}

interface LogEntry {
  id: number;
  timestamp: string;
  prefix: string;
  message: string;
  color: "green" | "cyan" | "amber" | "red" | "muted";
}

// --- Terminal log sequences ---

const SWARM_LOG_SEQUENCE: Omit<LogEntry, "id" | "timestamp">[] = [
  { prefix: "SYS", message: "Initializing AegisCode swarm pipeline...", color: "cyan" },
  { prefix: "SYS", message: "Validating GitHub URL format...", color: "cyan" },
  { prefix: "NET", message: "Establishing authenticated connection to GitHub API...", color: "muted" },
  { prefix: "NET", message: "Fetching raw file content from repository...", color: "muted" },
  { prefix: "NET", message: "Resolving last commit author via git history...", color: "muted" },
  { prefix: "SYS", message: "File content received. Preparing swarm deployment.", color: "cyan" },
  { prefix: "ML", message: "Extracting structural features (LOC, cyclomatic complexity)...", color: "amber" },
  { prefix: "ML", message: "Running K-Means Clustering — assigning complexity tier...", color: "amber" },
  { prefix: "ML", message: "Deploying CodeBERT SLM — scanning for high-risk code patterns...", color: "amber" },
  { prefix: "SYS", message: "ML Pre-Triage complete. Evaluating bypass eligibility...", color: "cyan" },
  { prefix: "SWARM", message: "Deploying Agent 1 of 3...", color: "green" },
  { prefix: "AGENT 1", message: "Critic online. Mapping abstract syntax tree...", color: "green" },
  { prefix: "AGENT 1", message: "Scanning for algorithmic bottlenecks (O(N) analysis)...", color: "green" },
  { prefix: "AGENT 1", message: "Probing for injection vectors and SSRF patterns...", color: "green" },
  { prefix: "AGENT 1", message: "Checking memory lifecycle and resource cleanup...", color: "green" },
  { prefix: "AGENT 1", message: "Critic report generated. Handing off to Defender.", color: "green" },
  { prefix: "SWARM", message: "Deploying Agent 2 of 3...", color: "cyan" },
  { prefix: "AGENT 2", message: "Defender online. Ingesting Critic report...", color: "cyan" },
  { prefix: "AGENT 2", message: "Cross-referencing claims against source code...", color: "cyan" },
  { prefix: "AGENT 2", message: "Validating vulnerability reproducibility...", color: "cyan" },
  { prefix: "AGENT 2", message: "Flagging hallucinated findings for dismissal...", color: "cyan" },
  { prefix: "AGENT 2", message: "Building optimized code patch...", color: "cyan" },
  { prefix: "AGENT 2", message: "Defender rebuttal complete. Escalating to Judge.", color: "cyan" },
  { prefix: "SWARM", message: "Deploying Agent 3 of 3...", color: "amber" },
  { prefix: "AGENT 3", message: "Judge online. Ingesting full debate context...", color: "amber" },
  { prefix: "AGENT 3", message: "Weighing Critic aggression vs Defender rebuttals...", color: "amber" },
  { prefix: "AGENT 3", message: "Discarding unsubstantiated claims...", color: "amber" },
  { prefix: "AGENT 3", message: "Synthesizing final optimized payload...", color: "amber" },
  { prefix: "AGENT 3", message: "Serializing verdict to structured JSON...", color: "amber" },
  { prefix: "SYS", message: "All agents returned. Parsing final payload...", color: "cyan" },
];

// --- Helpers ---

function getTimestamp(): string {
  const now = new Date();
  return [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
}

function colorClass(color: LogEntry["color"]): string {
  switch (color) {
    case "green":
      return "text-neon-green";
    case "cyan":
      return "text-neon-cyan";
    case "amber":
      return "text-neon-amber";
    case "red":
      return "text-neon-red";
    case "muted":
      return "text-text-muted";
  }
}

/**
 * Client-side validation: ensures the URL points to a GitHub file,
 * not a directory, profile, or unrelated domain.
 */
function isValidGitHubFileUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    const host = url.hostname.toLowerCase();

    if (host === "raw.githubusercontent.com") {
      // Must have at least /owner/repo/branch/filepath
      return url.pathname.split("/").filter(Boolean).length >= 4;
    }

    if (host === "github.com") {
      const parts = url.pathname.split("/").filter(Boolean);
      // Must match /owner/repo/blob/branch/...file
      return parts.length >= 5 && parts[2] === "blob";
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Returns Tailwind classes for the severity badge based on level.
 */
function severityStyle(level: AuditResult["severity"]): {
  bg: string;
  text: string;
  ring: string;
  pulse: boolean;
} {
  switch (level) {
    case "Critical":
      return { bg: "bg-red-950", text: "text-red-400", ring: "ring-red-500/40", pulse: true };
    case "High":
      return { bg: "bg-orange-950", text: "text-orange-400", ring: "ring-orange-500/30", pulse: false };
    case "Medium":
      return { bg: "bg-yellow-950", text: "text-yellow-400", ring: "ring-yellow-500/30", pulse: false };
    case "Low":
      return { bg: "bg-blue-950", text: "text-blue-400", ring: "ring-blue-500/30", pulse: false };
    case "None":
    default:
      return { bg: "bg-emerald-950", text: "text-emerald-400", ring: "ring-emerald-500/30", pulse: false };
  }
}

// --- Component ---

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<ApiErrorResponse | null>(null);

  const terminalRef = useRef<HTMLDivElement>(null);
  const logIndexRef = useRef(0);
  const logIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const logIdCounter = useRef(0);

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs, result, error]);

  const pushLog = useCallback(
    (entry: Omit<LogEntry, "id" | "timestamp">) => {
      const newLog: LogEntry = {
        ...entry,
        id: logIdCounter.current++,
        timestamp: getTimestamp(),
      };
      setLogs((prev) => [...prev, newLog]);
    },
    []
  );

  const startLogSimulation = useCallback(() => {
    logIndexRef.current = 0;

    // Push the first log immediately
    if (SWARM_LOG_SEQUENCE.length > 0) {
      pushLog(SWARM_LOG_SEQUENCE[0]);
      logIndexRef.current = 1;
    }

    logIntervalRef.current = setInterval(() => {
      if (logIndexRef.current < SWARM_LOG_SEQUENCE.length) {
        pushLog(SWARM_LOG_SEQUENCE[logIndexRef.current]);
        logIndexRef.current++;
      }
      // interval stays alive — cleared when request completes
    }, 3000);
  }, [pushLog]);

  const stopLogSimulation = useCallback(() => {
    if (logIntervalRef.current) {
      clearInterval(logIntervalRef.current);
      logIntervalRef.current = null;
    }
  }, []);

  const resetWorkspace = useCallback(() => {
    setUrl("");
    setLoading(false);
    setLogs([]);
    setResult(null);
    setError(null);
    stopLogSimulation();
  }, [stopLogSimulation]);

  // Cleanup on unmount
  useEffect(() => {
    return () => stopLogSimulation();
  }, [stopLogSimulation]);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();

    const trimmed = url.trim();
    if (!trimmed) return;

    // Client-side URL validation — abort before hitting the backend
    if (!isValidGitHubFileUrl(trimmed)) {
      setResult(null);
      setLogs([]);
      setError({
        error:
          "Invalid GitHub file URL. The link must point to a specific file (contain /blob/ in the path) on github.com, or be a raw.githubusercontent.com URL.",
        hint:
          "Example: https://github.com/owner/repo/blob/main/src/index.ts",
      });
      return;
    }

    // Reset state
    setResult(null);
    setError(null);
    setLogs([]);
    setLoading(true);

    startLogSimulation();

    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ githubUrl: trimmed }),
      });

      const data = await res.json();

      stopLogSimulation();

      if (!res.ok) {
        const errData = data as ApiErrorResponse;
        pushLog({
          prefix: "ERR",
          message: `${res.status} — ${errData.error}`,
          color: "red",
        });
        setError(errData);
      } else {
        const successData = data as ApiSuccessResponse;
        if (successData.ml_bypassed) {
          pushLog({
            prefix: "ML",
            message: "Pre-Triage bypass activated — file cleared without full swarm.",
            color: "green",
          });
        } else {
          pushLog({
            prefix: "SYS",
            message: "Swarm audit complete. Rendering verdict.",
            color: "green",
          });
        }
        setResult(successData.audit);
      }
    } catch (err) {
      stopLogSimulation();
      const message =
        err instanceof Error ? err.message : "Network request failed.";
      pushLog({ prefix: "ERR", message, color: "red" });
      setError({ error: message, hint: "Check your network connection and try again." });
    } finally {
      setLoading(false);
    }
  }

  // --- Idle state content for the terminal ---
  const isIdle = !loading && !result && !error && logs.length === 0;

  return (
    <div className="flex flex-col min-h-screen bg-surface-0">
      {/* ── Nav ─────────────────────────────────── */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-border-dim bg-surface-1/60 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
          <h1 className="text-sm font-bold tracking-widest uppercase text-neon-green">
            AegisCode
          </h1>
          <span className="text-text-muted text-xs tracking-wide hidden sm:inline">
            // Zero-Trust Swarm
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <span className="hidden sm:inline">v1.0.0</span>
          <span className="w-px h-3 bg-border-dim hidden sm:inline" />
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-neon-cyan transition-colors"
          >
            GitHub
          </a>
        </div>
      </header>

      {/* ── Main ────────────────────────────────── */}
      <main className="flex-1 flex flex-col md:flex-row">
        {/* ── Left Panel: Input ────────────────── */}
        <section className="w-full md:w-[420px] xl:w-[480px] flex-shrink-0 border-b md:border-b-0 md:border-r border-border-dim bg-surface-1/40 flex flex-col">
          <div className="p-6 flex flex-col gap-6 flex-1">
            {/* Section label */}
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-neon-cyan" />
              <span className="text-xs font-semibold tracking-widest uppercase text-neon-cyan">
                Target Acquisition
              </span>
            </div>

            {/* Branding block */}
            <div className="space-y-3">
              <h2 className="text-2xl font-bold tracking-tight text-foreground">
                Deploy the Swarm
              </h2>
              <p className="text-sm text-text-muted leading-relaxed">
                Paste a direct GitHub file URL. The swarm will fetch the source,
                identify the last committer, and deploy three adversarial AI
                agents to audit the code for vulnerabilities, bottlenecks, and
                memory leaks.
              </p>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="relative">
                <label htmlFor="github-url" className="sr-only">
                  GitHub File URL
                </label>
                <input
                  id="github-url"
                  type="url"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading}
                  placeholder="https://github.com/owner/repo/blob/main/src/index.ts"
                  className="w-full bg-surface-0 border border-border-dim rounded-lg px-4 py-3 text-sm text-foreground placeholder:text-text-muted/50 focus:outline-none focus:border-neon-cyan/50 focus:ring-1 focus:ring-neon-cyan/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                />
              </div>

              <button
                id="deploy-swarm-btn"
                type="submit"
                disabled={loading || !url.trim()}
                className={`w-full py-3 px-6 rounded-lg text-sm font-bold uppercase tracking-widest transition-all
                  ${
                    loading
                      ? "bg-surface-3 text-text-muted cursor-wait border border-border-dim"
                      : "bg-neon-green/10 text-neon-green border border-neon-green/30 hover:bg-neon-green/20 hover:border-neon-green/50 btn-glow disabled:opacity-30 disabled:cursor-not-allowed disabled:animate-none"
                  }`}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg
                      className="animate-spin h-4 w-4"
                      viewBox="0 0 24 24"
                      fill="none"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="3"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                      />
                    </svg>
                    Swarm Active...
                  </span>
                ) : (
                  "Deploy Swarm"
                )}
              </button>
            </form>

            {/* Agent legend */}
            <div className="mt-auto pt-6 border-t border-border-dim">
              <p className="text-[10px] font-semibold tracking-widest uppercase text-text-muted mb-3">
                Swarm Agents
              </p>
              <div className="space-y-2">
                {[
                  { label: "Critic", desc: "Aggressive vulnerability scanner", color: "bg-neon-green" },
                  { label: "Defender", desc: "Hallucination filter & fix proposer", color: "bg-neon-cyan" },
                  { label: "Judge", desc: "Final arbiter & code synthesizer", color: "bg-neon-amber" },
                ].map((agent) => (
                  <div key={agent.label} className="flex items-center gap-2.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${agent.color}`} />
                    <span className="text-xs text-foreground font-medium">
                      {agent.label}
                    </span>
                    <span className="text-xs text-text-muted">
                      — {agent.desc}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ── Right Panel: Terminal ─────────────── */}
        <section className="flex-1 flex flex-col bg-surface-0 relative overflow-hidden min-h-[500px] md:min-h-0">
          <div className="scanlines" />

          {/* Terminal header bar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-border-dim bg-surface-1/60 backdrop-blur-sm z-10 relative">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-neon-red/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-neon-amber/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-neon-green/60" />
              </div>
              <span className="text-[10px] text-text-muted ml-2 tracking-wider uppercase">
                aegis://terminal
              </span>
            </div>
            {loading && (
              <span className="text-[10px] text-neon-green tracking-wider animate-pulse uppercase">
                ● Live
              </span>
            )}
            {result && (
              <span className="text-[10px] text-neon-green tracking-wider uppercase">
                ● Complete
              </span>
            )}
          </div>

          {/* Terminal body */}
          <div
            ref={terminalRef}
            className="flex-1 overflow-y-auto p-4 space-y-1 text-xs leading-relaxed z-10 relative"
          >
            {/* Idle state */}
            {isIdle && (
              <div className="h-full flex flex-col items-center justify-center text-center gap-4 opacity-40">
                <div className="text-4xl">⛊</div>
                <div>
                  <p className="text-sm text-text-muted font-medium">
                    Awaiting target URL
                  </p>
                  <p className="text-xs text-text-muted/60 mt-1">
                    Paste a GitHub file link and deploy the swarm
                  </p>
                </div>
              </div>
            )}

            {/* Live logs */}
            {logs.map((log) => (
              <div key={log.id} className="log-line flex gap-2">
                <span className="text-text-muted/50 select-none shrink-0">
                  {log.timestamp}
                </span>
                <span
                  className={`font-bold shrink-0 ${colorClass(log.color)}`}
                >
                  [{log.prefix}]
                </span>
                <span className="text-foreground/80">{log.message}</span>
              </div>
            ))}

            {/* Blinking cursor while loading */}
            {loading && (
              <div className="log-line">
                <span className="cursor-blink text-text-muted/30" />
              </div>
            )}

            {/* Error display */}
            {error && (
              <div className="mt-4 space-y-3">
                <div className="border border-neon-red/30 bg-neon-red/5 rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-neon-red font-bold text-xs">
                      ✖ AUDIT FAILED
                    </span>
                  </div>
                  <p className="text-sm text-neon-red/90">{error.error}</p>
                  {error.hint && (
                    <p className="text-xs text-text-muted italic">
                      Hint: {error.hint}
                    </p>
                  )}
                </div>
                <button
                  id="clear-workspace-err-btn"
                  onClick={resetWorkspace}
                  className="text-xs font-semibold uppercase tracking-widest px-4 py-2 rounded-lg border border-neon-red/30 text-neon-red/70 hover:bg-neon-red/10 hover:text-neon-red transition-all cursor-pointer"
                >
                  ✕ Clear Workspace
                </button>
              </div>
            )}

            {/* Success: audit result */}
            {result && (
              <div className="mt-4 space-y-5">
                {/* Meta header */}
                <div className="border border-border-dim rounded-lg overflow-hidden">
                  <div className="bg-surface-2/80 px-4 py-2 border-b border-border-dim">
                    <span className="text-[10px] font-bold tracking-widest uppercase text-neon-cyan">
                      Audit Target
                    </span>
                  </div>
                  <div className="px-4 py-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div>
                      <span className="text-text-muted block mb-0.5">
                        Repository
                      </span>
                      <span className="text-foreground font-medium">
                        {result.repo}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">
                        File
                      </span>
                      <span className="text-foreground font-medium break-all">
                        {result.file}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">
                        Culprit
                      </span>
                      <span className="text-neon-red font-bold">
                        {result.culprit}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Verdict */}
                <div className="border border-neon-green/20 rounded-lg overflow-hidden">
                  <div className="bg-neon-green/5 px-4 py-2 border-b border-neon-green/20 flex items-center justify-between flex-wrap gap-2">
                    <span className="text-[10px] font-bold tracking-widest uppercase text-neon-green">
                      ◆ Final Verdict
                    </span>
                    <div className="flex items-center gap-2">
                      {/* Severity badge */}
                      {(() => {
                        const s = severityStyle(result.severity);
                        return (
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-widest ring-1 ${s.bg} ${s.text} ${s.ring} ${s.pulse ? "animate-pulse" : ""}`}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${s.pulse ? "bg-red-400" : "bg-current"}`} />
                            {result.severity}
                          </span>
                        );
                      })()}
                      {/* Confidence score */}
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-widest ring-1 bg-surface-2 text-neon-cyan ring-neon-cyan/20">
                        ◎ {(result.confidence_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                  <div className="px-4 py-3">
                    <p className="text-sm text-foreground/90 leading-relaxed">
                      {result.verdict}
                    </p>
                  </div>
                </div>

                {/* Side-by-side diff: original vs optimized */}
                <div className="border border-border-dim rounded-lg overflow-hidden">
                  <div className="bg-surface-2/80 px-4 py-2 border-b border-border-dim flex items-center justify-between">
                    <span className="text-[10px] font-bold tracking-widest uppercase text-neon-cyan">
                      Code Diff — Original vs Optimized
                    </span>
                    <button
                      id="copy-code-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(result.optimized_code);
                      }}
                      className="text-[10px] text-text-muted hover:text-neon-cyan transition-colors uppercase tracking-wider cursor-pointer"
                    >
                      Copy Optimized
                    </button>
                  </div>
                  <div className="overflow-x-auto overflow-y-auto max-h-[700px]">
                    <ReactDiffViewer
                      oldValue={result.original_code}
                      newValue={result.optimized_code}
                      splitView={true}
                      useDarkTheme={true}
                      leftTitle="Original Code"
                      rightTitle="Optimized Code"
                      styles={{
                        variables: {
                          dark: {
                            diffViewerBackground: "#0a0f1a",
                            gutterBackground: "#111827",
                            addedBackground: "#12261e",
                            addedGutterBackground: "#0d3321",
                            removedBackground: "#2a1215",
                            removedGutterBackground: "#3b1219",
                            wordAddedBackground: "#1a4d2e",
                            wordRemovedBackground: "#4d1a1f",
                            addedGutterColor: "#39ff14",
                            removedGutterColor: "#ff3b3b",
                            gutterColor: "#64748b",
                            codeFoldGutterBackground: "#111827",
                            codeFoldBackground: "#0a0f1a",
                            emptyLineBackground: "#0a0f1a",
                          },
                        },
                        contentText: {
                          fontFamily: "var(--font-geist-mono), ui-monospace, SFMono-Regular, monospace",
                          fontSize: "12px",
                          lineHeight: "1.6",
                        },
                        titleBlock: {
                          fontFamily: "var(--font-geist-mono), ui-monospace, monospace",
                          fontSize: "10px",
                          fontWeight: 700,
                          letterSpacing: "0.1em",
                          textTransform: "uppercase" as const,
                          padding: "8px 12px",
                          background: "#111827",
                          borderBottom: "1px solid #1e293b",
                          color: "#64748b",
                        },
                      }}
                    />
                  </div>
                </div>

                {/* Clear workspace */}
                <button
                  id="clear-workspace-btn"
                  onClick={resetWorkspace}
                  className="text-xs font-semibold uppercase tracking-widest px-4 py-2 rounded-lg border border-border-dim text-text-muted hover:border-neon-cyan/40 hover:text-neon-cyan transition-all cursor-pointer"
                >
                  ↺ Clear Workspace
                </button>
              </div>
            )}
          </div>
        </section>
      </main>

      {/* ── Footer ──────────────────────────────── */}
      <footer className="px-6 py-3 border-t border-border-dim bg-surface-1/40 flex items-center justify-between text-[10px] text-text-muted">
        <span>AegisCode © {new Date().getFullYear()}</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse" />
          System Operational
        </span>
      </footer>
    </div>
  );
}
