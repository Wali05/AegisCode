"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowRight, ClipboardPaste, FlaskConical, Sparkles } from "lucide-react";
import type { AuditRequest } from "@/lib/client/stream";
import { SAMPLES } from "@/lib/samples";
import { Button, GithubIcon, Kbd, Segmented, Tabs, cn } from "../ui";

type Mode = "github" | "paste" | "samples";

const EXAMPLES = [
  { label: "juice-shop · login.ts", url: "https://github.com/juice-shop/juice-shop/blob/master/routes/login.ts" },
  { label: "NodeGoat · contributions.js", url: "https://github.com/OWASP/NodeGoat/blob/master/app/routes/contributions.js" },
  { label: "DVWA · exec/low.php", url: "https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/low.php" },
  { label: "OWASP/NodeGoat (repo)", url: "https://github.com/OWASP/NodeGoat" },
];

export interface Health {
  swarm: { enabled: boolean; model?: string };
  github: { authenticated: boolean };
  engine: { version: string; rules: number };
}

export function useHealth(): Health | null {
  const [health, setHealth] = useState<Health | null>(null);
  useEffect(() => {
    let alive = true;
    fetch("/api/health")
      .then((r) => r.json())
      .then((h) => alive && setHealth(h))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  return health;
}

export function Console({ onRun, health, busy, initialUrl = "" }: { onRun: (req: AuditRequest) => void; health: Health | null; busy: boolean; initialUrl?: string }) {
  const [mode, setMode] = useState<Mode>("github");
  const [url, setUrl] = useState(initialUrl);
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [swarm, setSwarm] = useState<AuditRequest["swarm"]>("auto");
  const [error, setError] = useState<string | null>(null);
  const urlInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        setMode("github");
        requestAnimationFrame(() => urlInput.current?.focus());
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const submit = (e?: FormEvent) => {
    e?.preventDefault();
    setError(null);
    if (busy) return;
    if (mode === "github") {
      const v = url.trim();
      if (!v) return setError("Paste a GitHub file or repository URL.");
      if (!/github\.com|githubusercontent\.com|^[\w.-]+\/[\w.-]+$/.test(v)) return setError("That doesn't look like a GitHub URL.");
      onRun({ url: v, swarm });
    } else if (mode === "paste") {
      if (!code.trim()) return setError("Paste some code first.");
      onRun({ code, filename: filename.trim() || undefined, swarm });
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
  };

  return (
    <div className="panel panel-glow overflow-hidden" onKeyDown={onKeyDown}>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
        <Tabs<Mode>
          value={mode}
          onChange={(m) => {
            setMode(m);
            setError(null);
          }}
          items={[
            { id: "github", label: "GitHub", icon: <GithubIcon className="size-3.5" /> },
            { id: "paste", label: "Paste code", icon: <ClipboardPaste className="size-3.5" /> },
            { id: "samples", label: "Samples", icon: <FlaskConical className="size-3.5" /> },
          ]}
        />
        <div className="flex items-center gap-2">
          <span className="hidden text-[12px] text-fg-3 sm:inline">Swarm</span>
          <Segmented
            label="Adversarial swarm"
            value={swarm}
            onChange={setSwarm}
            options={[
              { id: "auto", label: "Auto", title: "Run the LLM swarm only when the risk model escalates" },
              { id: "force", label: "Always", title: "Always run the LLM swarm" },
              { id: "off", label: "Off", title: "Static engine only" },
            ]}
          />
        </div>
      </div>

      {mode === "samples" ? (
        <div className="grid gap-2 p-3 sm:grid-cols-2">
          {SAMPLES.map((s) => (
            <button
              key={s.id}
              disabled={busy}
              onClick={() => onRun({ code: s.code, filename: s.filename, swarm })}
              className="group rounded-xl border border-line bg-s2/60 p-3.5 text-left transition-colors hover:border-line-strong hover:bg-s2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13.5px] font-medium">{s.label}</span>
                <ArrowRight className="size-3.5 text-fg-3 transition-transform group-hover:translate-x-0.5 group-hover:text-accent" />
              </div>
              <div className="mt-0.5 font-mono text-[11px] text-fg-3">{s.filename}</div>
              <p className="mt-2 text-[12.5px] leading-relaxed text-fg-2">{s.blurb}</p>
            </button>
          ))}
        </div>
      ) : (
        <form onSubmit={submit} className="p-3">
          {mode === "github" ? (
            <div className="flex flex-col gap-2 sm:flex-row">
              <label className="flex h-12 min-w-0 flex-1 items-center gap-2.5 rounded-xl border border-line-strong bg-bg/60 px-3.5 focus-within:border-accent/60 focus-within:ring-4 focus-within:ring-accent/10">
                <GithubIcon className="size-4 shrink-0 text-fg-3" aria-hidden />
                <input
                  ref={urlInput}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="github.com/owner/repo or …/blob/main/file.ts"
                  className="min-w-0 flex-1 bg-transparent font-mono text-[13.5px] placeholder:text-fg-3 focus:outline-none"
                  spellCheck={false}
                  autoComplete="off"
                  aria-label="GitHub URL"
                />
                <Kbd>/</Kbd>
              </label>
              <Button type="submit" variant="primary" className="h-12 px-5" disabled={busy}>
                <Sparkles className="size-4" /> Audit
              </Button>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Paste a file — JS/TS, Python, Go, Java, PHP, Ruby, C#, Rust, C/C++, shell, or a package.json / requirements.txt"
                className="code h-56 w-full resize-y rounded-xl border border-line-strong bg-bg/60 p-3.5 text-fg placeholder:font-sans placeholder:text-fg-3 focus:border-accent/60 focus:ring-4 focus:ring-accent/10 focus:outline-none"
                spellCheck={false}
                aria-label="Source code"
              />
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="filename (optional, e.g. api/users.ts — sets the language)"
                  className="h-11 min-w-0 flex-1 rounded-xl border border-line-strong bg-bg/60 px-3.5 font-mono text-[13px] placeholder:font-sans placeholder:text-fg-3 focus:border-accent/60 focus:outline-none"
                  spellCheck={false}
                  aria-label="Filename"
                />
                <Button type="submit" variant="primary" className="h-11 px-5" disabled={busy}>
                  <Sparkles className="size-4" /> Audit snippet <Kbd>⌘↵</Kbd>
                </Button>
              </div>
            </div>
          )}

          {error && <p className="mt-2 text-[12.5px] text-sev-critical">{error}</p>}

          {mode === "github" && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[12px] text-fg-3">Try</span>
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.url}
                  type="button"
                  onClick={() => setUrl(ex.url)}
                  className={cn("rounded-full border border-line bg-s2/70 px-2.5 py-1 font-mono text-[11.5px] text-fg-2 transition-colors hover:border-line-strong hover:text-fg", url === ex.url && "border-accent/50 text-fg")}
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}
        </form>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line bg-bg/40 px-4 py-2 text-[11.5px] text-fg-3">
        <StatusDot ok label={`Engine v${health?.engine.version ?? "2"} · ${health?.engine.rules ?? "…"} rules`} />
        <StatusDot ok={!!health?.swarm.enabled} label={health ? (health.swarm.enabled ? `Swarm · ${health.swarm.model}` : "Swarm offline · static-only mode") : "Swarm …"} />
        <StatusDot ok={!!health?.github.authenticated} warn label={health?.github.authenticated ? "GitHub · authenticated" : "GitHub · anonymous (60 req/h)"} />
      </div>
    </div>
  );
}

function StatusDot({ ok, warn, label }: { ok: boolean; warn?: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={cn("size-1.5 rounded-full", ok ? "bg-accent" : warn ? "bg-sev-medium" : "bg-fg-3")} />
      {label}
    </span>
  );
}
