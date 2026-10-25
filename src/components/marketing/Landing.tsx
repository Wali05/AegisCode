import Link from "next/link";
import { ArrowRight, Ban, Bot, Check, GitBranch, GitCommitHorizontal, KeyRound, PackageSearch, Scale, Target, Terminal, Wand2, Workflow, X } from "lucide-react";
import { catalogStats } from "@/lib/catalog";
import bench from "@/lib/bench-summary.json";

export function Hero() {
  return (
    <div className="text-center">
      <Link href="/agents" className="inline-flex animate-fade-up items-center gap-2 rounded-full border border-line-strong bg-s1/80 py-1 pr-3 pl-1 text-[12px] text-fg-2 backdrop-blur hover:text-fg">
        <span className="rounded-full bg-accent px-2 py-0.5 font-medium text-accent-ink">New</span>
        MCP server for Claude Code, Cursor and Codex
        <ArrowRight className="size-3" />
      </Link>
      <h1 className="mt-6 animate-fade-up text-[clamp(2.4rem,6.4vw,4.6rem)] leading-[1.02] font-semibold tracking-[-0.035em] text-balance [animation-delay:60ms]">
        <span className="text-gradient">Security checks for code</span>{" "}
        <span className="font-serif font-normal tracking-[-0.01em] text-accent italic">your AI wrote.</span>
      </h1>
      <p className="mx-auto mt-5 max-w-2xl animate-fade-up text-[16px] leading-relaxed text-pretty text-fg-2 [animation-delay:90ms] sm:text-[17px]">
        Coding agents ship fast and repeat the same mistakes: SQL built from strings, request data in shell commands, imports of packages that don&apos;t exist. AegisCode traces untrusted input
        across your files, checks every package against the real registry, and writes fixes it re-verifies before you see them.
      </p>
    </div>
  );
}

const SURFACES = [
  {
    Icon: Bot,
    title: "Inside your coding agent",
    body: "An MCP server the agent calls on its own changes before committing. It gets back each issue, the data-flow path and a verified fix it can apply.",
    code: "claude mcp add aegiscode -- node ~/aegiscode/bin/aegis.mjs mcp",
  },
  {
    Icon: GitCommitHorizontal,
    title: "Before every commit",
    body: "A pre-commit hook that scans only what's staged and blocks only issues the commit introduces, so years of existing debt never get in the way.",
    code: "node bin/aegis.mjs hook install",
  },
  {
    Icon: Terminal,
    title: "In CI and right here",
    body: "SARIF for GitHub Code Scanning, a --fail-on gate, Markdown for PR descriptions, and this web app for pasting a file or a whole repository.",
    code: "aegis scan . --sarif aegis.sarif --fail-on high",
  },
];

const STEPS = [
  { n: "01", title: "Read the change", body: "A file, a repo, your staged changes or everything since main. Local modules the change imports are pulled in for context.", Icon: GitBranch },
  { n: "02", title: "Trace across files", body: "Taint analysis on the TypeScript compiler AST follows untrusted input through helpers, imports and re-exports, and knows when a check makes it safe.", Icon: Workflow },
  { n: "03", title: "Check every package", body: "Each import is looked up on npm or PyPI: names that don't exist, lookalikes of popular packages, brand-new releases, install scripts.", Icon: PackageSearch },
  { n: "04", title: "Fix and re-verify", body: "Common issues get a written fix. It only counts as verified if a re-scan shows the issue gone and nothing new.", Icon: Wand2 },
  { n: "05", title: "Optional AI review", body: "With a Gemini key, a Critic, Defender and Judge argue over the evidence. Claims that quote code that isn't there are thrown out.", Icon: Scale },
];

export function Landing() {
  const stats = catalogStats();
  return (
    <>
      <section className="mx-auto w-full max-w-7xl px-4 pb-8 sm:px-6">
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-line bg-line sm:grid-cols-4">
          {[
            { k: `${bench.precision}% / ${bench.recall}%`, v: `precision / recall on ${bench.cases} labelled cases` },
            { k: `${stats.rules}`, v: `rules across ${stats.cwes} CWEs` },
            { k: `${stats.languages}`, v: "languages" },
            { k: "0", v: "API keys needed for the core checks" },
          ].map((s) => (
            <div key={s.v} className="bg-s1 px-5 py-5">
              <dt className="font-mono text-2xl tracking-tight text-fg tabular-nums sm:text-3xl">{s.k}</dt>
              <dd className="mt-1 text-[12.5px] text-fg-3">{s.v}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-2 text-right text-[11.5px] text-fg-3">
          Benchmark is hand-written; the first run on unseen cases scored {bench.holdoutFirstRun.precision}% / {bench.holdoutFirstRun.recall}%.{" "}
          <a className="underline decoration-line-strong underline-offset-2 hover:text-fg-2" href="https://github.com/Wali05/AegisCode/blob/main/bench/RESULTS.md">
            Details
          </a>
        </p>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 py-16 sm:px-6">
        <div className="max-w-3xl">
          <div className="font-mono text-[11px] tracking-[0.14em] text-accent uppercase">Where it runs</div>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Catch it where the code is written, <span className="font-serif font-normal text-fg-2 italic">not after it ships.</span>
          </h2>
        </div>
        <div className="mt-10 grid gap-3 md:grid-cols-3">
          {SURFACES.map((s) => (
            <div key={s.title} className="panel flex min-w-0 flex-col p-6">
              <div className="flex size-8 items-center justify-center rounded-lg border border-line-strong bg-s2 text-accent">
                <s.Icon className="size-4" />
              </div>
              <h3 className="mt-5 text-[16px] font-medium">{s.title}</h3>
              <p className="mt-2 text-[13.5px] leading-relaxed text-fg-2">{s.body}</p>
              <code className="mt-5 block overflow-x-auto rounded-lg border border-line bg-bg/60 px-3 py-2 font-mono text-[11.5px] whitespace-nowrap text-fg-2">
                <span className="text-fg-3">$ </span>
                {s.code}
              </code>
            </div>
          ))}
        </div>
        <Link href="/agents" className="mt-4 inline-flex items-center gap-1.5 text-[13px] text-fg-2 hover:text-fg">
          Setup for Claude Code, Cursor, Codex and CI <ArrowRight className="size-3.5" />
        </Link>
      </section>

      <section id="how" className="mx-auto w-full max-w-7xl scroll-mt-20 px-4 py-16 sm:px-6">
        <div className="max-w-3xl">
          <div className="font-mono text-[11px] tracking-[0.14em] text-accent uppercase">How it works</div>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Deterministic first. <span className="font-serif font-normal text-fg-2 italic">AI second.</span> Evidence always.
          </h2>
          <p className="mt-4 text-[15px] leading-relaxed text-fg-2">
            Models are good at judgement and bad at bookkeeping. So the bookkeeping (which value came from where, what a fix changes) is done by an analyser, and a model is only asked to weigh in on
            evidence that can be checked.
          </p>
        </div>
        <ol className="mt-12 grid gap-3 md:grid-cols-5">
          {STEPS.map((s, i) => (
            <li key={s.n} className="panel relative p-5">
              <div className="flex items-center justify-between">
                <s.Icon className="size-5 text-accent" />
                <span className="font-mono text-[11px] text-fg-3">{s.n}</span>
              </div>
              <h3 className="mt-6 text-[15px] font-medium">{s.title}</h3>
              <p className="mt-2 text-[13px] leading-relaxed text-fg-2">{s.body}</p>
              {i < STEPS.length - 1 && <span className="absolute top-1/2 -right-2 z-10 hidden size-4 -translate-y-1/2 rotate-45 border-t border-r border-line-strong bg-bg md:block" aria-hidden />}
            </li>
          ))}
        </ol>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 pb-20 sm:px-6">
        <div className="grid auto-rows-[minmax(15rem,auto)] gap-3 md:grid-cols-6">
          <Bento className="md:col-span-4" icon={<Workflow className="size-4" />} title="Follows data across files" body="A route in one file passes request data to a helper in another, which builds SQL. AegisCode reports it at the real sink with every hop, and stays quiet when an allowlist or validation check is in the way.">
            <TraceDemo />
          </Bento>
          <Bento className="md:col-span-2" icon={<PackageSearch className="size-4" />} title="Packages AI made up" body="Assistants invent plausible package names; attackers register them. Every import is checked against the live npm / PyPI registry.">
            <div className="mt-5 space-y-1.5 font-mono text-[11.5px]">
              <div className="text-fg-2">
                <span className="text-sev-high">✕</span> pdf-invoice-parser-pro <span className="text-fg-3">· not on npm</span>
              </div>
              <div className="text-fg-2">
                <span className="text-sev-high">✕</span> lodahs <span className="text-fg-3">· looks like lodash</span>
              </div>
              <div className="text-fg-2">
                <span className="text-accent">✓</span> express <span className="text-fg-3">· well known</span>
              </div>
            </div>
          </Bento>
          <Bento className="md:col-span-3" icon={<Wand2 className="size-4" />} title="Fixes that check themselves" body="String-built SQL becomes a parameterised query, innerHTML becomes textContent, redirects are limited to this site. Each edit is re-scanned before it's offered, and aegis scan --fix applies only the verified ones.">
            <div className="mt-5 overflow-x-auto rounded-lg border border-line bg-bg/60 py-1.5 font-mono text-[11.5px] whitespace-nowrap">
              <div className="bg-sev-critical/[0.07] px-3 text-fg-2">
                <span className="text-sev-critical">− </span>pool.query(&quot;SELECT * FROM users WHERE name = &apos;&quot; + req.query.name + &quot;&apos;&quot;)
              </div>
              <div className="bg-accent/[0.07] px-3 text-fg">
                <span className="text-accent">+ </span>pool.query(&quot;SELECT * FROM users WHERE name = $1&quot;, [req.query.name])
              </div>
            </div>
            <div className="mt-2 text-[11.5px] text-accent">✓ Re-scanned: issue gone, nothing new introduced</div>
          </Bento>
          <Bento className="md:col-span-3" icon={<Target className="size-4" />} title="New issues only" body="Scans of staged changes, a branch or a baseline file report what the change adds and what it fixes, matched by content rather than line numbers. That's what makes it usable as a gate on an agent's work.">
            <div className="mt-5 font-mono text-[11.5px] text-fg-2">
              <span className="text-accent">aegis</span> 3 changed files · <span className="text-fg">1 new</span> · <span className="text-accent">2 fixed</span> · 14 pre-existing
            </div>
          </Bento>
          <Bento className="md:col-span-2" icon={<Ban className="size-4" />} title="Hallucination firewall" body="In the optional AI review, every claim must quote code that exists at the cited lines, or it's dropped before the debate starts." />
          <Bento className="md:col-span-2" icon={<KeyRound className="size-4" />} title="Secrets, redacted" body="Provider key formats plus entropy scoring. Values are masked inside the analyser, so reports are safe to share." />
          <Bento className="md:col-span-2" icon={<Check className="size-4" />} title="Measured, not claimed" body={`${bench.cases} labelled cases (${bench.vulnerable} vulnerable, ${bench.cases - bench.vulnerable} safe look-alikes) run in CI. A drop below 95% precision or recall fails the build.`} />
        </div>
      </section>

      <section className="mx-auto w-full max-w-5xl px-4 pb-24 sm:px-6">
        <h2 className="text-center text-3xl font-semibold tracking-tight">
          Not another <span className="font-serif font-normal text-fg-2 italic">“ask a chatbot to review it”</span>
        </h2>
        <div className="panel mt-10 overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-[13.5px]">
            <thead className="border-b border-line text-[12px] text-fg-3">
              <tr>
                <th className="px-5 py-3 font-normal" />
                <th className="px-5 py-3 font-normal">AI code review</th>
                <th className="px-5 py-3 font-medium text-accent">AegisCode</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {[
                ["Works with no API key", false],
                ["Same result every run", false],
                ["Line-accurate data-flow paths across files", false],
                ["Checks imported packages actually exist", false],
                ["Fixes re-verified before they're offered", false],
                ["Blocks only what a change introduces", false],
                ["Callable by coding agents over MCP", false],
                ["Published, reproducible accuracy numbers", false],
              ].map(([label]) => (
                <tr key={label as string}>
                  <td className="px-5 py-3 text-fg-2">{label}</td>
                  <td className="px-5 py-3">
                    <X className="size-4 text-fg-3" aria-label="usually not" />
                  </td>
                  <td className="px-5 py-3">
                    <Check className="size-4 text-accent" aria-label="yes" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function Bento({ className, icon, title, body, children }: { className?: string; icon: React.ReactNode; title: string; body: string; children?: React.ReactNode }) {
  return (
    <div className={`panel flex min-w-0 flex-col p-6 ${className ?? ""}`}>
      <div className="flex size-8 items-center justify-center rounded-lg border border-line-strong bg-s2 text-accent">{icon}</div>
      <h3 className="mt-5 text-[16px] font-medium">{title}</h3>
      <p className="mt-2 max-w-xl text-[13.5px] leading-relaxed text-fg-2">{body}</p>
      {children && <div className="mt-auto">{children}</div>}
    </div>
  );
}

function TraceDemo() {
  const steps = [
    { k: "S", at: "routes/orders.ts:4", label: "HTTP request input", code: "req.query.customer", cls: "border-sev-high text-sev-high" },
    { k: "↓", at: "routes/orders.ts:4", label: "passed to findOrders()", code: "findOrders(req.query.customer)", cls: "border-fg-3 text-fg-3" },
    { k: "↓", at: "db/orders.ts:3", label: "concatenated into string", code: `"… WHERE customer = '" + id + "'"`, cls: "border-fg-3 text-fg-3" },
    { k: "!", at: "db/orders.ts:3", label: "reaches SQL injection sink", code: "pool.query(…)", cls: "border-sev-critical text-sev-critical" },
  ];
  return (
    <ol className="mt-6 grid gap-2 sm:grid-cols-4">
      {steps.map((s) => (
        <li key={s.label} className="min-w-0 rounded-xl border border-line bg-bg/60 p-3">
          <div className="flex items-center gap-2">
            <span className={`flex size-5 items-center justify-center rounded-full border-2 text-[9px] font-bold ${s.cls}`}>{s.k}</span>
            <span className="truncate font-mono text-[11px] text-fg-3">{s.at}</span>
          </div>
          <div className="mt-2 text-[12px] text-fg">{s.label}</div>
          <code className="mt-1 block truncate font-mono text-[11px] text-fg-2">{s.code}</code>
        </li>
      ))}
    </ol>
  );
}
