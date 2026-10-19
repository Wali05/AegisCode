import { Ban, Bot, Check, FileJson, Gauge, GitBranch, KeyRound, Package, Scale, Shield, Swords, Workflow, X } from "lucide-react";
import { catalogStats } from "@/lib/catalog";

export function Hero() {
  return (
    <div className="text-center">
      <a href="#how" className="inline-flex animate-fade-up items-center gap-2 rounded-full border border-line-strong bg-s1/80 py-1 pr-3 pl-1 text-[12px] text-fg-2 backdrop-blur hover:text-fg">
        <span className="rounded-full bg-accent px-2 py-0.5 font-medium text-accent-ink">v2</span>
        AST taint engine × adversarial LLM swarm
      </a>
      <h1 className="mt-6 animate-fade-up text-[clamp(2.4rem,6.4vw,4.6rem)] leading-[1.02] font-semibold tracking-[-0.035em] text-balance [animation-delay:60ms]">
        <span className="text-gradient">Security review that</span>{" "}
        <span className="font-serif font-normal tracking-[-0.01em] text-accent italic">argues with itself.</span>
      </h1>
      <p className="mx-auto mt-5 max-w-2xl animate-fade-up text-[16px] leading-relaxed text-pretty text-fg-2 [animation-delay:90ms] sm:text-[17px]">
        AegisCode traces untrusted input through your code with a real taint-analysis engine, then makes three AI agents
        debate every finding. Any claim that can&apos;t quote your source is thrown out. Every patch is re-scanned before you see it.
      </p>
    </div>
  );
}

const STEPS = [
  { n: "01", title: "Ingest", body: "Single files, whole repos (ranked by attack surface) or pasted code. Branches with slashes, private repos, rate-limit aware.", Icon: GitBranch },
  { n: "02", title: "Deterministic engine", body: "TypeScript-compiler AST taint tracking with interprocedural function summaries, 80+ CWE-mapped rules, entropy secret scan, OSV advisories.", Icon: Workflow },
  { n: "03", title: "Risk gate", body: "An explainable logistic model decides if the file is worth LLM time. Clean code never touches a model.", Icon: Gauge },
  { n: "04", title: "Adversarial swarm", body: "Critic attacks, Defender rebuts, Judge rules. Every claim must quote verbatim code — hallucinations are dropped before debate.", Icon: Scale },
  { n: "05", title: "Verified patch", body: "The Judge's fix is compiled and re-scanned by the same engine. You see the score delta, not a promise.", Icon: Check },
];

export function Landing() {
  const stats = catalogStats();
  return (
    <>
      <section className="mx-auto w-full max-w-7xl px-4 pb-8 sm:px-6">
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-line bg-line sm:grid-cols-4">
          {[
            { k: `${stats.rules}`, v: "detection rules" },
            { k: `${stats.cwes}`, v: "distinct CWEs" },
            { k: `${stats.languages}`, v: "languages" },
            { k: "0", v: "LLM calls on clean code" },
          ].map((s) => (
            <div key={s.v} className="bg-s1 px-5 py-5">
              <dt className="font-mono text-2xl tracking-tight text-fg tabular-nums sm:text-3xl">{s.k}</dt>
              <dd className="mt-1 text-[12.5px] text-fg-3">{s.v}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section id="how" className="mx-auto w-full max-w-7xl scroll-mt-20 px-4 py-20 sm:px-6">
        <div className="max-w-3xl">
          <div className="font-mono text-[11px] tracking-[0.14em] text-accent uppercase">How it works</div>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Deterministic first. <span className="font-serif font-normal text-fg-2 italic">AI second.</span> Evidence always.
          </h2>
          <p className="mt-4 text-[15px] leading-relaxed text-fg-2">
            LLMs are great at judgement and terrible at bookkeeping. So AegisCode does the bookkeeping with a compiler-grade engine and only asks
            models to argue about evidence it can verify.
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
          <Bento className="md:col-span-4" icon={<Workflow className="size-4" />} title="Real source → sink taint tracking" body="Not regex. A scope-aware walk over the TypeScript compiler AST follows data through assignments, destructuring, template literals, callbacks and local function calls — with sanitizers that actually break the chain.">
            <TraceDemo />
          </Bento>
          <Bento className="md:col-span-2" icon={<Ban className="size-4" />} title="Hallucination firewall" body="Each Critic claim must quote code that exists at the cited lines. Fabricated evidence is rejected before the debate even starts.">
            <div className="mt-5 space-y-2 font-mono text-[11.5px]">
              <div className="rounded-lg border border-line bg-bg/60 px-3 py-2 text-fg-2">
                <span className="text-critic">C3</span> “<span className="line-through decoration-sev-medium">db.raw(userInput)</span>” — L88
              </div>
              <div className="flex items-center gap-1.5 text-sev-medium">
                <Ban className="size-3" /> evidence not found in file · dismissed
              </div>
            </div>
          </Bento>
          <Bento className="md:col-span-2" icon={<Swords className="size-4" />} title="Critic · Defender · Judge" body="Three schema-constrained agents with opposing incentives. The Judge can overrule the static engine too — false positives get dismissed with a written rationale.">
            <div className="mt-5 flex gap-2">
              <AgentPill Icon={Swords} label="Critic" cls="text-critic border-critic/30 bg-critic/10" />
              <AgentPill Icon={Shield} label="Defender" cls="text-defender border-defender/30 bg-defender/10" />
              <AgentPill Icon={Scale} label="Judge" cls="text-judge border-judge/30 bg-judge/10" />
            </div>
          </Bento>
          <Bento className="md:col-span-2" icon={<Check className="size-4" />} title="Patches that prove themselves" body="The Judge's patched file is parsed by the TypeScript compiler and re-scanned by the engine, so the score delta is measured — not claimed.">
            <div className="mt-5 flex items-baseline gap-3 font-mono">
              <span className="text-3xl text-sev-critical">28</span>
              <span className="text-fg-3">→</span>
              <span className="text-3xl text-accent">94</span>
              <span className="text-[11.5px] text-fg-3">example · 7 resolved · 0 introduced</span>
            </div>
          </Bento>
          <Bento className="md:col-span-2" icon={<Package className="size-4" />} title="Supply-chain intel" body="Lockfiles and manifests for npm, PyPI, Go, crates.io, RubyGems and Packagist are checked against OSV.dev with CVSS 3.1 scoring.">
            <div className="mt-5 font-mono text-[11.5px] text-fg-2">
              lodash@4.17.15 · <span className="text-sev-high">GHSA-35jh-r3h4-6jhm</span> · CVSS 7.2 · fix 4.17.21
            </div>
          </Bento>
          <Bento className="md:col-span-3" icon={<KeyRound className="size-4" />} title="Secrets, redacted at the source" body="Provider-specific signatures (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, PEM keys…) plus Shannon-entropy scoring. Values are redacted inside the engine, so reports are safe to share.">
            <div className="mt-5 rounded-lg border border-line bg-bg/60 px-3 py-2 font-mono text-[11.5px] text-fg-2">
              <span className="text-sev-critical">AEG-SEC-005</span> const stripe = &quot;sk_l••••••••••••Nq&quot; <span className="text-fg-3">· entropy 4.71</span>
            </div>
          </Bento>
          <Bento className="md:col-span-3" icon={<FileJson className="size-4" />} title="Ships where your code ships" body="SARIF 2.1.0 with code flows for GitHub Code Scanning, a CI-ready CLI with --fail-on thresholds, Markdown reports for PRs, and the full JSON report.">
            <div className="mt-5 overflow-x-auto rounded-lg border border-line bg-bg/60 px-3 py-2 font-mono text-[11.5px] whitespace-nowrap text-fg-2">
              <span className="text-fg-3">$</span> node bin/aegis.mjs scan . --sarif aegis.sarif --fail-on high
            </div>
          </Bento>
        </div>
      </section>

      <section className="mx-auto w-full max-w-5xl px-4 pb-24 sm:px-6">
        <h2 className="text-center text-3xl font-semibold tracking-tight">
          Not another <span className="font-serif font-normal text-fg-2 italic">“paste code into a chatbot”</span>
        </h2>
        <div className="panel mt-10 overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-[13.5px]">
            <thead className="border-b border-line text-[12px] text-fg-3">
              <tr>
                <th className="px-5 py-3 font-normal" />
                <th className="px-5 py-3 font-normal">LLM wrapper</th>
                <th className="px-5 py-3 font-medium text-accent">AegisCode</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {[
                ["Works with no API key", false, true],
                ["Line-accurate data-flow traces", false, true],
                ["Rejects fabricated findings", false, true],
                ["Deterministic, reproducible results", false, true],
                ["Explains why the AI was (or wasn't) used", false, true],
                ["Patches verified by re-analysis", false, true],
                ["CVE lookups for dependencies", false, true],
                ["SARIF / CI integration", false, true],
                ["Prompt-injection guardrails for reviewed code", false, true],
              ].map(([label, a, b]) => (
                <tr key={label as string}>
                  <td className="px-5 py-3 text-fg-2">{label}</td>
                  <td className="px-5 py-3">{a ? <Check className="size-4 text-accent" /> : <X className="size-4 text-fg-3" aria-label="no" />}</td>
                  <td className="px-5 py-3">{b ? <Check className="size-4 text-accent" aria-label="yes" /> : <X className="size-4 text-fg-3" />}</td>
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

function AgentPill({ Icon, label, cls }: { Icon: typeof Bot; label: string; cls: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12px] ${cls}`}>
      <Icon className="size-3.5" /> {label}
    </span>
  );
}

function TraceDemo() {
  const steps = [
    { k: "S", line: 34, label: "HTTP request input", code: "const customerId = req.query.customer", cls: "border-sev-high text-sev-high" },
    { k: "↓", line: 35, label: "passed to findOrdersQuery()", code: "db.query(findOrdersQuery(customerId))", cls: "border-fg-3 text-fg-3" },
    { k: "↓", line: 17, label: "concatenated into string", code: `"SELECT … WHERE customer_id = '" + customerId + "'"`, cls: "border-fg-3 text-fg-3" },
    { k: "!", line: 35, label: "reaches SQL injection sink", code: "db.query(…)", cls: "border-sev-critical text-sev-critical" },
  ];
  return (
    <ol className="mt-6 grid gap-2 sm:grid-cols-4">
      {steps.map((s) => (
        <li key={s.label} className="min-w-0 rounded-xl border border-line bg-bg/60 p-3">
          <div className="flex items-center gap-2">
            <span className={`flex size-5 items-center justify-center rounded-full border-2 text-[9px] font-bold ${s.cls}`}>{s.k}</span>
            <span className="font-mono text-[11px] text-fg-3">L{s.line}</span>
          </div>
          <div className="mt-2 text-[12px] text-fg">{s.label}</div>
          <code className="mt-1 block truncate font-mono text-[11px] text-fg-2">{s.code}</code>
        </li>
      ))}
    </ol>
  );
}
