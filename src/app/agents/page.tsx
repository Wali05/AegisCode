import type { Metadata } from "next";
import { Footer, Nav, REPO_URL } from "@/components/site";
import { CodeBlock } from "@/components/CodeBlock";

export const metadata: Metadata = {
  title: "Set up for coding agents",
  description: "Connect AegisCode to Claude Code, Cursor or Codex over MCP, add a pre-commit hook, and gate CI on new issues only.",
};

const TOOLS = [
  ["scan_changes", "Scans uncommitted, staged, or since-branch changes and returns only the issues they introduce. The one to call before committing."],
  ["scan_code", "Scans a file's contents before it is written. Includes verified fixes the agent can apply directly."],
  ["check_packages", "Checks package names on npm / PyPI before they're added: nonexistent, lookalike, brand-new, install scripts, deprecated."],
  ["scan_paths", "Scans files or folders (inside the project only), following data flow across them."],
  ["explain_rule", "Explains a rule id such as AEG-TAINT-SQL: what it catches and how to fix it."],
];

const AGENT_NOTE = `## Security checks

Before committing, call the \`scan_changes\` tool from the aegiscode MCP server and fix every
new issue it reports (apply the verified fix when one is given).
Before adding a dependency, call \`check_packages\` with the package names.`;

const EXAMPLE = `AegisCode: 1 changed file(s) — 2 new issue(s), 0 fixed, 3 pre-existing (not shown).
- [CRITICAL] src/db/orders.ts:4 SQL injection: HTTP request input (from src/routes/orders.ts) → line 4 (AEG-TAINT-SQL, CWE-89)
  flow: src/routes/orders.ts:6 HTTP request input → src/routes/orders.ts:6 passed to findOrders() in src/db/orders.ts → L4 concatenated into string → L4 reaches sql injection sink
  verified fix (Use a parameterised query), replace line 4 with:
    return pool.query("SELECT * FROM orders WHERE customer = $1", [customerId]);
- [HIGH] src/routes/orders.ts:2 \`pdf-invoice-parser-pro\` does not exist on npm (AEG-PKG-001)
  fix: Find the real package that provides this functionality and depend on that, or remove the import.`;

export default function AgentsPage() {
  return (
    <>
      <Nav />
      <main className="mx-auto w-full max-w-4xl px-4 pt-14 pb-24 sm:px-6">
        <div className="font-mono text-[11px] tracking-[0.14em] text-accent uppercase">Setup</div>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight">
          Put a checkpoint <span className="font-serif font-normal text-fg-2 italic">in front of your agent.</span>
        </h1>
        <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-fg-2">
          Everything below runs locally from a clone of the repository. Only the package check talks to the network (the npm and PyPI registries). The optional AI review lives in the web app.
        </p>

        <Section title="1. Get the code">
          <CodeBlock code={`git clone ${REPO_URL}.git ~/aegiscode\ncd ~/aegiscode && npm ci`} />
        </Section>

        <Section title="2. Connect your agent over MCP">
          <p>Claude Code:</p>
          <CodeBlock code={`claude mcp add aegiscode -- node ~/aegiscode/bin/aegis.mjs mcp`} />
          <p>Cursor (<code className="font-mono text-fg">.cursor/mcp.json</code> in your project, or the global one):</p>
          <CodeBlock
            label="json"
            code={JSON.stringify({ mcpServers: { aegiscode: { command: "node", args: ["/Users/you/aegiscode/bin/aegis.mjs", "mcp"] } } }, null, 2)}
          />
          <p>Codex (<code className="font-mono text-fg">~/.codex/config.toml</code>):</p>
          <CodeBlock label="toml" code={`[mcp_servers.aegiscode]\ncommand = "node"\nargs = ["/Users/you/aegiscode/bin/aegis.mjs", "mcp"]`} />
          <p>Any other MCP client: run <code className="font-mono text-fg">node bin/aegis.mjs mcp</code> over stdio, from your project folder.</p>
        </Section>

        <Section title="3. Tell the agent to use it">
          <p>
            Add this to your <code className="font-mono text-fg">CLAUDE.md</code>, <code className="font-mono text-fg">AGENTS.md</code> or Cursor rules:
          </p>
          <CodeBlock label="markdown" code={AGENT_NOTE} />
          <div className="panel overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-[13px]">
              <thead className="border-b border-line text-[11.5px] text-fg-3">
                <tr>
                  <th className="px-4 py-2.5 font-normal">Tool</th>
                  <th className="px-4 py-2.5 font-normal">What it does</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {TOOLS.map(([name, desc]) => (
                  <tr key={name} className="align-top">
                    <td className="px-4 py-3 font-mono text-[12.5px] text-fg">{name}</td>
                    <td className="px-4 py-3 text-fg-2">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>What the agent gets back:</p>
          <CodeBlock label="scan_changes" code={EXAMPLE} />
        </Section>

        <Section title="4. Block risky commits">
          <p>The hook scans only staged changes and fails only on issues the commit introduces (high and above by default). Skip it once with <code className="font-mono text-fg">git commit --no-verify</code>.</p>
          <CodeBlock code={`cd your-project\nnode ~/aegiscode/bin/aegis.mjs hook install\n# stricter: AEGIS_FAIL_ON=medium git commit ...`} />
        </Section>

        <Section title="5. Gate pull requests in CI">
          <CodeBlock
            label="yaml"
            code={`- run: |
    git clone --depth 1 ${REPO_URL} .aegis
    npm ci --prefix .aegis --omit=dev --ignore-scripts
- run: node .aegis/bin/aegis.mjs scan --since origin/main --sarif aegis.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with: { sarif_file: aegis.sarif }`}
          />
          <p>
            For a full scan that ignores existing issues, write a baseline once with <code className="font-mono text-fg">--write-baseline aegis-baseline.json</code>, commit it, and run with{" "}
            <code className="font-mono text-fg">--baseline aegis-baseline.json</code>.
          </p>
        </Section>
      </main>
      <Footer />
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-12 space-y-3 text-[14px] leading-relaxed text-fg-2">
      <h2 className="text-xl font-semibold tracking-tight text-fg">{title}</h2>
      {children}
    </section>
  );
}
