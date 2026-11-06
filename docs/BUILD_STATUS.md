# BUILD_STATUS — 2026-11-06

## What this pass shipped

Npx-ready MCP packaging for AegisCode (Claude Code / Cursor / Codex), without requiring a manual clone + `npm ci` for everyday agent use.

- `scripts/build-cli.mjs` — esbuild bundle of `src/cli` → `dist/cli.mjs` (analyser + MCP only; Next.js / React / LLM swarm stay out of the bundle).
- `bin/aegis.mjs` — Anvil-style thin wrapper: prefers `dist/cli.mjs`, falls back to tsx for local checkouts without a build.
- `prepare` / `npm run build:cli` — builds the CLI on install; `npm run build` remains the Next.js web app.
- `scripts/mcp-smoke.mjs` + `npm run smoke:mcp` — real stdio MCP client (`StdioClientTransport`) against the bin; asserts the five tools and a `scan_code` open-redirect finding.
- README + `/agents` page lead with the npx one-liner; clone path kept for contributors / web app.
- `src/lib/version.ts` — `ENGINE_VERSION` / `RULE_COUNT` extracted so the CLI import graph does not pull `src/lib/swarm`.

Package stays `"private": true` (github installs still work; not publishing to the npm registry).

## Verification (this machine, Asia/Calcutta)

```text
npm run build:cli
  → dist/cli.mjs ~246kb, 15ms

npm run smoke:mcp
  → mcp-smoke ok: 5 tools (check_packages, explain_rule, scan_changes, scan_code, scan_paths);
     scan_code found [MEDIUM] Open redirect

npm test
  → Test Files 11 passed (11)
  → Tests 97 passed (97)

npm run typecheck
  → next typegen + tsc --noEmit OK

npm pack → install into a fresh temp project
  → bin --help works; MCP listTools + scan_code open-redirect OK via the installed package
```

`next build` was not re-run this pass (typecheck covers the TS surface; web `build` script unchanged).

## Working MCP install command

After this commit is on `main` at github.com/Wali05/AegisCode:

```bash
claude mcp add aegiscode -- npx -y -p github:Wali05/AegisCode aegis mcp
```

Verified locally against a packed install of this tree (`npm pack` + install), and against `node bin/aegis.mjs mcp` via `npm run smoke:mcp`. Live `npx … github:Wali05/AegisCode` was not re-hit here because this commit is not pushed yet.

From a clone (also verified):

```bash
node bin/aegis.mjs mcp
```

## Known limits

- Private package: install via `github:Wali05/AegisCode`, not the npm registry.
- First npx run pulls the full dependency tree (including Next.js for the web app) and runs `prepare` to build `dist/cli.mjs`; that can take a minute. Later runs reuse the npm cache.
- On this box, npm's `allowScripts` can block `prepare` / esbuild postinstall; the bin then falls back to tsx when `dist/` is missing. Normal user installs run `prepare`.
- `check_packages` needs network (npm / PyPI). Other MCP tools are local.
- Analyser accuracy limits are unchanged; see README "How accurate is it?".
