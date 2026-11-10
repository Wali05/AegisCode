# BUILD_STATUS — 2026-11-10 (v2.1.0)

## What this pass shipped

An accuracy and robustness pass, driven by two new rounds of test cases that were run before anything was changed.

**Analyser (JS/TS)**

- Control flow is joined instead of applied in program order: `if`/`else`, `switch` (with fall-through), `try`/`catch`/`finally` and loops. Loop bodies run twice so a value assigned late in one iteration is seen early in the next.
- Sanitisers are context-aware (`src/lib/engine/taint/model.ts`, `SANITIZERS`): an HTML escaper clears a value for HTML sinks only, `path.basename` for paths only, and so on. Decoding undoes it.
- Object literals are tracked per field, including destructuring and later writes to a field. `map` / `reduce` use what the callback returns.
- Sources: NestJS parameter decorators (validating pipes respected), Server Actions, Hono body helpers, GraphQL resolver arguments, and requests recognised by type or position rather than only by the name `req`.
- Sinks: `spawn("sh", ["-c", x])` and `{ shell: true }`, MongoDB `$where`, query-builder `.where()` strings, `Location` headers, and `promisify(exec)` / renamed imports.
- Guards: Zod schemas, literal `case` clauses, `postMessage` origin checks, calls that never return (`notFound()`), short-circuit `&&` / `||`. Regex guards must anchor every alternative.
- Calls into the project's own classes resolve through declared types, in the same file and across files (`ProjectIndex` publishes `Class.method` summaries).

**Analyser (Python / PHP)**: multi-line calls are read as one statement, Python locals stay inside their function, Flask / FastAPI route parameters are sources, PHP `<?= ?>` is an echo sink.

**Fixes**: the SQL fixer only binds an expression where a single value can go. Before, it would rewrite `"… FROM posts " + where + " ORDER BY x " + dir` into `"… posts ? ORDER BY x ?", [where, dir]` and mark it verified.

**CLI / MCP**

- Change scans follow renames (a renamed file's existing issues were all reported as new) and read paths with `-z` (non-ASCII file names were silently skipped).
- Dangling symlinks and link loops no longer abort a scan.
- MCP `scan_paths` checks the real path, so a symlink inside the project can't be used to read outside it.

**Web app**: rate limiter evicts least-recently-used clients instead of clearing all buckets; malformed `RATE_LIMIT_PER_10_MIN` / `MAX_REPO_FILES` fall back to defaults; clearer validation and GitHub rate-limit messages.

**Dependencies**: Next.js 16.2.3 → 16.4.6. `npm audit` went from 17 advisories (1 critical, 5 high) to 8 moderate, all one `minimatch` issue inside the ESLint toolchain (dev only; the fix is a breaking downgrade of `eslint-config-next`).

## Verification (cloud container, Node 22)

```text
npm run lint        → clean
npm run typecheck   → next typegen + tsc --noEmit OK
npm test            → 12 files, 147 tests passed
npm run bench       → 202 cases, precision 100% / recall 100%
npm run build       → next build OK (9 routes)
npm run smoke:mcp   → 5 tools; scan_code found [MEDIUM] Open redirect
node bin/aegis.mjs scan src --no-deps --fail-on high → exit 0 (score 95, 0 critical, 0 high)
```

First-run scores of the new rounds, before their misses were fixed (see `bench/RESULTS.md`):

```text
round 2 (67 cases)  precision 82.9%  recall 61.7%   against the v2.0.0 engine
round 3 (48 cases)  precision 91.3%  recall 77.8%   against the rewritten engine
```

Old engine vs new on real repositories (taint findings, matched by rule + file + line):

```text
OWASP Juice Shop   44 → 46   +2 NoSQL injection via $where (routes/showProductReviews.ts, routes/trackOrder.ts)
OWASP NodeGoat      5 →  5   no change
DVWA               55 → 54   -1 (login.php:47, a query whose inputs are escaped with mysqli_real_escape_string)
Express             8 →  6   -3 redirects to a fixed "/user/" prefix, +1 res.location() in a test
```

The web app was driven in a headless browser at 1440×900 and at phone size: no console errors, no horizontal overflow, and a pasted snippet audits end to end.

## Not verified here

- Repository scans through the web app: the GitHub API was rate-limited in this container, so only the pasted-code path was exercised end to end. The GitHub client itself is covered by the mocked tests.
- The AI review (no `GEMINI_API_KEY` here); it is covered by the scripted-model tests.
- CI on GitHub: the workflow runs on pushes to `main` and on pull requests, and this work is on a branch without one.
- `debate.png` and `patch.png` in `docs/screenshots` are from the previous pass.

## Known limits

- Class resolution needs declared types (`new C()`, `: C`, constructor parameter properties). Untyped JS that passes services around isn't followed.
- Schema support is Zod only.
- Unrecognised sanitiser names (`sanitize(x)`, `clean(x)`) still clear a value for every sink.
- Python and PHP analysis stays inside one file.
- The benchmark is hand-written; the first-run column is the estimate for unseen code.
