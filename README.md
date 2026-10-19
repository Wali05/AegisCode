<div align="center">

<img src="src/app/icon.svg" width="56" height="56" alt="" />

# AegisCode

Security review that argues with itself.

[![CI](https://github.com/Wali05/AegisCode/actions/workflows/ci.yml/badge.svg)](https://github.com/Wali05/AegisCode/actions/workflows/ci.yml)
![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-555)

<img src="docs/screenshots/landing.png" alt="AegisCode home page" width="900" />

</div>

AegisCode is a code security scanner. You give it a GitHub file, a whole repo, or some pasted code, and it tells you what's exploitable, how the attacker's input gets there, and how to fix it.

The first version of this project was basically a prompt: fetch a file, send it to Gemini three times, print whatever came back. It looked impressive in a demo, but the output had made-up line numbers and confident claims about code that didn't exist. So I rewrote it around a simple rule: **the model only gets to argue about evidence the code itself can prove.**

## How it works

There are four stages:

1. **Static analysis.** A real analyser, no AI involved. It parses the code with the TypeScript compiler and tracks untrusted input (`req.query`, `request.json()`, `location.hash`, …) until it hits something dangerous (`db.query`, `exec`, `fetch`, `innerHTML`, …). It follows values through variables, string building, callbacks and calls into other functions in the same file, so a finding comes with the full path, not just a line number. On top of that there are ~120 pattern rules across 12 languages, a secret scanner, a dependency check against OSV.dev, and some complexity and performance checks.
2. **Triage.** A small, transparent scoring model looks at what the analyser found and decides whether it's worth spending LLM calls on the file. Clean files never touch a model. The UI shows every signal and its weight, so you can see why.
3. **The debate (optional).** If a Gemini key is configured, three agents go through the findings:
   - the **Critic** tries to break the code and has to quote the exact lines it's talking about,
   - the **Defender** pushes back on false positives and proposes fixes,
   - the **Judge** rules on each claim and writes a patched version of the file.

   Before the debate starts, every quote the Critic made is checked against the real file. If the code it quoted isn't there, the claim is thrown out. The UI marks those as "hallucination blocked".
4. **Verification.** The Judge's patch gets compiled and re-scanned by the same analyser, so the before/after score is measured rather than taken on trust.

Everything streams to the browser as it happens over server-sent events, so the progress you see is the real pipeline.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/report.png" alt="Report view" /><br/><sub>Report: score, severity mix, and a finding with its source → sink path.</sub></td>
<td width="50%"><img src="docs/screenshots/pipeline.png" alt="Pipeline timings" /><br/><sub>Pipeline: the analyser takes milliseconds, the LLM agents take seconds.</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/debate.png" alt="Debate view" /><br/><sub>Debate view. This screenshot uses the scripted model from the test suite.</sub></td>
<td><img src="docs/screenshots/patch.png" alt="Patch view" /><br/><sub>Patch view, same test data.</sub></td>
</tr>
</table>

## What it catches

- **Injection through data flow** (JS/TS, Python, PHP): SQL and NoSQL injection, command and code injection, SSRF, path traversal, open redirects, DOM and reflected XSS, template injection, prototype pollution, ReDoS, unsafe deserialisation.
- **Dangerous patterns** in JS/TS, Python, Go, Java/Kotlin, PHP, Ruby, C#, Rust, C/C++ and shell, such as disabled TLS checks, weak crypto, `gets()`, `pickle.loads`, `shell=True`, Flask debug mode and wildcard CORS. Every rule maps to a CWE and to the OWASP Top 10 (2025). The full list lives at `/rules` in the app.
- **Leaked secrets:** AWS, GitHub, Stripe, OpenAI, Anthropic, Slack and private keys, plus an entropy check for anything assigned to a variable called `password`, `token`, `apiKey` and so on. Values are masked before they reach the report.
- **Vulnerable dependencies:** npm, PyPI, Go, crates.io, RubyGems and Packagist manifests and lockfiles, checked against OSV.dev, with CVSS scores and the version that fixes each issue.
- **Code health:** O(n²) lookups inside loops, `await` inside loops, caches that never get cleared, React effects that never clean up, and functions that are too complex to review properly.

## Running it

```bash
git clone https://github.com/Wali05/AegisCode.git
cd AegisCode
npm install
cp .env.example .env.local
npm run dev
```

Then open http://localhost:3000. The **Samples** tab has a few deliberately broken files to try, or paste one of these:

- `https://github.com/juice-shop/juice-shop/blob/master/routes/login.ts`
- `https://github.com/OWASP/NodeGoat/blob/master/app/routes/contributions.js`
- `https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/low.php`

All environment variables are optional:

| Variable | What it does |
|---|---|
| `GEMINI_API_KEY` | Turns on the Critic / Defender / Judge debate. Without it you still get the full analysis. |
| `GEMINI_MODEL` | Defaults to `gemini-flash-latest`. |
| `GITHUB_TOKEN` | Raises GitHub's limit from 60 to 5,000 requests an hour and lets you scan private repos (read-only access is enough). |
| `MAX_REPO_FILES` | How many files to scan per repo (default 40). It picks the ones most likely to matter: routes, auth, database code and so on. |
| `RATE_LIMIT_PER_10_MIN` | Audits allowed per IP (default 12). |

## Using it in CI

The analyser doesn't depend on Next.js, so there's a small CLI too:

```bash
npm run scan -- src --sarif aegis.sarif --fail-on high
```

```
CRITICAL SQL injection: HTTP request input → line 34
         login.ts:34  AEG-TAINT-SQL  CWE-89  conf 86%
         L34 HTTP request input → L34 interpolated into string → L34 reaches sql injection sink

aegis 3 files · 187 lines · score 49 (D) · 6 critical · 0 high · 0 medium · 0 low · 0 info · 81 ms
✖ 6 findings at or above high
```

It writes SARIF (which GitHub Code Scanning understands), Markdown or JSON. It exits with code 1 if anything is at or above `--fail-on`. This repo runs it on its own source in [CI](.github/workflows/ci.yml).

If a finding is a false positive, you can silence it with a comment and a reason:

```ts
// aegis-ignore AEG-JS-010 -- md5 is only used as a cache key here
const key = createHash("md5").update(url).digest("hex");
```

The finding is still listed in the report, marked as dismissed, together with the reason you gave.

## Project layout

```
src/
  lib/engine/     the analyser (lexer, taint tracking, rules, secrets, metrics, scoring)
  lib/swarm/      Gemini provider, response schemas, quote checking, the three agents
  lib/deps/       manifest parsing, OSV client, CVSS calculation
  lib/github.ts   URL parsing, branch resolution, picking which repo files to scan
  lib/pipeline.ts runs everything in order and emits progress events
  app/api/audit   streaming endpoint (validated input, rate limited, cached)
  components/     the UI
  cli/            the `aegis scan` command
tests/            vitest
```

## A few decisions worth explaining

- **Why not just use the LLM?** Models are good at judgement calls ("is this endpoint supposed to be public?") and bad at bookkeeping ("which variable did this value come from three functions ago?"). The analyser does the bookkeeping, and the models only weigh in on what it found.
- **Structured output everywhere.** Each agent's response has to match a schema (built with zod). If it doesn't, the model gets one chance to fix it before the run fails.
- **Scoring.** A file's score drops faster for a critical than for a pile of minor issues. Any open critical caps it at 59, any open high at 79. A repo's score is a weighted average of its files, so large repos aren't penalised just for being large.
- **Safety of the tool itself.** It sends a strict CSP and other security headers, validates every input, never fetches a URL the user picked (only GitHub and OSV), escapes code before rendering it, and masks secrets before they leave the analyser.

## Limitations

- Data flow tracking stays inside a single file; it doesn't follow imports.
- It doesn't understand guard checks, so `if (!ALLOWED.has(host)) return` won't clear a finding. This is why findings carry a confidence value.
- Python and PHP get a simpler line-by-line analysis instead of a full parser.
- The cache and rate limiter live in memory, which is fine for one server but would need Redis behind a load balancer.

## Scripts

```bash
npm run dev        # dev server
npm test           # test suite
npm run check      # lint + typecheck + tests
npm run build      # production build
npm run scan -- .  # CLI
```

## License

MIT
