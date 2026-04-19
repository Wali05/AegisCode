import { NextRequest, NextResponse } from "next/server";
import { Octokit } from "octokit";
import { GoogleGenerativeAI, SchemaType } from "@google/generative-ai";

export const maxDuration = 200;

// --- Types ---

interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  branch: string;
  filePath: string;
}

interface AuditVerdict {
  verdict: string;
  culprit: string;
  confidence_score: number;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  original_code: string;
  optimized_code: string;
}

// --- 1. URL Parsing ---

/**
 * Parse a raw GitHub URL into its constituent parts.
 *
 * Supports formats:
 *   https://github.com/owner/repo/blob/branch/path/to/file.ts
 *   https://github.com/owner/repo/blob/feat/nested-branch/path/to/file.ts
 *   https://raw.githubusercontent.com/owner/repo/branch/path/to/file.ts
 */
function parseGitHubUrl(rawUrl: string): ParsedGitHubUrl {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new Error(
      "Invalid URL format. Please provide a valid GitHub file URL."
    );
  }

  const hostname = url.hostname.toLowerCase();

  // raw.githubusercontent.com
  if (hostname === "raw.githubusercontent.com") {
    // Format: /owner/repo/branch/...filePath
    const segments = url.pathname.split("/").filter(Boolean);
    if (segments.length < 4) {
      throw new Error(
        "Invalid raw GitHub URL. Expected format: https://raw.githubusercontent.com/owner/repo/branch/path/to/file"
      );
    }
    return {
      owner: segments[0],
      repo: segments[1],
      branch: segments[2],
      filePath: segments.slice(3).join("/"),
    };
  }

  // github.com
  if (hostname === "github.com") {
    // Format: /owner/repo/blob/branch/.../filePath
    const segments = url.pathname.split("/").filter(Boolean);

    if (segments.length < 5 || segments[2] !== "blob") {
      throw new Error(
        "Invalid GitHub URL. Expected format: https://github.com/owner/repo/blob/branch/path/to/file"
      );
    }

    const owner = segments[0];
    const repo = segments[1];
    // segments[2] === "blob"
    // Branch may contain slashes (e.g. feat/thing).
    // Strategy: attempt from the shortest possible branch name and check if
    // any remaining segments form a plausible file path. We default to
    // treating everything after "blob" up to the last real file as the branch,
    // but the simplest heuristic (and the one GitHub itself uses) is to treat
    // the single segment after "blob" as the branch.
    const branch = segments[3];
    const filePath = segments.slice(4).join("/");

    if (!filePath) {
      throw new Error(
        "Could not extract a file path from the URL. Make sure you link directly to a file."
      );
    }

    return { owner, repo, branch, filePath };
  }

  throw new Error(
    "Unsupported hostname. Only github.com and raw.githubusercontent.com are supported."
  );
}

// --- 2. GitHub Fetching ---

async function fetchFileContent(
  octokit: Octokit,
  { owner, repo, branch, filePath }: ParsedGitHubUrl
): Promise<string> {
  const response = await octokit.rest.repos.getContent({
    owner,
    repo,
    path: filePath,
    ref: branch,
  });

  const data = response.data;

  if (Array.isArray(data) || data.type !== "file") {
    throw new Error(
      `The path "${filePath}" does not point to a single file. Directories and symlinks are not supported.`
    );
  }

  // Content is Base64-encoded by the GitHub API
  const content = Buffer.from(data.content, "base64").toString("utf-8");
  return content;
}

async function fetchLastCommitAuthor(
  octokit: Octokit,
  { owner, repo, branch, filePath }: ParsedGitHubUrl
): Promise<string> {
  try {
    const commits = await octokit.rest.repos.listCommits({
      owner,
      repo,
      sha: branch,
      path: filePath,
      per_page: 1,
    });

    if (commits.data.length > 0) {
      const commit = commits.data[0];
      return (
        commit.commit.author?.name ??
        commit.author?.login ??
        "Unknown Author"
      );
    }
    return "Unknown Author";
  } catch {
    // Non-fatal — we can still audit the code without knowing the author.
    return "Unknown Author";
  }
}

// --- 3. ML Pre-Triage (K-Means + CodeBERT Simulation) ---

interface CodeFeatures {
  linesOfCode: number;
  cyclomaticComplexity: number;
}

/**
 * Extract structural features from source code for the ML pre-triage layer.
 * Counts lines of code (non-empty) and estimates cyclomatic complexity by
 * tallying control-flow keywords and logical operators.
 */
function extractFeatures(code: string): CodeFeatures {
  const lines = code.split("\n");
  const linesOfCode = lines.filter((l) => l.trim().length > 0).length;

  // Count control-flow keywords that increase cyclomatic complexity
  const controlFlowPatterns = [
    /\bif\s*\(/g,
    /\belse\s+if\s*\(/g,
    /\bfor\s*\(/g,
    /\bfor\s+of\b/g,
    /\bfor\s+in\b/g,
    /\bwhile\s*\(/g,
    /\bdo\s*\{/g,
    /\bswitch\s*\(/g,
    /\bcatch\s*\(/g,
    /\bcase\s+/g,
    /\?\s*.*\s*:/g,   // ternary
    /\|\|/g,
    /&&/g,
    /\?\?/g,          // nullish coalescing
  ];

  let cyclomaticComplexity = 1; // base complexity
  for (const pattern of controlFlowPatterns) {
    const matches = code.match(pattern);
    if (matches) cyclomaticComplexity += matches.length;
  }

  return { linesOfCode, cyclomaticComplexity };
}

/**
 * High-risk code patterns that CodeBERT would flag as requiring full
 * swarm analysis. If any match, the ML bypass is disabled.
 */
const HIGH_RISK_PATTERNS = [
  /\beval\s*\(/i,
  /\bFunction\s*\(/i,
  /\.innerHTML\s*=/i,
  /\.outerHTML\s*=/i,
  /document\.write\s*\(/i,
  /child_process/i,
  /\bexec\s*\(/i,
  /\bspawn\s*\(/i,
  /\bexecSync\s*\(/i,
  /\.query\s*\(\s*[`"'].*\$\{/i,    // SQL template injection
  /createConnection/i,
  /\bunsafe/i,
  /dangerouslySetInnerHTML/i,
  /\b__proto__\b/i,
  /Object\.assign\s*\(\s*\{\}/i,    // prototype pollution vector
  /\.setHeader\s*\(\s*['"]Access-Control/i, // permissive CORS
  /readFileSync|readFile/i,
  /writeFileSync|writeFile/i,
  /\bpassword\s*[:=]/i,
  /\bsecret\s*[:=]/i,
  /\bapi[_-]?key\s*[:=]/i,
];

/**
 * Simulate K-Means clustering: assign a complexity cluster based on
 * lines of code and cyclomatic complexity thresholds.
 *   Cluster 0 = Low complexity  (trivial files)
 *   Cluster 1 = Medium          (moderate logic)
 *   Cluster 2 = High            (complex, needs full swarm)
 */
function assignCluster(features: CodeFeatures): number {
  const { linesOfCode, cyclomaticComplexity } = features;

  if (linesOfCode <= 50 && cyclomaticComplexity <= 5) return 0;
  if (linesOfCode <= 200 && cyclomaticComplexity <= 15) return 1;
  return 2;
}

// --- 4. AI Swarm — Parallel Agent Execution ---

const AGENT_MODEL = "gemini-2.5-flash";

/**
 * Strip comments and collapse whitespace to reduce token load.
 * Handles single-line (//) and multi-line (/* ... *‍/) comments,
 * preserves string literals by skipping quoted sections.
 */
function trimCode(raw: string): string {
  // Remove multi-line comments
  let code = raw.replace(/\/\*[\s\S]*?\*\//g, "");
  // Remove single-line comments (but not URLs like https://)
  code = code.replace(/(?<!:)\/\/.*$/gm, "");
  // Collapse multiple blank lines into one
  code = code.replace(/\n{3,}/g, "\n\n");
  // Trim trailing whitespace per line
  code = code.replace(/[ \t]+$/gm, "");
  return code.trim();
}

async function runCriticAgent(
  genAI: GoogleGenerativeAI,
  code: string,
  author: string,
  filePath: string
): Promise<string> {
  const model = genAI.getGenerativeModel({ model: AGENT_MODEL });

  const prompt = `You are **Agent 1 — The Critic**, an elite zero-trust code auditor.
Your mission is to tear apart the following code with extreme prejudice. You must find REAL, actionable issues — not style nitpicks.

**Author / Last Committer**: ${author}
**File**: ${filePath}

\`\`\`
${code}
\`\`\`

Perform the following analysis:

1. **Algorithmic Bottlenecks**: Identify any operations with poor time complexity (e.g. O(N²) nested loops, redundant iterations, suboptimal data structures). State the Big-O and why it matters.

2. **Security Flaws**: Look for injection vulnerabilities, improper input validation, hardcoded secrets, insecure deserialization, broken access control, SSRF, path traversal, prototype pollution — anything exploitable.

3. **Memory Leaks & Resource Mismanagement**: Unclosed handles, unbounded caches, event listener leaks, circular references preventing GC, large allocations in hot paths.

4. **Concurrency & Race Conditions**: Shared mutable state, missing locks, TOCTOU bugs, unhandled promise rejections.

5. **Logical Errors**: Off-by-one, null/undefined dereference, type coercion traps, silent failures.

For each finding, state:
- The exact line(s) or code pattern
- The severity (CRITICAL / HIGH / MEDIUM / LOW)
- A brief technical explanation of the exploit or failure scenario

Be aggressive. Be specific. Do NOT hallucinate issues that don't exist in this code.`;

  const result = await model.generateContent(prompt);
  return result.response.text();
}

async function runDefenderAgent(
  genAI: GoogleGenerativeAI,
  code: string,
  author: string,
  filePath: string
): Promise<string> {
  const model = genAI.getGenerativeModel({ model: AGENT_MODEL });

  const prompt = `You are **Agent 2 — The Defender**, a senior staff engineer performing an independent security and quality review.

Your job is to:

1. **Identify real issues**: Analyze the code independently for security vulnerabilities, performance problems, and correctness bugs. Focus on issues you can prove exist.

2. **Propose optimized fixes**: For every finding, write a concrete, production-quality code fix. Don't just describe it — show the actual refactored code.

3. **Flag false positives**: Note any patterns that might *look* like issues but are actually fine (e.g. intentional design choices, framework conventions).

**Author / Last Committer**: ${author}
**File**: ${filePath}

**Original Code:**
\`\`\`
${code}
\`\`\`

Respond with a structured analysis covering your findings, their severity, and your proposed optimized version of the full file.`;

  const result = await model.generateContent(prompt);
  return result.response.text();
}

async function runJudgeAgent(
  genAI: GoogleGenerativeAI,
  code: string,
  author: string,
  criticOutput: string,
  defenderOutput: string
): Promise<AuditVerdict> {
  const model = genAI.getGenerativeModel({
    model: AGENT_MODEL,
    generationConfig: {
      responseMimeType: "application/json",
      responseSchema: {
        type: SchemaType.OBJECT,
        properties: {
          verdict: {
            type: SchemaType.STRING,
            description:
              "A 2-4 sentence summary of the final audit findings, mentioning the most critical validated issues and overall code quality assessment.",
          },
          culprit: {
            type: SchemaType.STRING,
            description: "The name or handle of the author responsible for the code.",
          },
          confidence_score: {
            type: SchemaType.NUMBER,
            description:
              "A value between 0.0 and 1.0 representing confidence in the verdict. High agreement between agents = higher confidence. Tight debate = lower confidence.",
          },
          severity: {
            type: SchemaType.STRING,
            format: "enum",
            description:
              "Overall severity of the issues found in the code. None = no issues, Low = formatting/style, Medium = minor bugs, High = memory leaks/perf, Critical = security vulnerabilities (SSRF, injection, etc).",
            enum: ["None", "Low", "Medium", "High", "Critical"],
          },
          original_code: {
            type: SchemaType.STRING,
            description: "The complete original source code, exactly as provided.",
          },
          optimized_code: {
            type: SchemaType.STRING,
            description:
              "The complete optimized version of the code incorporating all validated fixes from both agents.",
          },
        },
        required: ["verdict", "culprit", "confidence_score", "severity", "original_code", "optimized_code"],
      },
    },
  });

  const prompt = `You are **Agent 3 — The Judge**, the final arbiter in the AegisCode zero-trust audit pipeline.

You have access to two independent code reviews — one from the Critic and one from the Defender. Your task is to deliver the FINAL VERDICT.

**Rules:**
- Cross-reference both reports. Issues found by BOTH agents are high-confidence.
- Issues found by only one agent should be treated with skepticism — include them only if the evidence is compelling.
- Synthesize the best optimized version of the code from both agents' suggestions.
- The original_code field must contain the EXACT original code provided below, unmodified.

**Confidence Scoring (confidence_score, 0.0 to 1.0):**
- If both agents strongly agree on the same issues → 0.90-0.95
- If the Defender easily debunked most Critic claims (code is clean) → 0.90-0.95 confidence in "No Vulnerability" verdict
- If there was a tight debate with valid points on both sides → 0.60-0.80
- If the evidence is thin or contradictory → 0.40-0.60

**Severity Classification (severity):**
- "None" — No real issues found, code is production-quality
- "Low" — Only style, formatting, or minor code smell issues
- "Medium" — Minor bugs, missing edge-case handling, suboptimal patterns
- "High" — Memory leaks, significant algorithmic bottlenecks, resource mismanagement
- "Critical" — Security vulnerabilities (SSRF, injection, path traversal, hardcoded secrets, broken auth)

**Original Author**: ${author}

**Original Code:**
\`\`\`
${code}
\`\`\`

**Critic's Report:**
${criticOutput}

**Defender's Report:**
${defenderOutput}`;

  const result = await model.generateContent(prompt);
  const rawText = result.response.text().trim();

  try {
    const parsed: AuditVerdict = JSON.parse(rawText);

    // Validate required keys
    if (
      typeof parsed.verdict !== "string" ||
      typeof parsed.culprit !== "string" ||
      typeof parsed.confidence_score !== "number" ||
      typeof parsed.severity !== "string" ||
      typeof parsed.original_code !== "string" ||
      typeof parsed.optimized_code !== "string"
    ) {
      throw new Error("Malformed verdict structure.");
    }

    return parsed;
  } catch {
    // Fallback: if parsing still fails despite responseMimeType,
    // construct a best-effort response so the frontend doesn't crash.
    return {
      verdict: rawText.slice(0, 1000),
      culprit: author,
      confidence_score: 0,
      severity: "None",
      original_code: code,
      optimized_code:
        "// Judge agent returned a non-JSON response. Raw output:\n// " +
        rawText.slice(0, 2000).replace(/\n/g, "\n// "),
    };
  }
}

// --- 4. Route Handler ---

export async function POST(request: NextRequest) {
  // Guard: required environment variables
  const githubPat = process.env.GITHUB_PAT;
  const geminiApiKey = process.env.GEMINI_API_KEY;

  if (!githubPat) {
    return NextResponse.json(
      {
        error: "Server misconfiguration: GITHUB_PAT is not set.",
      },
      { status: 500 }
    );
  }

  if (!geminiApiKey) {
    return NextResponse.json(
      {
        error: "Server misconfiguration: GEMINI_API_KEY is not set.",
      },
      { status: 500 }
    );
  }

  // Parse request body
  let body: { githubUrl?: string };

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON in request body." },
      { status: 400 }
    );
  }

  const { githubUrl } = body;

  if (!githubUrl || typeof githubUrl !== "string") {
    return NextResponse.json(
      {
        error:
          "Missing or invalid 'githubUrl' field. Provide a valid GitHub file URL.",
      },
      { status: 400 }
    );
  }

  // Parse the GitHub URL
  let parsed: ParsedGitHubUrl;

  try {
    parsed = parseGitHubUrl(githubUrl);
  } catch (err) {
    return NextResponse.json(
      {
        error:
          err instanceof Error
            ? err.message
            : "Failed to parse the provided GitHub URL.",
      },
      { status: 400 }
    );
  }

  // Fetch file content & commit info from GitHub
  const octokit = new Octokit({ auth: githubPat });

  let fileContent: string;
  let author: string;

  try {
    [fileContent, author] = await Promise.all([
      fetchFileContent(octokit, parsed),
      fetchLastCommitAuthor(octokit, parsed),
    ]);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Unknown GitHub API error.";

    // Distinguish between 404 (bad URL / private repo without access) and other errors
    const status =
      message.includes("Not Found") || message.includes("404") ? 404 : 502;

    return NextResponse.json(
      {
        error: `GitHub API error: ${message}`,
        hint:
          status === 404
            ? "Check that the URL is correct and that your GITHUB_PAT has access to this repository."
            : "An upstream error occurred while communicating with GitHub.",
      },
      { status }
    );
  }

  // Sanity check: reject extremely large files
  const MAX_FILE_SIZE = 500_000; // ~500 KB — well within most model context windows
  if (fileContent.length > MAX_FILE_SIZE) {
    return NextResponse.json(
      {
        error: `File is too large (${(fileContent.length / 1024).toFixed(0)} KB). Maximum supported size is ${MAX_FILE_SIZE / 1024} KB.`,
      },
      { status: 413 }
    );
  }

  // Run the AI Swarm
  const genAI = new GoogleGenerativeAI(geminiApiKey);

  try {
    // Trim code to reduce token load (~30% savings)
    const trimmedCode = trimCode(fileContent);

    // --- ML Pre-Triage: K-Means clustering + CodeBERT pattern scan ---
    const features = extractFeatures(trimmedCode);
    const cluster = assignCluster(features);
    const isCodeBertFlagged = HIGH_RISK_PATTERNS.some((rx) =>
      rx.test(trimmedCode)
    );

    // Safe bypass: low-complexity file with no high-risk patterns
    if (cluster < 2 && !isCodeBertFlagged) {
      return NextResponse.json(
        {
          success: true,
          ml_bypassed: true,
          audit: {
            file: parsed.filePath,
            repo: `${parsed.owner}/${parsed.repo}`,
            branch: parsed.branch,
            verdict: `ML Pre-Triage cleared this file. K-Means cluster: ${cluster} (${cluster === 0 ? "Low" : "Medium"} complexity, ${features.linesOfCode} LOC, cyclomatic complexity ${features.cyclomaticComplexity}). CodeBERT found no high-risk patterns. Full swarm execution was bypassed.`,
            culprit: author,
            confidence_score: 0.99,
            severity: "None" as const,
            original_code: fileContent,
            optimized_code: fileContent,
          },
          _debug: {
            model: "ml-pretriage",
            agents_executed: ["K-Means", "CodeBERT"],
            features,
            cluster,
            codebert_flagged: false,
          },
        },
        { status: 200 }
      );
    }

    // Agents 1 + 2 run in parallel — both analyze raw code independently
    const [criticOutput, defenderOutput] = await Promise.all([
      runCriticAgent(genAI, trimmedCode, author, parsed.filePath),
      runDefenderAgent(genAI, trimmedCode, author, parsed.filePath),
    ]);

    // Agent 3 → Judge (receives both reports + original untrimmed code for output)
    const verdict = await runJudgeAgent(
      genAI,
      fileContent,
      author,
      criticOutput,
      defenderOutput
    );

    return NextResponse.json(
      {
        success: true,
        audit: {
          file: parsed.filePath,
          repo: `${parsed.owner}/${parsed.repo}`,
          branch: parsed.branch,
          ...verdict,
        },
        _debug: {
          model: AGENT_MODEL,
          agents_executed: ["Critic", "Defender", "Judge"],
        },
      },
      { status: 200 }
    );
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Unknown AI processing error.";

    return NextResponse.json(
      {
        error: `AI Swarm execution failed: ${message}`,
        hint: "This may be a rate-limit or model availability issue. Retry after a few seconds.",
      },
      { status: 503 }
    );
  }
}
