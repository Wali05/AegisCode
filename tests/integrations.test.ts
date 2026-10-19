import { afterEach, describe, expect, it, vi } from "vitest";
import { parseManifest, rangeFloor } from "../src/lib/deps/manifests";
import { cvss3Score, osvSeverity, scanDependencies } from "../src/lib/deps/osv";
import { GitHubClient, parseGitHubUrl, selectFiles } from "../src/lib/github";
import { toMarkdown, toSarif } from "../src/lib/report/export";
import { runAudit } from "../src/lib/pipeline";
import { SAMPLES } from "../src/lib/samples";
import type { PipelineEvent } from "../src/lib/report/types";

afterEach(() => vi.unstubAllGlobals());

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("manifests", () => {
  it("parses npm lockfiles, package.json ranges, requirements and go.mod", () => {
    const lock = parseManifest("package-lock.json", JSON.stringify({ packages: { "": {}, "node_modules/lodash": { version: "4.17.15" }, "node_modules/a/node_modules/b": { version: "1.0.0" } } }));
    expect(lock.map((d) => `${d.name}@${d.version}`)).toEqual(["lodash@4.17.15", "b@1.0.0"]);
    const pkg = parseManifest("package.json", JSON.stringify({ dependencies: { express: "^4.17.1", local: "file:../x" } }));
    expect(pkg).toEqual([expect.objectContaining({ name: "express", version: "4.17.1", exact: false })]);
    const req = parseManifest("requirements.txt", "Django==3.2.0  # pinned\nrequests>=2.0\n-r other.txt\n");
    expect(req.map((d) => [d.name, d.version, d.exact])).toEqual([["django", "3.2.0", true], ["requests", "2.0", false]]);
    const go = parseManifest("go.mod", "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n");
    expect(go[0]).toMatchObject({ name: "github.com/gin-gonic/gin", version: "v1.6.0", ecosystem: "Go" });
  });

  it("computes range floors", () => {
    expect(rangeFloor("^1.2.3")).toBe("1.2.3");
    expect(rangeFloor("~2.1")).toBe("2.1.0");
    expect(rangeFloor(">=3.0.0 <4")).toBe("3.0.0");
    expect(rangeFloor("workspace:*")).toBeNull();
  });
});

describe("OSV + CVSS", () => {
  it("computes CVSS 3.1 base scores", () => {
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3Score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3Score("CVSS:4.0/AV:N")).toBeNull();
    expect(osvSeverity({ id: "x", database_specific: { severity: "MODERATE" } }).severity).toBe("medium");
  });

  it("turns OSV advisories into findings with fix versions", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/querybatch")) return json({ results: [{ vulns: [{ id: "GHSA-test" }] }, {}] });
      return json({ id: "GHSA-test", summary: "Prototype pollution", aliases: ["CVE-2020-8203"], severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" }], affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }] }] });
    }));
    const res = await scanDependencies([
      { name: "lodash", version: "4.17.15", ecosystem: "npm", exact: true, manifest: "package-lock.json" },
      { name: "safe", version: "1.0.0", ecosystem: "npm", exact: true, manifest: "package-lock.json" },
    ]);
    expect(res).toMatchObject({ scanned: 2, vulnerable: 1 });
    expect(res.findings[0]).toMatchObject({ ruleId: "GHSA-test", severity: "high", detector: "osv", remediation: "Upgrade lodash to 4.17.19 or later." });
    expect(res.findings[0].description).toContain("CVE-2020-8203");
  });
});

describe("GitHub", () => {
  it("parses every URL shape users paste", () => {
    expect(parseGitHubUrl("vercel/next.js")).toMatchObject({ kind: "repo", owner: "vercel", repo: "next.js" });
    expect(parseGitHubUrl("https://github.com/o/r.git")).toMatchObject({ kind: "repo", repo: "r" });
    expect(parseGitHubUrl("https://github.com/o/r/tree/feat/x/src")).toMatchObject({ kind: "repo", segments: ["feat", "x", "src"] });
    expect(parseGitHubUrl("https://github.com/o/r/blob/main/src/a.ts")).toMatchObject({ kind: "file", segments: ["main", "src", "a.ts"] });
    expect(parseGitHubUrl("https://raw.githubusercontent.com/o/r/refs/heads/dev/a.py")).toMatchObject({ kind: "file", segments: ["dev", "a.py"] });
    expect(() => parseGitHubUrl("https://gitlab.com/o/r")).toThrow(/github\.com/);
    expect(() => parseGitHubUrl("https://github.com/o/r/issues/1")).toThrow(/Unsupported/);
    expect(() => parseGitHubUrl("https://github.com/o/..%2F..")).toThrow();
  });

  it("resolves branch names containing slashes", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === "https://raw.githubusercontent.com/o/r/feat/auth/src/a.ts") return new Response("const a = 1;");
      if (url === "https://api.github.com/repos/o/r/branches/feat/auth") return json({ name: "feat/auth" });
      return new Response("", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const file = await new GitHubClient().resolveFile("o", "r", ["feat", "auth", "src", "a.ts"]);
    expect(file).toEqual({ ref: "feat/auth", path: "src/a.ts", content: "const a = 1;" });
  });

  it("explains rate limits", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 403, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 600) } })));
    await expect(new GitHubClient().repoInfo("o", "r")).rejects.toMatchObject({ status: 429, hint: expect.stringContaining("GITHUB_TOKEN") });
  });

  it("ranks repository files by attack surface and skips vendored code", () => {
    const entries = ["src/routes/auth.ts", "src/utils/format.ts", "node_modules/x/index.js", "dist/app.js", "src/api/upload.py", "test/auth.test.ts", "README.md", "package.json", "package-lock.json", "web/package.json", "app.min.js"].map((path) => ({ path, size: 2000, sha: "" }));
    const sel = selectFiles(entries, 3);
    expect(sel.sources.map((e) => e.path)).toEqual(["src/routes/auth.ts", "src/api/upload.py", "src/utils/format.ts"]);
    expect(sel.manifests.map((e) => e.path)).toEqual(["package-lock.json", "web/package.json"]);
  });
});

describe("exports", () => {
  it("produces valid-looking SARIF with code flows and suppressions", async () => {
    const report = await runAudit({ code: SAMPLES[0].code, filename: SAMPLES[0].filename, swarm: "off" }, { github: new GitHubClient(), provider: null, maxRepoFiles: 10 }, () => {});
    const sarif = toSarif(report) as { version: string; runs: Array<{ tool: { driver: { rules: Array<{ id: string; properties: Record<string, unknown> }> } }; results: Array<{ ruleId: string; level: string; codeFlows?: unknown[] }> }> };
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.results.length).toBe(report.findings.length);
    const sql = run.results.find((r) => r.ruleId === "AEG-TAINT-SQL")!;
    expect(sql.level).toBe("error");
    expect(sql.codeFlows).toHaveLength(1);
    expect(run.tool.driver.rules.find((r) => r.id === "AEG-TAINT-SQL")!.properties["security-severity"]).toBe("9.5");
    expect(toMarkdown(report)).toContain("# AegisCode audit");
  });
});

describe("pipeline", () => {
  it("streams stages and skips the swarm with a reason when no model is configured", async () => {
    const events: PipelineEvent[] = [];
    const report = await runAudit({ code: SAMPLES[0].code, filename: SAMPLES[0].filename, swarm: "auto" }, { github: new GitHubClient(), provider: null, maxRepoFiles: 10 }, (e) => events.push(e));
    expect(report.summary.grade).toBe("F");
    expect(report.swarm).toMatchObject({ status: "skipped", reason: expect.stringContaining("GEMINI_API_KEY") });
    const stageIds = events.filter((e) => e.type === "stage").map((e) => (e as Extract<PipelineEvent, { type: "stage" }>).stage.id);
    expect(new Set(stageIds)).toEqual(new Set(["ingest", "parse", "taint", "patterns", "secrets", "metrics", "deps", "triage", "critic", "defender", "judge", "verify"]));
    expect(report.sources[SAMPLES[0].filename]).toBe(SAMPLES[0].code);
  });

  it("does not spend LLM calls on clean code", async () => {
    const generate = vi.fn();
    const clean = SAMPLES.find((s) => s.id === "clean")!;
    const report = await runAudit({ code: clean.code, filename: clean.filename, swarm: "auto" }, { github: new GitHubClient(), provider: { name: "x", model: "x", generate }, maxRepoFiles: 10 }, () => {});
    expect(generate).not.toHaveBeenCalled();
    expect(report.summary.score).toBe(100);
    expect(report.swarm).toMatchObject({ status: "skipped", reason: expect.stringContaining("below the 50% escalation threshold") });
  });

  it("keeps static results when the swarm fails", async () => {
    const report = await runAudit(
      { code: SAMPLES[0].code, filename: SAMPLES[0].filename, swarm: "force" },
      { github: new GitHubClient(), provider: { name: "x", model: "x", generate: async () => { throw new Error("quota exceeded"); } }, maxRepoFiles: 10 },
      () => {}
    );
    expect(report.swarm).toMatchObject({ status: "failed" });
    expect(report.findings.length).toBeGreaterThan(5);
  });
});
