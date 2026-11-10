import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, appendFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/cli/mcp";
import { parseNameStatus, scanChanges } from "../src/cli/changes";
import { walk } from "../src/cli/index";
import { diffFindings } from "../src/lib/baseline";
import { scanFile } from "../src/lib/engine";

let repo: string;
const git = (...args: string[]) => execFileSync("git", args, { cwd: repo, stdio: "ignore" });

beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), "aegis-agent-"));
  mkdirSync(join(repo, "src"));
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  writeFileSync(join(repo, "src/db.ts"), `export function legacy(id: string) {\n  return pool.query("SELECT * FROM old WHERE id = " + id);\n}\nexport function run(cmd: string) {\n  exec("sh -c " + cmd);\n}\n`);
  writeFileSync(join(repo, "src/routes.ts"), `import { legacy, run } from "./db";\napp.get("/old", (req, res) => res.json(legacy(req.query.id)));\n`);
  git("add", "-A");
  git("commit", "-qm", "init");
});

afterAll(() => rmSync(repo, { recursive: true, force: true }));

describe("baseline comparison", () => {
  it("matches findings by content, not line numbers", () => {
    const before = scanFile("a.ts", `app.get("/", (req) => db.query("SELECT " + req.query.id));`).findings;
    const after = scanFile("a.ts", `// a new comment above shifts every line\n\napp.get("/", (req) => db.query("SELECT " + req.query.id));\napp.get("/x", (req) => eval(req.query.code));`).findings;
    const diff = diffFindings(before, after);
    expect(diff.existing.map((f) => f.ruleId)).toEqual(["AEG-TAINT-SQL"]);
    expect(diff.added.map((f) => f.ruleId)).toEqual(["AEG-TAINT-CODE"]);
    expect(diff.fixed).toEqual([]);
  });
});

describe("change scanning", () => {
  it("reports only what the working-tree change introduces, including flows into unchanged files", async () => {
    appendFileSync(join(repo, "src/routes.ts"), `app.post("/run", (req, res) => { run(req.body.cmd); res.end(); });\n`);
    const res = await scanChanges(repo, { kind: "working" }, { packages: false });
    expect(res.files).toEqual(["src/routes.ts"]);
    expect(res.added.map((f) => [f.ruleId, f.file])).toEqual([["AEG-TAINT-CMD", "src/db.ts"]]);
    expect(res.existing.map((f) => f.ruleId)).toContain("AEG-TAINT-SQL");
    git("checkout", "--", ".");
  });

  it("scans the index for staged changes", async () => {
    appendFileSync(join(repo, "src/routes.ts"), `app.get("/e", (req) => eval(req.query.x));\n`);
    git("add", "src/routes.ts");
    const res = await scanChanges(repo, { kind: "staged" }, { packages: false });
    expect(res.added.map((f) => f.ruleId)).toEqual(["AEG-TAINT-CODE"]);
    git("reset", "-q", "--hard");
  });

  it("follows a renamed file back to its old name, so its existing issues aren't reported as new", async () => {
    git("mv", "src/db.ts", "src/database.ts");
    const moved = await scanChanges(repo, { kind: "staged" }, { packages: false });
    expect(moved.files).toEqual(["src/database.ts"]);
    expect(moved.added).toEqual([]);
    expect(moved.existing.length).toBeGreaterThan(0);

    appendFileSync(join(repo, "src/database.ts"), `app.get("/e", (req) => eval(req.query.x));\n`);
    git("add", "-A");
    const edited = await scanChanges(repo, { kind: "staged" }, { packages: false });
    expect(edited.added.map((f) => [f.ruleId, f.file])).toEqual([["AEG-TAINT-CODE", "src/database.ts"]]);
    git("reset", "-q", "--hard");
  });

  it("scans files whose names git would otherwise quote", async () => {
    const name = "src/café ünï.ts";
    writeFileSync(join(repo, name), `app.get("/", (req) => eval(req.query.x));\n`);
    const untracked = await scanChanges(repo, { kind: "working" }, { packages: false });
    expect(untracked.files).toEqual([name]);
    expect(untracked.added.map((f) => f.ruleId)).toEqual(["AEG-TAINT-CODE"]);

    git("add", "-A");
    const staged = await scanChanges(repo, { kind: "staged" }, { packages: false });
    expect(staged.added.map((f) => f.file)).toEqual([name]);
    git("reset", "-q", "--hard");
  });

  it("parses NUL-separated name-status output, including renames", () => {
    expect(parseNameStatus("M\0a.ts\0R087\0old name.ts\0new name.ts\0A\0b.ts\0")).toEqual([{ path: "a.ts" }, { path: "new name.ts", previous: "old name.ts" }, { path: "b.ts" }]);
    expect(parseNameStatus(null)).toEqual([]);
  });
});

describe("file walk", () => {
  it("skips dangling links and link loops instead of aborting", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-walk-"));
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src/a.ts"), "export const a = 1;\n");
    symlinkSync("/nonexistent/target", join(dir, "src/dangling"));
    symlinkSync(dir, join(dir, "src/loop"));
    symlinkSync(join(dir, "src/a.ts"), join(dir, "alias.ts"));
    expect(walk(dir).map((e) => e.path).sort()).toEqual(["alias.ts", "src/a.ts"]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("MCP server", () => {
  async function connect() {
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const server = createServer(repo);
    const client = new Client({ name: "test", version: "1.0.0" });
    await Promise.all([server.connect(serverT), client.connect(clientT)]);
    return client;
  }
  const textOf = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0].text);

  it("lists the agent tools", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["check_packages", "explain_rule", "scan_changes", "scan_code", "scan_paths"]);
  });

  it("scans code an agent is about to write", async () => {
    const client = await connect();
    const out = textOf(await client.callTool({ name: "scan_code", arguments: { filename: "api.ts", code: `app.get("/", (req, res) => res.redirect(req.query.next));` } }));
    expect(out).toMatch(/\[MEDIUM\] api\.ts:1 Open redirect/);
    expect(out).toMatch(/verified fix \(Only allow same-site paths\), replace line 1 with:/);
  });

  it("refuses paths outside the project and explains rules", async () => {
    const client = await connect();
    const outside = await client.callTool({ name: "scan_paths", arguments: { paths: ["../../etc"] } });
    expect(JSON.stringify(outside)).toMatch(/outside the project/);
    // A link inside the project must not become a way to read files outside it.
    symlinkSync(tmpdir(), join(repo, "escape"));
    const viaLink = await client.callTool({ name: "scan_paths", arguments: { paths: ["escape"] } });
    expect(JSON.stringify(viaLink)).toMatch(/outside the project/);
    rmSync(join(repo, "escape"));
    expect(textOf(await client.callTool({ name: "explain_rule", arguments: { id: "aeg-taint-sql" } }))).toMatch(/^AEG-TAINT-SQL — SQL injection/);
  });

  it("reports new issues from uncommitted changes", async () => {
    appendFileSync(join(repo, "src/routes.ts"), `app.post("/run", (req, res) => run(req.body.cmd));\n`);
    const client = await connect();
    const out = textOf(await client.callTool({ name: "scan_changes", arguments: { scope: "working" } }));
    expect(out).toMatch(/1 new issue/);
    expect(out).toMatch(/\[CRITICAL\] src\/db\.ts:5 Command injection/);
    git("checkout", "--", ".");
  });
});
