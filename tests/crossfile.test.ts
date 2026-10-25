import { describe, expect, it } from "vitest";
import { scanProject } from "../src/lib/engine";
import { taint } from "./helpers";

const ids = (code: string) => taint("a.ts", code).map((f) => f.ruleId);

describe("validation guards", () => {
  it("clears taint after an allowlist check that exits", () => {
    expect(ids(`app.get("/", (req) => { const u = new URL(req.query.url); if (!ALLOWED.has(u.hostname)) return; fetch(u); });`)).toEqual([]);
    expect(ids(`app.get("/", (req) => { const u = new URL(req.query.url); fetch(u); });`)).toEqual(["AEG-TAINT-SSRF"]);
  });

  it("understands anchored regex tests and rejects unanchored ones", () => {
    expect(ids(`app.get("/", (req) => { const id = req.query.id; if (!/^\\d+$/.test(id)) throw new Error("bad"); db.query("SELECT " + id); });`)).toEqual([]);
    expect(ids(`app.get("/", (req) => { const id = req.query.id; if (!/\\d+/.test(id)) throw new Error("bad"); db.query("SELECT " + id); });`)).toEqual(["AEG-TAINT-SQL"]);
  });

  it("treats validators as safe only inside the guarded branch", () => {
    const code = `app.get("/", (req) => { const id = req.query.id; if (isUuid(id)) { db.query("SELECT " + id); } db.query("DELETE " + id); });`;
    const found = taint("a.ts", code);
    expect(found).toHaveLength(1);
    expect(found[0].snippet).toContain("DELETE");
  });

  it("handles equality allowlists and path containment checks", () => {
    expect(ids(`app.get("/", (req) => { const s = req.query.sort; if (s !== "asc" && s !== "desc") return; db.query("SELECT * ORDER BY x " + s); });`)).toEqual([]);
    expect(ids(`app.get("/f", (req, res) => { const p = path.resolve(ROOT, req.params.f); if (!p.startsWith(ROOT)) return res.status(400).end(); res.sendFile(p); });`)).toEqual([]);
  });

  it("does not trust a protocol-only prefix check", () => {
    expect(ids(`app.get("/", (req) => { const u = req.query.u; if (!u.startsWith("https://")) return; fetch(u); });`)).toEqual(["AEG-TAINT-SSRF"]);
  });
});

describe("cross-file taint", () => {
  const files = [
    {
      path: "src/db/orders.ts",
      code: `import { pool } from "./pool";\n\nexport async function findOrders(customerId: string) {\n  return pool.query("SELECT * FROM orders WHERE customer = '" + customerId + "'");\n}\n\nexport function safeFind(id: string) {\n  return pool.query("SELECT * FROM orders WHERE id = $1", [id]);\n}\n`,
    },
    {
      path: "src/routes/orders.ts",
      code: `import { findOrders, safeFind } from "../db/orders";\nimport * as shell from "../lib/shell";\n\napp.get("/orders", async (req, res) => {\n  res.json(await findOrders(req.query.customer));\n  res.json(await safeFind(req.query.id));\n  shell.archive(req.query.name);\n});\n`,
    },
    { path: "src/lib/shell.js", code: `const { exec } = require("child_process");\nfunction archive(name) {\n  exec("tar czf /tmp/" + name + ".tgz data");\n}\nmodule.exports = { archive };\n` },
  ];

  it("reports the flow at the sink in the imported module with a two-file trace", () => {
    const reports = scanProject(files);
    const db = reports.find((r) => r.path === "src/db/orders.ts")!;
    const sql = db.findings.find((f) => f.ruleId === "AEG-TAINT-SQL")!;
    expect(sql).toBeTruthy();
    expect(sql.location.line).toBe(4);
    expect(sql.trace![0]).toMatchObject({ kind: "source", file: "src/routes/orders.ts" });
    expect(sql.trace!.some((s) => s.label.includes("in src/db/orders.ts"))).toBe(true);
    expect(db.findings.filter((f) => f.ruleId === "AEG-TAINT-SQL")).toHaveLength(1); // parameterised safeFind stays clean
  });

  it("follows CommonJS namespace imports", () => {
    const reports = scanProject(files);
    const shell = reports.find((r) => r.path === "src/lib/shell.js")!;
    expect(shell.findings.map((f) => f.ruleId)).toContain("AEG-TAINT-CMD");
    expect(shell.score).toBeLessThan(60);
  });

  it("leaves single files untouched", () => {
    expect(scanProject([files[0]])[0].findings.filter((f) => f.detector === "taint")).toHaveLength(0);
  });
});
