import { describe, expect, it } from "vitest";
import { scanProject } from "../src/lib/engine";
import { taint } from "./helpers";

const fixesFor = (code: string, file = "a.ts") => {
  const [r] = scanProject([{ path: file, code }]);
  return r.findings.filter((f) => f.fix).map((f) => ({ rule: f.ruleId, verified: f.fix!.verified, added: f.fix!.diff.added.join("\n"), note: f.fix!.note }));
};

describe("ternary and expression guards", () => {
  it("treats a validated value as clean in the matching branch of a conditional", () => {
    expect(taint("a.ts", `app.get("/", (req, res) => res.redirect(/^\\/(?!\\/)[\\w\\-./?=&%#~]*$/.test(String(req.query.next)) ? String(req.query.next) : "/"));`)).toHaveLength(0);
    expect(taint("a.ts", `app.get("/", (req, res) => res.redirect(/^\\/(?!\\/)[\\w\\-./?=&%#~]*$/.test(String(req.query.next)) ? "/" : String(req.query.next)));`)).toHaveLength(1);
  });

  it("clears a validated request field without trusting the rest of the request", () => {
    const code = `app.get("/", (req) => { if (!LANGS.has(req.query.lang)) return; db.query("SELECT " + req.query.lang); db.query("SELECT " + req.query.other); });`;
    const found = taint("a.ts", code);
    expect(found).toHaveLength(1);
    expect(found[0].trace![0].snippet).toContain("req.query.other");
  });
});

describe("verified quick fixes", () => {
  it("parameterises string-built SQL, including quoted LIKE patterns", () => {
    const [fix] = fixesFor(`app.get("/", async (req, res) => res.json(await pool.query("SELECT * FROM d WHERE t LIKE '%" + req.query.q + "%' AND o = '" + req.query.o + "'")));`);
    expect(fix).toMatchObject({ rule: "AEG-TAINT-SQL", verified: true });
    expect(fix.added).toContain(`pool.query("SELECT * FROM d WHERE t LIKE $1 AND o = $2", [\`%\${req.query.q}%\`, req.query.o])`);
  });

  it("uses ? placeholders for non-postgres clients and refuses identifiers", () => {
    expect(fixesFor(`app.get("/", (req) => db.query(\`SELECT * FROM t WHERE id = \${req.query.id}\`));`)[0].added).toContain(`db.query("SELECT * FROM t WHERE id = ?", [req.query.id])`);
    expect(fixesFor(`app.get("/", (req) => db.query("SELECT * FROM t ORDER BY " + req.query.col));`)).toEqual([]);
  });

  it("does not rewrite queries that are built somewhere else", () => {
    expect(fixesFor(`function q(id) { return "SELECT * FROM t WHERE id = " + id; }\napp.get("/", (req) => db.query(q(req.query.id)));`)).toEqual([]);
  });

  it("fixes DOM XSS, NoSQL filters, redirects and TLS", () => {
    const rules = fixesFor(
      [
        `const p = new URLSearchParams(location.search);`,
        `document.getElementById("x").innerHTML = p.get("m");`,
        `app.post("/l", async (req) => Users.findOne({ email: req.body.email }));`,
        `app.get("/o", (req, res) => res.redirect(req.query.next));`,
        `export const agent = new https.Agent({ rejectUnauthorized: false });`,
      ].join("\n")
    );
    expect(rules.map((r) => [r.rule, r.verified])).toEqual(
      expect.arrayContaining([
        ["AEG-TAINT-XSS", true],
        ["AEG-TAINT-NOSQL", true],
        ["AEG-TAINT-REDIRECT", true],
        ["AEG-JS-013", true],
      ])
    );
  });

  it("only wraps the user-supplied part of a path", () => {
    const [fix] = fixesFor(`import path from "node:path";\napp.get("/d", (req, res) => res.sendFile(path.join(ROOT, "files", req.params.f)));`);
    expect(fix.verified).toBe(true);
    expect(fix.added).toContain(`path.join(ROOT, "files", path.basename(String(req.params.f)))`);
    expect(fixesFor(`import path from "node:path";\napp.get("/d", (req, res) => { const p = path.join(ROOT, req.params.f); res.sendFile(p); });`)).toEqual([]);
  });
});
