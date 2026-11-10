import { describe, expect, it } from "vitest";
import { scanProject } from "../src/lib/engine";
import { isValuePosition } from "../src/lib/engine/fixes";
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

  it("only binds values, never a spliced-in clause, column or sort direction", () => {
    // Binding `where` or `dir` as a parameter would produce a query that no longer runs.
    expect(fixesFor(`app.get("/", async (req, res) => {\n  const where = req.query.q ? "WHERE title = '" + req.query.q + "'" : "";\n  const dir = req.query.dir;\n  res.json(await db.query("SELECT * FROM posts " + where + " ORDER BY created_at " + dir));\n});`)).toEqual([]);
    expect(fixesFor(`app.get("/", (req) => db.query("SELECT " + req.query.cols + " FROM t WHERE id = 1"));`)).toEqual([]);
    expect(fixesFor(`app.get("/", (req) => db.query("SELECT * FROM t WHERE name = '" + req.query.n + " AND x = 1"));`)).toEqual([]);
    expect(isValuePosition("SELECT * FROM t WHERE id = ")).toBe(true);
    expect(isValuePosition("SELECT * FROM t WHERE age >= ")).toBe(true);
    expect(isValuePosition("SELECT * FROM t WHERE id IN (?, ")).toBe(true);
    expect(isValuePosition("INSERT INTO t (a, b) VALUES (")).toBe(true);
    expect(isValuePosition("SELECT * FROM t WHERE d BETWEEN ? AND ")).toBe(true);
    expect(isValuePosition("SELECT * FROM t LIMIT ")).toBe(true);
    expect(isValuePosition("SELECT * FROM posts ")).toBe(false);
    expect(isValuePosition("SELECT * FROM t WHERE a = 1 AND ")).toBe(false);
    expect(isValuePosition("SELECT count(")).toBe(false);
    expect(isValuePosition("SELECT * FROM t ORDER BY created_at ")).toBe(false);
  });

  it("binds every value in VALUES and IN lists", () => {
    expect(fixesFor(`app.post("/", (req) => db.query("INSERT INTO t (a, b) VALUES (" + req.body.a + ", '" + req.body.b + "')"));`)[0].added).toContain(`db.query("INSERT INTO t (a, b) VALUES (?, ?)", [req.body.a, req.body.b])`);
    expect(fixesFor(`app.get("/", (req) => pool.query("SELECT * FROM t WHERE id IN (" + req.query.a + ", " + req.query.b + ") LIMIT " + req.query.n));`)[0].added).toContain(`pool.query("SELECT * FROM t WHERE id IN ($1, $2) LIMIT $3", [req.query.a, req.query.b, req.query.n])`);
  });

  it("writes the fix in the form each client expects, or not at all", () => {
    expect(fixesFor("app.get('/', async (req, res) => res.json(await sequelize.query(`SELECT * FROM p WHERE name = '${req.query.n}'`)));")[0].added).toContain(`sequelize.query("SELECT * FROM p WHERE name = ?", { replacements: [req.query.n] })`);
    expect(fixesFor(`app.get("/", (req, res) => res.json(db.prepare("SELECT * FROM t WHERE id = " + req.query.id).get()));`)).toEqual([]);
    expect(fixesFor("app.get('/', async (req, res) => res.json(await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${req.query.id}`)));")).toEqual([]);
    expect(fixesFor("app.post('/', (req) => { const ids = req.body.ids.join(','); db.query(`DELETE FROM t WHERE id IN (${ids})`); });")).toEqual([]);
  });

  it("does not turn intentional markup into text", () => {
    expect(fixesFor(`el.innerHTML = "<strong>" + location.hash + "</strong>";`, "c.js")).toEqual([]);
    expect(fixesFor(`el.innerHTML = "Welcome " + location.hash;`, "c.js")[0].added).toContain("el.textContent =");
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
