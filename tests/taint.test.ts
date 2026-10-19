import { describe, expect, it } from "vitest";
import { taint } from "./helpers";

const ids = (code: string, file = "a.ts") => taint(file, code).map((f) => f.ruleId);

describe("JS/TS taint engine", () => {
  it("finds a direct SQL injection with a full trace", () => {
    const [f] = taint("a.ts", `app.get("/u", async (req, res) => {\n  const id = req.query.id;\n  await db.query("SELECT * FROM u WHERE id = " + id);\n});`);
    expect(f.ruleId).toBe("AEG-TAINT-SQL");
    expect(f.severity).toBe("critical");
    expect(f.location.line).toBe(3);
    expect(f.trace!.map((s) => s.kind)).toEqual(["source", "propagation", "propagation", "sink"]);
    expect(f.trace![0].line).toBe(2);
  });

  it("follows data across local functions via summaries", () => {
    const code = `function q(id) { return "SELECT * FROM t WHERE id=" + id }\nfunction run(c) { exec("ls " + c) }\napp.post("/x", (req, res) => { db.query(q(req.body.id)); run(req.body.cmd); });`;
    expect(ids(code).sort()).toEqual(["AEG-TAINT-CMD", "AEG-TAINT-SQL"]);
    const cmd = taint("a.ts", code).find((f) => f.ruleId === "AEG-TAINT-CMD")!;
    expect(cmd.location.line).toBe(2); // reported at the sink inside run()
    expect(cmd.trace!.some((s) => s.label.includes("passed to run()"))).toBe(true);
  });

  it("treats sanitizers and parameterised queries as safe", () => {
    expect(ids(`app.get("/", (req) => { const n = parseInt(req.query.n); db.query("SELECT " + n); });`)).toEqual([]);
    expect(ids(`app.get("/", (req) => { db.query("SELECT * FROM t WHERE id = $1", [req.query.id]); });`)).toEqual([]);
    expect(ids("app.get('/', (req) => { db.query(sql`SELECT * FROM t WHERE id = ${req.query.id}`); });")).toEqual([]);
    expect(ids(`app.get("/f", (req, res) => { res.sendFile(path.basename(req.params.f)); });`)).toEqual([]);
  });

  it("clears taint when a variable is reassigned with clean data", () => {
    expect(ids(`app.get("/", (req) => { let id = req.query.id; id = "1"; db.query("SELECT " + id); });`)).toEqual([]);
  });

  it("downgrades SSRF when the host is fixed", () => {
    const [full] = taint("a.ts", `app.get("/", (req) => fetch(req.query.url));`);
    const [partial] = taint("a.ts", "app.get('/', (req) => fetch(`https://api.example.com/users/${req.query.id}`));");
    expect(full.severity).toBe("high");
    expect(partial.severity).toBe("low");
  });

  it("only reports NoSQL injection for structured (unconverted) input", () => {
    expect(ids(`app.post("/login", async (req) => { await User.findOne({ email: req.body.email }); });`)).toEqual(["AEG-TAINT-NOSQL"]);
    expect(ids(`app.post("/login", async (req) => { await User.findOne({ email: String(req.body.email) }); });`)).toEqual([]);
  });

  it("handles Next.js route handlers and React client sources", () => {
    expect(ids(`export async function GET(request) {\n  const { searchParams } = new URL(request.url);\n  return fetch(searchParams.get("u"));\n}`)).toEqual(["AEG-TAINT-SSRF"]);
    const tsx = `export function C() {\n  const q = useSearchParams().get("q");\n  return <div dangerouslySetInnerHTML={{ __html: "<b>" + q }} />;\n}`;
    expect(ids(tsx, "c.tsx")).toEqual(["AEG-TAINT-XSS"]);
  });

  it("propagates through array callbacks and destructuring", () => {
    expect(ids(`app.post("/", (req) => { const { files } = req.body; files.forEach((f) => fs.unlinkSync(f)); });`)).toEqual(["AEG-TAINT-PATH"]);
  });

  it("detects DOM XSS, open redirects and prototype pollution", () => {
    expect(ids(`const h = location.hash; el.innerHTML = h;`)).toEqual(["AEG-TAINT-XSS"]);
    expect(ids(`app.get("/", (req, res) => res.redirect(req.query.next));`)).toEqual(["AEG-TAINT-REDIRECT"]);
    expect(ids(`app.post("/", (req) => { cfg[req.body.k][req.body.k2] = req.body.v; });`)).toEqual(["AEG-TAINT-PROTO"]);
  });

  it("does not confuse RegExp.exec with child_process.exec", () => {
    expect(ids(`app.get("/", (req) => { /a/.exec(req.query.q); pattern.exec(req.query.q); });`)).toEqual([]);
  });
});

describe("lexical taint (Python / PHP)", () => {
  it("tracks Python request data through f-strings into execute()", () => {
    const code = `term = request.args.get("q")\nquery = f"SELECT * FROM t WHERE name = '{term}'"\ncur.execute(query)\ncur.execute("SELECT * FROM t WHERE name = %s", (term,))`;
    const found = taint("app.py", code);
    expect(found.map((f) => f.ruleId)).toEqual(["AEG-TAINT-SQL"]);
    expect(found[0].location.line).toBe(3);
  });

  it("distinguishes shell=True from argument lists in subprocess", () => {
    const shell = taint("a.py", `h = request.args["h"]\nsubprocess.run(f"ping {h}", shell=True)`);
    expect(shell[0].severity).toBe("critical");
    const list = taint("a.py", `h = request.args["h"]\nsubprocess.run(["ping", h])`);
    expect(list[0].severity).toBe("medium"); // no shell, but `h` can still smuggle flags (argument injection)
    expect(list[0].title).toMatch(/^Argument injection/);
  });

  it("respects PHP sanitizers", () => {
    expect(taint("a.php", `<?php\n$id = $_GET['id'];\nmysqli_query($c, "SELECT * FROM t WHERE id=" . $id);`).map((f) => f.ruleId)).toEqual(["AEG-TAINT-SQL"]);
    expect(taint("a.php", `<?php\n$id = intval($_GET['id']);\nmysqli_query($c, "SELECT * FROM t WHERE id=" . $id);`)).toHaveLength(0);
  });
});
