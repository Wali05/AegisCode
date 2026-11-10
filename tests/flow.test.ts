import { describe, expect, it } from "vitest";
import { isStrictPattern } from "../src/lib/engine/taint/analyzer";
import { taint } from "./helpers";

const ids = (code: string, file = "a.ts") => taint(file, code).map((f) => f.ruleId);
const handler = (body: string) => `app.get("/", async (req, res) => {\n${body}\n});`;

describe("control-flow joins", () => {
  it("reports a value that is tainted on either branch of an if / else", () => {
    expect(ids(handler(`let sql;\nif (req.query.raw) { sql = "SELECT * FROM t WHERE " + req.query.raw; } else { sql = "SELECT * FROM t"; }\ndb.query(sql);`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`let sql;\nif (!req.query.raw) { sql = "SELECT * FROM t"; } else { sql = "SELECT * FROM t WHERE " + req.query.raw; }\ndb.query(sql);`))).toEqual(["AEG-TAINT-SQL"]);
  });

  it("keeps taint when only one path replaces the value", () => {
    expect(ids(handler(`let id = req.query.id;\nif (req.query.reset) { id = "0"; }\ndb.query("SELECT * FROM t WHERE id = " + id);`))).toEqual(["AEG-TAINT-SQL"]);
  });

  it("is clean when every path validates or replaces the value", () => {
    expect(ids(handler(`let id = req.query.id;\nif (!isValidId(id)) { id = "0"; }\ndb.query("SELECT * FROM t WHERE id = " + id);`))).toEqual([]);
    expect(ids(handler(`let id = req.query.id;\nif (req.query.a) { id = "1"; } else if (req.query.b) { id = "2"; } else { id = "3"; }\ndb.query("SELECT * FROM t WHERE id = " + id);`))).toEqual([]);
  });

  it("joins switch clauses, including fall-through and a missing default", () => {
    expect(ids(handler(`let order;\nswitch (req.query.mode) {\n  case "raw": order = req.query.order; break;\n  default: order = "id";\n}\ndb.query("SELECT * FROM t ORDER BY " + order);`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`let order = req.query.order;\nswitch (req.query.mode) {\n  case "a": order = "id"; break;\n  case "b": order = "name"; break;\n}\ndb.query("SELECT * FROM t ORDER BY " + order);`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`let order = req.query.order;\nswitch (req.query.mode) {\n  case "a": order = "id"; break;\n  default: order = "name";\n}\ndb.query("SELECT * FROM t ORDER BY " + order);`))).toEqual([]);
  });

  it("treats a literal case as an allowlist for the switched value", () => {
    expect(ids(handler(`const sort = req.query.sort;\nlet col = "id";\nswitch (sort) {\n  case "name":\n  case "created_at":\n    col = sort;\n    break;\n}\ndb.query("SELECT * FROM t ORDER BY " + col);`))).toEqual([]);
  });

  it("assumes a try block may stop before its assignments", () => {
    expect(ids(handler(`let u = req.query.url;\ntry { await check(u); } catch (e) { u = "https://example.com"; }\nawait fetch(u);`))).toEqual(["AEG-TAINT-SSRF"]);
    expect(ids(handler(`let u;\ntry { u = new URL(req.query.u); } catch { return res.status(400).end(); }\nif (!ALLOWED.has(u.hostname)) return res.status(400).end();\nawait fetch(u);`))).toEqual([]);
  });

  it("carries taint from one loop iteration to the next", () => {
    expect(ids(`app.post("/", (req, res) => {\n  let prev = "";\n  for (const p of req.body.parts) { db.query("SELECT " + prev); prev = p; }\n});`)).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`app.post("/", (req, res) => {\n  let where = "";\n  let i = 0;\n  while (i < req.body.filters.length) { where += " AND " + req.body.filters[i++]; }\n  db.query("SELECT * FROM t WHERE 1=1" + where);\n});`)).toEqual(["AEG-TAINT-SQL"]);
  });

  it("honours guards that skip a loop iteration or short-circuit", () => {
    expect(ids(`app.post("/", (req, res) => {\n  for (const id of req.body.ids) {\n    if (!isUuid(id)) continue;\n    db.query("DELETE FROM t WHERE id = '" + id + "'");\n  }\n});`)).toEqual([]);
    expect(ids(handler(`const id = req.query.id;\nisUuid(id) && db.query("SELECT * FROM t WHERE id = '" + id + "'");`))).toEqual([]);
    expect(ids(handler(`const id = req.query.id;\nisUuid(id) || db.query("SELECT * FROM t WHERE id = '" + id + "'");`))).toEqual(["AEG-TAINT-SQL"]);
  });

  it("understands calls that never return as an early exit", () => {
    expect(ids(`export async function GET(request) {\n  const slug = new URL(request.url).searchParams.get("slug");\n  if (!/^[a-z0-9-]+$/.test(slug)) notFound();\n  return Response.json(await db.query("SELECT * FROM posts WHERE slug = '" + slug + "'"));\n}`)).toEqual([]);
  });

  it("hoists var out of the block it was declared in", () => {
    expect(ids(handler(`if (req.query.q) { var sql = "SELECT * FROM t WHERE q = '" + req.query.q + "'"; }\ndb.query(sql);`))).toEqual(["AEG-TAINT-SQL"]);
  });
});

describe("context-aware sanitisers", () => {
  it("does not accept an escaper written for a different context", () => {
    expect(ids(handler(`const name = escapeHtml(req.query.name);\ndb.query("SELECT * FROM t WHERE name = '" + name + "'");`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`db.query("SELECT * FROM t WHERE name = '" + encodeURIComponent(req.query.name) + "'");`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`exec("convert " + path.basename(req.query.f) + " out.png");`))).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(handler(`res.send("<b>" + db.escape(req.query.q) + "</b>");`))).toEqual(["AEG-TAINT-XSS"]);
  });

  it("accepts an escaper in its own context", () => {
    expect(ids(handler(`res.send("<h1>" + escapeHtml(req.query.name) + "</h1>");`))).toEqual([]);
    expect(ids(handler(`res.sendFile(path.join(ROOT, path.basename(req.query.f)));`))).toEqual([]);
    expect(ids(handler(`db.query("SELECT * FROM t WHERE name = " + connection.escape(req.query.name));`))).toEqual([]);
    expect(ids(handler(`await fetch("https://api.example.com/search?q=" + encodeURIComponent(req.query.q));`))).toEqual([]);
    expect(ids(handler(`new RegExp(escapeRegExp(req.query.q));`))).toEqual([]);
  });

  it("explains the mismatch in the trace", () => {
    const [f] = taint("a.ts", handler(`const name = escapeHtml(req.query.name);\ndb.query("SELECT * FROM t WHERE name = '" + name + "'");`));
    expect(f.trace!.some((s) => /escaped by escapeHtml\(\) for HTML only/.test(s.label))).toBe(true);
  });

  it("only clears a concatenation where every part is escaped for that sink", () => {
    expect(ids(handler(`res.send("<p>" + escapeHtml(req.query.a) + req.query.b + "</p>");`))).toEqual(["AEG-TAINT-XSS"]);
  });

  it("forgets the escaping once the value is decoded again", () => {
    expect(ids(handler(`const q = decodeURIComponent(encodeURIComponent(req.query.q));\nres.send("<p>" + q + "</p>");`))).toEqual(["AEG-TAINT-XSS"]);
  });
});

describe("objects, arrays and callbacks", () => {
  it("tracks object literal fields separately", () => {
    expect(ids(handler(`const cfg = { host: "api.internal.example", token: req.headers.authorization };\nawait fetch("https://" + cfg.host + "/v1/me");`))).toEqual([]);
    expect(ids(handler(`const cfg = { host: req.query.host, token: "x" };\nawait fetch("https://" + cfg.host + "/v1/me");`))).toEqual(["AEG-TAINT-SSRF"]);
    expect(ids(handler(`const { host } = { host: "api.internal.example", q: req.query.q };\nawait fetch("https://" + host + "/v1/me");`))).toEqual([]);
  });

  it("follows a later write to a field", () => {
    expect(ids(handler(`const cfg = { host: "api.internal.example", q: req.query.q };\ncfg.host = req.query.host;\nawait fetch("https://" + cfg.host + "/v1/me");`))).toEqual(["AEG-TAINT-SSRF"]);
    expect(ids(handler(`const cfg = { host: req.query.host, q: 1 };\ncfg.host = "api.internal.example";\nawait fetch("https://" + cfg.host + "/v1/me");`))).toEqual([]);
  });

  it("still treats the whole object as tainted when it is used whole or its shape is unknown", () => {
    expect(ids(handler(`const filter = { email: req.body.email, active: true };\nawait User.findOne(filter);`))).toEqual(["AEG-TAINT-NOSQL"]);
    expect(ids(handler(`const cfg = { ...req.body, host: "x" };\nawait fetch(cfg.url);`))).toEqual(["AEG-TAINT-SSRF"]);
  });

  it("uses what a map / reduce callback returns", () => {
    expect(ids(`app.post("/", (req, res) => {\n  const ids = req.body.ids.map((x) => Number(x)).join(",");\n  db.query(\`DELETE FROM t WHERE id IN (\${ids})\`);\n});`)).toEqual([]);
    expect(ids(`app.post("/", (req, res) => {\n  const ph = req.body.ids.map((_, i) => "$" + (i + 1)).join(",");\n  pool.query(\`DELETE FROM t WHERE id IN (\${ph})\`, req.body.ids);\n});`)).toEqual([]);
    expect(ids(`app.post("/", (req, res) => {\n  const list = req.body.ids.map((x) => "'" + x + "'").join(",");\n  db.query(\`DELETE FROM t WHERE id IN (\${list})\`);\n});`)).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`app.post("/", (req, res) => {\n  const where = req.body.filters.reduce((acc, f) => acc + " AND " + f, "1=1");\n  db.query("SELECT * FROM t WHERE " + where);\n});`)).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`app.post("/", (req, res) => {\n  const total = req.body.items.reduce((acc, i) => acc + Number(i.qty), 0);\n  db.query("SELECT " + total);\n});`)).toEqual([]);
  });
});

describe("framework sources", () => {
  it("reads NestJS parameter decorators, and respects validating pipes", () => {
    const nest = (params: string, body: string) => `@Controller("users")\nexport class UsersController {\n  constructor(private readonly db: Db) {}\n  @Get(":id")\n  find(${params}) {\n    ${body}\n  }\n}`;
    expect(ids(nest(`@Param("id") id: string`, "return this.db.query(`SELECT * FROM users WHERE id = ${id}`);"))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(nest(`@Body() dto: CreateUserDto`, "return this.users.findOne({ email: dto.email });"))).toEqual(["AEG-TAINT-NOSQL"]);
    expect(ids(nest(`@Param("id", ParseIntPipe) id: number`, "return this.db.query(`SELECT * FROM users WHERE id = ${id}`);"))).toEqual([]);
    expect(ids(nest(`@Param("id", new ParseUUIDPipe()) id: string`, "return this.db.query(`SELECT * FROM users WHERE id = '${id}'`);"))).toEqual([]);
    expect(ids(nest(`@Req() incoming: Request`, "return this.db.query(`SELECT * FROM users WHERE id = ${incoming.query.id}`);"))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(nest(`@Inject(TOKEN) table: string`, "return this.db.query(`SELECT * FROM ${table}`);"))).toEqual([]);
  });

  it("treats Server Action arguments as client input", () => {
    expect(ids(`"use server";\nexport async function rename(formData: FormData) {\n  await db.query("UPDATE t SET name = '" + formData.get("name") + "'");\n}`)).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`"use server";\nexport const remove = async (id: string) => {\n  await db.query("DELETE FROM t WHERE id = '" + id + "'");\n};`)).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`export default function Page() {\n  async function save(formData: FormData) {\n    "use server";\n    await fs.writeFile("./notes/" + formData.get("file"), "x");\n  }\n  return <form action={save} />;\n}`, "page.tsx")).toEqual(["AEG-TAINT-PATH"]);
    // Not exported, and no directive: an ordinary helper.
    expect(ids(`"use server";\nasync function helper(id: string) {\n  await db.query("DELETE FROM t WHERE id = '" + id + "'");\n}`)).toEqual([]);
    expect(ids(`export async function rename(formData: FormData) {\n  await db.query("UPDATE t SET name = '" + formData.get("name") + "'");\n}`)).toEqual([]);
  });

  it("recognises the request by type or position, whatever it is called", () => {
    expect(ids(`export async function POST(r: Request) {\n  const { cmd } = await r.json();\n  return new Response(execSync(cmd));\n}`)).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(`export const GET = async (incoming) => {\n  return fetch(incoming.nextUrl.searchParams.get("u"));\n};`)).toEqual(["AEG-TAINT-SSRF"]);
    expect(ids(`async function proxy(msg: IncomingMessage) {\n  return fetch(msg.url);\n}`)).toEqual(["AEG-TAINT-SSRF"]);
    // An unrelated object that happens to have a .url is not a request.
    expect(ids(`async function load(item) {\n  return fetch(item.url);\n}`)).toEqual([]);
  });

  it("covers Hono's request helpers", () => {
    expect(ids(`app.post("/x", async (c) => {\n  const body = await c.req.json();\n  return c.json(await db.query("SELECT * FROM t WHERE name = '" + body.name + "'"));\n});`)).toEqual(["AEG-TAINT-SQL"]);
  });
});

describe("sink details", () => {
  it("flags argument arrays that are handed to a shell", () => {
    expect(ids(handler(`spawn("sh", ["-c", "ls " + req.query.d]);`))).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(handler(`spawn("ls", [req.query.d], { shell: true });`))).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(handler(`spawn("ls", [req.query.d]);`))).toEqual([]);
    expect(ids(handler(`spawn("bash", ["./deploy.sh", req.query.env]);`))).toEqual([]);
  });

  it("flags string concatenation inside a MongoDB $where", () => {
    const [f] = taint("a.ts", handler(`res.json(await User.find({ $where: "this.name == '" + req.query.name + "'" }));`));
    expect(f.ruleId).toBe("AEG-TAINT-NOSQL");
    expect(f.severity).toBe("critical");
    expect(ids(handler(`res.json(await User.find({ $where: "this.active == true" }));`))).toEqual([]);
  });

  it("trusts a postMessage payload only after its origin is checked", () => {
    expect(ids(`window.addEventListener("message", (e) => {\n  el.innerHTML = e.data;\n});`, "c.js")).toEqual(["AEG-TAINT-XSS"]);
    expect(ids(`window.addEventListener("message", (e) => {\n  if (e.origin !== "https://app.example.com") return;\n  el.innerHTML = e.data.html;\n});`, "c.js")).toEqual([]);
    expect(ids(`window.addEventListener("message", (e) => {\n  if (!TRUSTED.includes(e.origin)) return;\n  el.innerHTML = e.data;\n});`, "c.js")).toEqual([]);
  });

  it("only accepts regexes that constrain the whole value", () => {
    expect(isStrictPattern("/^\\d+$/")).toBe(true);
    expect(isStrictPattern("/^[a-z0-9-]+$/i")).toBe(true);
    expect(isStrictPattern("/^(?:asc|desc)$/")).toBe(true);
    expect(isStrictPattern("/^a$|^b$/")).toBe(true);
    expect(isStrictPattern("/\\d+/")).toBe(false);
    expect(isStrictPattern("/^\\d+|.*$/")).toBe(false);
    expect(isStrictPattern("/^.*$/")).toBe(false);
    expect(isStrictPattern("/^[\\s\\S]*$/")).toBe(false);
    expect(isStrictPattern("/^\\d+\\$/")).toBe(false);
    expect(isStrictPattern("/^[a|b]+$/")).toBe(true);
  });
});

describe("lexical engine (Python / PHP)", () => {
  it("analyses a call spread over several lines as one statement", () => {
    const found = taint("a.py", `name = request.args.get("name")\ncur.execute(\n    "SELECT * FROM users WHERE name = '" + name + "'"\n)`);
    expect(found.map((f) => f.ruleId)).toEqual(["AEG-TAINT-SQL"]);
    expect(found[0].location.line).toBe(2);
    expect(taint("a.py", `name = request.args.get("name")\ncur.execute(\n    "SELECT * FROM users WHERE name = %s",\n    (name,),\n)`)).toHaveLength(0);
    expect(taint("a.php", `<?php\n$id = $_GET['id'];\n$r = $pdo->query(\n  "SELECT * FROM t WHERE id = " . $id\n);`).map((f) => f.ruleId)).toEqual(["AEG-TAINT-SQL"]);
  });

  it("does not join PHP blocks into one line", () => {
    const found = taint("a.php", `<?php\nif (isset($_GET['id'])) {\n  $id = $_GET['id'];\n  echo "<p>" . $id . "</p>";\n}`);
    expect(found.map((f) => [f.ruleId, f.location.line])).toEqual([["AEG-TAINT-XSS", 4]]);
  });

  it("keeps Python locals inside their function", () => {
    expect(taint("a.py", `def a():\n    name = request.args.get("name")\n    return name\n\ndef b(name):\n    os.system("echo " + name)`)).toHaveLength(0);
    expect(taint("a.py", `def a():\n    name = request.args.get("name")\n    os.system("echo " + name)`)).toHaveLength(1);
  });

  it("treats route handler parameters as request input", () => {
    expect(ids(`@app.get("/items/{item_id}")\ndef read(item_id: str, q: str = None):\n    cur.execute(f"SELECT * FROM items WHERE id = {item_id}")`, "a.py")).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(`@app.route("/u/<name>")\ndef user(name):\n    return os.popen("finger " + name).read()`, "a.py")).toEqual(["AEG-TAINT-CMD"]);
    // Typed or converted parameters, and injected dependencies, are not strings from the client.
    expect(ids(`@app.get("/items/{item_id}")\ndef read(item_id: int, db: Session = Depends(get_db)):\n    cur.execute(f"SELECT * FROM items WHERE id = {item_id}")`, "a.py")).toEqual([]);
    expect(ids(`@app.route("/u/<int:uid>")\ndef user(uid):\n    cur.execute("SELECT * FROM u WHERE id = %d" % uid)`, "a.py")).toEqual([]);
    expect(ids(`def helper(name):\n    os.system("echo " + name)`, "a.py")).toEqual([]);
  });

  it("covers PHP short echo tags and stops at the closing tag", () => {
    expect(ids(`<h1><?= $_GET['name'] ?></h1>`, "a.php")).toEqual(["AEG-TAINT-XSS"]);
    expect(ids(`<h1><?= htmlspecialchars($_GET['name']) ?></h1>`, "a.php")).toEqual([]);
    expect(ids(`<?php echo htmlspecialchars($_GET['name']) ?>`, "a.php")).toEqual([]);
  });
});

describe("calls into the project's own classes", () => {
  it("follows a typed field into another class's method", () => {
    const code = `class ProductService {\n  constructor(private db) {}\n  search(term: string) {\n    return this.db.query("SELECT * FROM p WHERE name LIKE '%" + term + "%'");\n  }\n}\nclass ProductController {\n  constructor(private service: ProductService) {}\n  async list(req, res) {\n    res.json(await this.service.search(req.query.q));\n  }\n}`;
    const [f] = taint("a.ts", code);
    expect(f.ruleId).toBe("AEG-TAINT-SQL");
    expect(f.location.line).toBe(4);
    expect(f.trace!.some((s) => s.label.includes("passed to ProductService.search()"))).toBe(true);
  });

  it("keeps same-named methods of different classes apart", () => {
    const code = `class Safe {\n  run(x) { return x.length; }\n}\nclass Unsafe {\n  run(x) { return exec("ls " + x); }\n}\nconst a = new Safe();\nconst b = new Unsafe();\napp.get("/a", (req, res) => res.json(a.run(req.query.d)));`;
    expect(ids(code)).toEqual([]);
    expect(ids(code.replace("a.run(req.query.d)", "b.run(req.query.d)"))).toEqual(["AEG-TAINT-CMD"]);
  });

  it("still treats a driver call as a sink when the receiver's class is unknown", () => {
    expect(ids(`class Repo {\n  query(sql) { return this.pool.query(sql); }\n}\napp.get("/", (req, res) => db.query("SELECT " + req.query.c));`)).toEqual(["AEG-TAINT-SQL"]);
  });
});

describe("second-pass sources, sinks and validators", () => {
  it("sees through promisify and renamed imports", () => {
    expect(ids(`import { exec } from "node:child_process";\nimport { promisify } from "node:util";\nconst execAsync = promisify(exec);\napp.post("/t", async (req, res) => { await execAsync(\`convert \${req.body.file} out.png\`); });`)).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(`import { exec as sh } from "node:child_process";\napp.post("/t", (req, res) => { sh("ls " + req.body.dir); });`)).toEqual(["AEG-TAINT-CMD"]);
    expect(ids(`import { execFile } from "node:child_process";\nconst run = promisify(execFile);\napp.post("/t", async (req, res) => { await run("ls", [req.body.dir]); });`)).toEqual([]);
  });

  it("treats GraphQL resolver arguments as client input", () => {
    const resolvers = (body: string) => `export const resolvers = {\n  Query: {\n    user: async (_parent, args, ctx) => {\n      ${body}\n    },\n  },\n};`;
    expect(ids(resolvers(`return ctx.db.query("SELECT * FROM users WHERE email = '" + args.email + "'");`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(resolvers(`return ctx.db.query("SELECT * FROM users WHERE email = $1", [args.email]);`))).toEqual([]);
    // The same shape outside a resolver map is just a function.
    expect(ids(`export const helpers = {\n  Format: {\n    user: (_p, args, ctx) => ctx.db.query("SELECT " + args.col),\n  },\n};`)).toEqual([]);
  });

  it("reports SQL built inside a query-builder condition, not bound values", () => {
    expect(ids(handler("res.json(await repo.createQueryBuilder(\"u\").where(`u.name = '${req.query.name}'`).getMany());"))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(handler(`res.json(await repo.createQueryBuilder("u").where("u.name = :name", { name: req.query.name }).getMany());`))).toEqual([]);
    expect(ids(handler(`res.json(await knex("users").where("name", req.query.name));`))).toEqual([]);
    expect(ids(handler(`res.json(await knex("users").where({ name: String(req.query.name) }));`))).toEqual([]);
  });

  it("reports a tainted Location header however it is set", () => {
    expect(ids(handler(`res.writeHead(302, { Location: req.query.to });\nres.end();`))).toEqual(["AEG-TAINT-REDIRECT"]);
    expect(ids(handler(`res.setHeader("Location", req.query.to);\nres.statusCode = 302;\nres.end();`))).toEqual(["AEG-TAINT-REDIRECT"]);
    expect(ids(`export async function GET(request) {\n  const to = new URL(request.url).searchParams.get("to");\n  return new Response(null, { status: 302, headers: { Location: to } });\n}`)).toEqual(["AEG-TAINT-REDIRECT"]);
    expect(ids(handler(`res.setHeader("Content-Type", req.query.type);\nres.end();`))).toEqual([]);
  });

  it("does not call a fixed same-site path prefix an open redirect", () => {
    expect(ids(handler(`res.redirect("/users/" + req.params.id);`))).toEqual([]);
    expect(ids(handler("res.redirect(`/users/${req.params.id}`);"))).toEqual([]);
    // A bare "/" prefix still lets "//evil.example" through.
    expect(ids(handler(`res.redirect("/" + req.query.next);`))).toEqual(["AEG-TAINT-REDIRECT"]);
    expect(ids(handler(`res.redirect("//" + req.query.host + "/x");`))).toEqual(["AEG-TAINT-REDIRECT"]);
  });

  it("reads Zod schemas: constrained fields come out clean, free text does not", () => {
    const zod = (shape: string, use: string) => `import { z } from "zod";\nconst Query = z.object(${shape});\napp.get("/posts", async (req, res) => {\n  ${use}\n});`;
    expect(ids(zod(`{ dir: z.enum(["asc", "desc"]) }`, `const { dir } = Query.parse(req.query);\nres.json(await db.query("SELECT * FROM posts ORDER BY created_at " + dir));`))).toEqual([]);
    expect(ids(zod(`{ page: z.coerce.number().int().min(1), id: z.string().uuid() }`, `const q = Query.parse(req.query);\nres.json(await db.query(\`SELECT * FROM posts WHERE id = '\${q.id}' OFFSET \${q.page}\`));`))).toEqual([]);
    expect(ids(zod(`{ title: z.string().min(1).max(80) }`, `const { title } = Query.parse(req.query);\nres.json(await db.query("SELECT * FROM posts WHERE title = '" + title + "'"));`))).toEqual(["AEG-TAINT-SQL"]);
    expect(ids(zod(`{ slug: z.string().regex(/^[a-z0-9-]+$/), note: z.string() }`, `const parsed = Query.safeParse(req.query);\nif (!parsed.success) return res.status(400).end();\nres.json(await db.query("SELECT * FROM posts WHERE slug = '" + parsed.data.slug + "'"));`))).toEqual([]);
    expect(ids(zod(`{ slug: z.string().regex(/^[a-z0-9-]+$/), note: z.string() }`, `const parsed = Query.safeParse(req.query);\nif (!parsed.success) return res.status(400).end();\nres.json(await db.query("SELECT * FROM posts WHERE note = '" + parsed.data.note + "'"));`))).toEqual(["AEG-TAINT-SQL"]);
  });
});
