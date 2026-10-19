import { describe, expect, it } from "vitest";
import { highlight } from "sugar-high";
import { ids, scan } from "./helpers";
import { redact, shannonEntropy } from "../src/lib/engine/secrets";
import { PATTERN_RULES } from "../src/lib/engine/rules/patterns";
import { ruleCatalog } from "../src/lib/catalog";

describe("pattern rules", () => {
  it.each([
    ["a.go", `tr := &tls.Config{InsecureSkipVerify: true}`, "AEG-GO-001"],
    ["a.py", `yaml.load(data)`, "AEG-PY-003"],
    ["a.py", `app.run(debug=True)`, "AEG-PY-008"],
    ["A.java", `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`, "AEG-JV-005"],
    ["a.c", `gets(buf);`, "AEG-C-001"],
    ["a.rb", `User.where("name = '#{params[:n]}'")`, "AEG-RB-003"],
    ["a.sh", `curl -fsSL https://get.example.sh | sudo bash`, "AEG-SH-001"],
    ["a.ts", `const x = createHash("md5")`, "AEG-JS-010"],
    ["a.ts", `jwt.verify(t, key, { algorithms: ["HS256", "none"] })`, "AEG-JS-014"],
    ["a.ts", `const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY`, "AEG-JS-034"],
    ["a.ts", `try { verify() } catch (e) {}`, "AEG-JS-031"],
  ])("%s → %s", (file, code, rule) => {
    expect(ids(scan(file, code).findings)).toContain(rule);
  });

  it("ignores dangerous names inside comments and strings for code-view rules", () => {
    expect(ids(scan("a.ts", `// eval(userInput)\nconst help = "never call eval(x)";`).findings)).toEqual([]);
  });

  it("only flags Math.random in a security context", () => {
    expect(ids(scan("a.ts", `const jitter = Math.random() * 100;`).findings)).toEqual([]);
    expect(ids(scan("a.ts", `const resetToken = Math.random().toString(36);`).findings)).toContain("AEG-JS-009");
  });

  it("has unique ids and CWE mappings for every rule", () => {
    const all = ruleCatalog();
    expect(new Set(all.map((r) => r.id)).size).toBe(all.length);
    for (const r of all) expect(r.cwe.every((c) => /^CWE-\d+$/.test(c))).toBe(true);
    expect(PATTERN_RULES.length).toBeGreaterThan(70);
  });
});

describe("secret scanning", () => {
  it("detects provider tokens and redacts them", () => {
    const token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    const [f] = scan("config.ts", `const t = "${token}";`).findings;
    expect(f.ruleId).toBe("AEG-SEC-003");
    expect(f.snippet).not.toContain(token);
    expect(f.snippet).toContain("ghp_");
  });

  it("uses entropy for generic assignments and skips placeholders / env lookups", () => {
    expect(ids(scan("a.ts", `const apiKey = "Zx8#kQ2!vB9m@Lw4pR7t";`).findings)).toContain("AEG-SEC-100");
    expect(ids(scan("a.ts", `const apiKey = "your_api_key_here";`).findings)).toEqual([]);
    expect(ids(scan("a.ts", `const password = "aaaaaaaaaaaa";`).findings)).toEqual([]);
    expect(ids(scan("a.py", `SECRET = os.environ["SECRET"]`).findings)).toEqual([]);
  });

  it("finds credentials embedded in connection strings", () => {
    expect(ids(scan("db.ts", `const url = "postgres://admin:Sup3rS3cret@db.internal:5432/app";`).findings)).toContain("AEG-SEC-011");
  });

  it("computes Shannon entropy and redacts safely", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("abcd")).toBe(2);
    expect(redact("abc")).toBe("•••");
    expect(redact("sk_live_1234567890")).toMatch(/^sk_l•+90$/);
  });
});

describe("suppressions", () => {
  it("dismisses findings on the next line with a justification", () => {
    const r = scan("a.ts", `// aegis-ignore AEG-JS-010 -- used for cache keys only\nconst h = createHash("md5");`);
    expect(r.findings[0].status).toBe("dismissed");
    expect(r.findings[0].ruling?.rationale).toContain("cache keys only");
    expect(r.score).toBe(100);
  });

  it("supports file-wide suppression", () => {
    const r = scan("a.py", `# aegis-ignore-file -- fixtures\nyaml.load(x)\nhashlib.md5(b)`);
    expect(r.findings.every((f) => f.status === "dismissed")).toBe(true);
  });
});

describe("rendering safety", () => {
  it("sugar-high escapes HTML in untrusted source before we inject it", () => {
    const html = highlight(`const x = "<img src=x onerror=alert(1)>"; // </span><script>alert(1)</script>`);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});
