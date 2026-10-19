import { describe, expect, it } from "vitest";
import { ids, scan } from "./helpers";
import { aggregateScore, gradeFor, securityScore } from "../src/lib/engine/score";
import { maintainabilityIndex } from "../src/lib/engine/metrics";
import type { Finding } from "../src/lib/engine/types";

describe("metrics", () => {
  it("computes per-function cyclomatic complexity from the AST", () => {
    const r = scan("a.ts", `function f(a, b) {\n  if (a && b) return 1;\n  for (const x of a) { if (x) continue; }\n  return a ?? b;\n}`);
    const fn = r.metrics.functions.find((m) => m.name === "f")!;
    expect(fn.complexity).toBe(6); // 1 + if + && + for + if + ??
    expect(fn.maxNesting).toBe(2);
    expect(fn.params).toBe(2);
  });

  it("extracts Python and Go functions lexically", () => {
    const py = scan("a.py", `def a(x, y):\n    if x:\n        return y\n    return x\n\ndef b(self):\n    pass\n`);
    expect(py.metrics.functions.map((f) => [f.name, f.complexity, f.params])).toEqual([["a", 2, 2], ["b", 1, 0]]);
    const go = scan("a.go", `package m\nfunc Add(a int, b int) int {\n  if a > 0 && b > 0 { return a + b }\n  return 0\n}`);
    expect(go.metrics.functions[0]).toMatchObject({ name: "Add", complexity: 3, params: 2 });
  });

  it("keeps the maintainability index in range", () => {
    expect(maintainabilityIndex(0, 1, 0)).toBe(100);
    const mi = maintainabilityIndex(5000, 40, 400);
    expect(mi).toBeGreaterThanOrEqual(0);
    expect(mi).toBeLessThan(50);
  });
});

describe("quality checks", () => {
  it("flags O(n²) lookups, sequential awaits and unbounded caches", () => {
    const code = `const cache = new Map();\nexport async function sync(users, admins) {\n  for (const u of users) {\n    if (admins.includes(u.id)) await notify(u);\n  }\n  cache.set(users[0].id, users);\n}`;
    const found = ids(scan("a.ts", code).findings);
    expect(found).toEqual(expect.arrayContaining(["AEG-PERF-001", "AEG-PERF-002", "AEG-MEM-001"]));
  });

  it("flags effects that never clean up", () => {
    expect(ids(scan("c.tsx", `useEffect(() => { window.addEventListener("resize", f); }, []);`).findings)).toContain("AEG-MEM-002");
    expect(ids(scan("c.tsx", `useEffect(() => { window.addEventListener("resize", f); return () => window.removeEventListener("resize", f); }, []);`).findings)).toEqual([]);
  });
});

describe("scoring and triage", () => {
  const f = (severity: Finding["severity"], extra: Partial<Finding> = {}): Finding =>
    ({ id: Math.random().toString(), ruleId: "X", title: "", description: "", severity, confidence: 1, category: "injection", cwe: [], file: "a", location: { line: 1, column: 1, endLine: 1, endColumn: 1 }, snippet: "", remediation: "", detector: "pattern", status: "open", ...extra }) as Finding;

  it("caps scores by worst severity and ignores dismissed findings", () => {
    expect(securityScore([])).toBe(100);
    expect(securityScore([f("critical")])).toBeLessThanOrEqual(59);
    expect(securityScore([f("high")])).toBeLessThanOrEqual(79);
    expect(securityScore([f("critical", { status: "dismissed" })])).toBe(100);
    expect(securityScore(Array.from({ length: 40 }, () => f("low")))).toBeGreaterThan(securityScore([f("critical")]));
  });

  it("weights quality findings below security findings", () => {
    expect(securityScore([f("medium", { detector: "metric" })])).toBeGreaterThan(securityScore([f("medium")]));
  });

  it("aggregates repositories by SLOC instead of summing penalties", () => {
    const files = Array.from({ length: 30 }, () => ({ score: 90, metrics: { sloc: 100 } as never }));
    expect(aggregateScore(files)).toBe(90);
    expect(aggregateScore(files, [], [f("critical")])).toBe(59);
  });

  it("maps scores to grades", () => {
    expect([95, 85, 70, 50, 10].map(gradeFor)).toEqual(["A", "B", "C", "D", "F"]);
  });

  it("escalates risky files and lets clean ones skip the LLM", () => {
    const risky = scan("routes/api.ts", `app.get("/", (req) => db.query("SELECT " + req.query.id));`);
    expect(risky.triage.escalate).toBe(true);
    expect(risky.triage.signals[0].label).toMatch(/source→sink|critical/);
    const clean = scan("util.ts", `export const add = (a: number, b: number) => a + b;`);
    expect(clean.triage.escalate).toBe(false);
    expect(clean.score).toBe(100);
  });
});
