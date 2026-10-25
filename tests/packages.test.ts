import { afterEach, describe, expect, it, vi } from "vitest";
import { checkPackages, editDistance, extractPackageRefs, lookalikeOf } from "../src/lib/deps/packages";

afterEach(() => vi.unstubAllGlobals());

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const DAY = 86_400_000;
const NOW = Date.parse("2026-10-25T00:00:00Z");

describe("package references", () => {
  it("finds third-party imports and ignores builtins, relative paths and local folders", () => {
    const code = `import a from "express";\nimport type { T } from "type-only-pkg";\nimport fs from "node:fs";\nimport path from "path";\nimport x from "./x";\nimport y from "@/lib/y";\nimport ui from "components/ui";\nconst z = require("@scope/pkg/sub");\nconst w = await import("dynamic-pkg");\nexport { v } from "reexported-pkg";`;
    const refs = extractPackageRefs("a.ts", code, "typescript", new Set(["components"]));
    expect(refs.map((r) => [r.name, r.line])).toEqual([
      ["express", 1],
      ["@scope/pkg", 8],
      ["dynamic-pkg", 9],
      ["reexported-pkg", 10],
    ]);
  });

  it("maps Python imports to distributions and skips the standard library", () => {
    const refs = extractPackageRefs("a.py", "import os, json\nimport yaml\nfrom sklearn.linear_model import X\nimport my_module\nfrom . import sibling\n", "python", new Set(["my_module"]));
    expect(refs.map((r) => r.name)).toEqual(["pyyaml", "scikit-learn"]);
  });

  it("ignores imports quoted inside strings", () => {
    const js = 'import real from "real-pkg";\nconst sample = `import fake from "fake-pkg";\nconst x = require("other-fake");`;\nconst s = \'import y from "quoted-pkg"\';';
    expect(extractPackageRefs("a.ts", js, "typescript").map((r) => r.name)).toEqual(["real-pkg"]);
    const py = 'import yaml\nDOC = """\nimport requestz\n"""\n';
    expect(extractPackageRefs("a.py", py, "python").map((r) => r.name)).toEqual(["pyyaml"]);
  });

  it("reads manifests", () => {
    const refs = extractPackageRefs("package.json", JSON.stringify({ dependencies: { "left-pad": "^1.3.0" } }, null, 2), "json");
    expect(refs).toEqual([expect.objectContaining({ name: "left-pad", via: "manifest", line: 3 })]);
  });
});

describe("lookalikes", () => {
  it("measures edit distance with transpositions", () => {
    expect(editDistance("lodash", "lodahs")).toBe(1);
    expect(editDistance("express", "expresss")).toBe(1);
    expect(editDistance("react", "preact", 2)).toBe(1);
  });

  it("flags typos of popular packages but not plugins or the real thing", () => {
    expect(lookalikeOf("lodahs", "npm")).toBe("lodash");
    expect(lookalikeOf("reactdom", "npm")).toBe("react-dom");
    expect(lookalikeOf("reqeusts", "PyPI")).toBe("requests");
    expect(lookalikeOf("express-validator", "npm")).toBeNull();
    expect(lookalikeOf("lodash", "npm")).toBeNull();
    expect(lookalikeOf("ms", "npm")).toBeNull();
  });
});

describe("registry check", () => {
  it("reports missing, fresh, lookalike, install-script and deprecated packages", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/ghost-pkg")) return new Response("", { status: 404 });
        if (url.endsWith("/fresh-pkg"))
          return json({ time: { created: new Date(NOW - 3 * DAY).toISOString() }, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { scripts: { postinstall: "node x.js" } } } });
        if (url.endsWith("/lodahs")) return json({ time: { created: "2019-01-01T00:00:00Z" }, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": {} }, repository: {} });
        if (url.endsWith("/old-pkg")) return json({ time: { created: "2015-01-01T00:00:00Z" }, "dist-tags": { latest: "2.0.0" }, versions: { "2.0.0": { deprecated: "use new-pkg" } }, repository: {} });
        return new Response("", { status: 500 });
      })
    );
    const refs = ["ghost-pkg", "fresh-pkg", "lodahs", "old-pkg", "react"].map((name, i) => ({ name, registry: "npm" as const, file: "a.ts", line: i + 1, snippet: `import x from "${name}"`, via: "import" as const }));
    const res = await checkPackages(refs, { now: NOW });
    expect(res).toMatchObject({ checked: 4, skippedPopular: 1, unreachable: 0, unchecked: [] });
    const byRule = (id: string) => res.findings.filter((f) => f.ruleId === id).map((f) => f.snippet.match(/"(.+)"/)![1]);
    expect(byRule("AEG-PKG-001")).toEqual(["ghost-pkg"]);
    expect(byRule("AEG-PKG-002")).toEqual(["lodahs"]);
    expect(byRule("AEG-PKG-003")).toEqual(["fresh-pkg"]);
    expect(byRule("AEG-PKG-004")).toEqual(["fresh-pkg"]);
    expect(byRule("AEG-PKG-005")).toEqual(["old-pkg"]);
    expect(res.findings.find((f) => f.ruleId === "AEG-PKG-003")!.severity).toBe("high"); // new and no repository link
  });

  it("degrades gracefully when the registry is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    const res = await checkPackages([{ name: "expresss", registry: "npm", file: "a.ts", line: 1, snippet: "x", via: "import" }]);
    expect(res.unreachable).toBe(1);
    expect(res.unchecked).toEqual(["expresss"]);
    expect(res.findings.map((f) => f.ruleId)).toEqual(["AEG-PKG-002"]);
  });
});
