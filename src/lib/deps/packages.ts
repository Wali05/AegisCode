import { builtinModules } from "node:module";
import type { Finding, Language, RuleMeta } from "../engine/types";
import { makeFinding } from "../engine/finding";
import { buildViews } from "../engine/lexer";
import { OWASP } from "../engine/rules/patterns";
import { mapLimit, LruCache } from "../util/concurrency";
import { parseManifest } from "./manifests";
import { POPULAR_NPM, POPULAR_PYPI, PY_IMPORT_TO_DIST, PY_STDLIB } from "./popular";

/**
 * Package check for AI-written code.
 *
 * Coding assistants regularly import packages that don't exist. Attackers
 * register those names ("slopsquatting"), so the next `npm install` pulls in
 * their code. This module finds every package a file imports or a manifest
 * declares, and checks each one against the real npm / PyPI registries for:
 * nonexistent names, lookalikes of popular packages, very recent first
 * publication, install-time scripts, and deprecation.
 */

export type Registry = "npm" | "PyPI";

export interface PackageRef {
  name: string;
  registry: Registry;
  file: string;
  line: number;
  snippet: string;
  via: "import" | "manifest";
}

const base = { category: "dependency" as const, owasp: OWASP.supplyChain, languages: "*" as const, detector: "supply" as const };

export const PACKAGE_RULES = {
  missing: {
    ...base,
    id: "AEG-PKG-001",
    title: "Package does not exist on the registry",
    severity: "high",
    cwe: ["CWE-1357", "CWE-829"],
    description:
      "The code depends on a package name that the public registry has never published. AI assistants invent names like this; attackers watch for them and register them with malicious code, so the next install would run it.",
    remediation: "Find the real package that provides this functionality and depend on that, or remove the import. If it is a private package, make sure your registry is configured so the public name can't shadow it.",
  },
  lookalike: {
    ...base,
    id: "AEG-PKG-002",
    title: "Package name is a lookalike of a popular package",
    severity: "high",
    cwe: ["CWE-1357"],
    description: "The name is one or two characters away from a widely used package, a classic typosquatting pattern.",
    remediation: "Double-check the spelling. If you meant the popular package, switch to it; if this one is intentional, pin it and review its source.",
  },
  fresh: {
    ...base,
    id: "AEG-PKG-003",
    title: "Package was first published very recently",
    severity: "medium",
    cwe: ["CWE-1357"],
    description: "Brand-new packages have no track record. Combined with an AI-suggested import, this is how slopsquatted packages look.",
    remediation: "Review the package's source, maintainer and repository before installing, or wait until it has some history.",
  },
  installScript: {
    ...base,
    id: "AEG-PKG-004",
    title: "Package runs a script at install time",
    severity: "low",
    cwe: ["CWE-829"],
    description: "The latest version declares preinstall / install / postinstall scripts, which run with your user's permissions during `npm install`.",
    remediation: "Install with `--ignore-scripts` where possible and review what the script does.",
  },
  deprecated: {
    ...base,
    id: "AEG-PKG-005",
    title: "Package is deprecated or yanked",
    severity: "low",
    cwe: ["CWE-1104"],
    description: "The maintainers have marked the latest release as deprecated or yanked it.",
    remediation: "Move to the replacement the maintainers recommend.",
  },
} satisfies Record<string, RuleMeta>;

export const PACKAGE_RULE_LIST: RuleMeta[] = Object.values(PACKAGE_RULES);

const NODE_BUILTINS = new Set(builtinModules.flatMap((m) => [m, m.replace(/^node:/, "")]));
const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const POPULAR: Record<Registry, Set<string>> = { npm: new Set(POPULAR_NPM), PyPI: new Set(POPULAR_PYPI) };
const FRESH_DAYS = 30;

function npmPackageName(spec: string): string | null {
  if (/^(?:\.|\/|#|~\/|@\/|node:|virtual:|https?:|data:)/.test(spec)) return null;
  const parts = spec.split("/");
  const name = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  if (!NPM_NAME.test(name) || NODE_BUILTINS.has(name)) return null;
  return name;
}

/**
 * Finds third-party packages referenced by a source file or manifest.
 * `localRoots` holds top-level folder / module names of the project, so
 * `import x from "components/x"` (a baseUrl import) isn't mistaken for a package.
 */
export function extractPackageRefs(path: string, code: string, lang: Language, localRoots: Set<string> = new Set()): PackageRef[] {
  const out: PackageRef[] = [];
  const lines = code.split("\n");

  const deps = parseManifest(path, code);
  if (deps.length) {
    for (const d of deps) {
      if (d.ecosystem !== "npm" && d.ecosystem !== "PyPI") continue;
      out.push({ name: d.name, registry: d.ecosystem, file: path, line: d.line ?? 1, snippet: (lines[(d.line ?? 1) - 1] ?? d.name).trim(), via: "manifest" });
    }
    return out;
  }

  if (lang === "javascript" || lang === "typescript") {
    // Match statements on the view with string contents blanked, so code quoted
    // inside a string or template literal isn't mistaken for a real import, then
    // read the specifier back from the same offsets in the unmasked text.
    const { noComments, codeOnly: text } = buildViews(code, lang);
    const re = /(?:\bimport\s+(?:type\s+)?[^'"`;]*?\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+|\bexport\s+[^'"`;]*?\bfrom\s*)(['"])([^'"\n]+)\1/g;
    for (const m of text.matchAll(re)) {
      if (/^\s*import\s+type\b/.test(m[0])) continue;
      const end = m.index + m[0].length - 1;
      const name = npmPackageName(noComments.slice(end - m[2].length, end));
      if (!name || localRoots.has(name.split("/")[0])) continue;
      const line = text.slice(0, m.index).split("\n").length;
      out.push({ name, registry: "npm", file: path, line, snippet: lines[line - 1]?.trim() ?? m[0], via: "import" });
    }
  } else if (lang === "python") {
    const text = buildViews(code, lang).codeOnly;
    for (const m of text.matchAll(/^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b|import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*))/gm)) {
      const modules = m[1] ? [m[1]] : m[2].split(",").map((s) => s.trim().split(/\s+as\s+/)[0]);
      const line = text.slice(0, m.index).split("\n").length;
      for (const mod of modules) {
        const root = mod.split(".")[0];
        if (!root || PY_STDLIB.has(root) || localRoots.has(root)) continue;
        out.push({ name: PY_IMPORT_TO_DIST[root] ?? root.toLowerCase().replace(/_/g, "-"), registry: "PyPI", file: path, line, snippet: lines[line - 1]?.trim() ?? mod, via: "import" });
      }
    }
  }
  return out;
}

/** Optimal string alignment distance (Levenshtein + adjacent transpositions), capped at `max + 1`. */
export function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}

/** The popular package `name` imitates, if any. */
export function lookalikeOf(name: string, registry: Registry): string | null {
  if (POPULAR[registry].has(name)) return null;
  const bare = name.replace(/^@[^/]+\//, "");
  const squash = (s: string) => s.toLowerCase().replace(/[-_.]/g, "");
  for (const p of POPULAR[registry]) {
    const pBare = p.replace(/^@[^/]+\//, "");
    if (bare === pBare) continue; // same name under a different scope is a fork, not a typo
    if (name.startsWith(`${p}-`) || name.startsWith(`@${p}/`)) continue; // plugins and extensions
    if (squash(bare) === squash(pBare)) return p;
    const dist = editDistance(bare, pBare, 2);
    if ((dist === 1 && pBare.length >= 5) || (dist === 2 && pBare.length >= 9)) return p;
  }
  return null;
}

interface RegistryInfo {
  exists: boolean;
  created?: string;
  installScripts?: string[];
  deprecated?: string;
  repository?: boolean;
}

const cache = new LruCache<RegistryInfo>(2000, 6 * 60 * 60_000);

async function fetchJson(url: string, signal?: AbortSignal): Promise<{ status: number; body?: Record<string, unknown> }> {
  const res = await fetch(url, { headers: { Accept: "application/json", "User-Agent": "AegisCode" }, signal: signal ?? AbortSignal.timeout(8000) });
  if (res.status === 404) return { status: 404 };
  if (!res.ok) throw new Error(`registry ${res.status}`);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

async function lookup(name: string, registry: Registry, signal?: AbortSignal): Promise<RegistryInfo> {
  const key = `${registry}:${name}`;
  const hit = cache.get(key);
  if (hit) return hit;
  let info: RegistryInfo;
  if (registry === "npm") {
    const { status, body } = await fetchJson(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, signal);
    if (status === 404 || !body) info = { exists: false };
    else {
      const time = body.time as Record<string, string> | undefined;
      const latestTag = (body["dist-tags"] as Record<string, string> | undefined)?.latest;
      const latest = latestTag ? (body.versions as Record<string, { scripts?: Record<string, string>; deprecated?: string }> | undefined)?.[latestTag] : undefined;
      info = {
        exists: true,
        created: time?.created,
        installScripts: Object.keys(latest?.scripts ?? {}).filter((s) => /^(?:pre|post)?install$/.test(s)),
        deprecated: latest?.deprecated,
        repository: !!body.repository,
      };
    }
  } else {
    const { status, body } = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, signal);
    if (status === 404 || !body) info = { exists: false };
    else {
      const releases = body.releases as Record<string, Array<{ upload_time_iso_8601?: string; upload_time?: string; yanked?: boolean }>>;
      const uploads = Object.values(releases ?? {}).flat();
      const times = uploads.map((u) => u.upload_time_iso_8601 ?? u.upload_time).filter(Boolean).sort() as string[];
      const urls = (body.urls as Array<{ yanked?: boolean }>) ?? [];
      info = { exists: true, created: times[0], deprecated: urls.length && urls.every((u) => u.yanked) ? "latest release is yanked" : undefined, repository: true };
    }
  }
  cache.set(key, info);
  return info;
}

export interface PackageCheck {
  checked: number;
  skippedPopular: number;
  unreachable: number;
  /** Names that could not be looked up (registry unreachable) — never report these as safe. */
  unchecked: string[];
  findings: Finding[];
}

/** Checks each distinct package once (first reference wins) against its registry. */
export async function checkPackages(refs: PackageRef[], opts: { signal?: AbortSignal; now?: number; limit?: number } = {}): Promise<PackageCheck> {
  const now = opts.now ?? Date.now();
  const unique = [...new Map(refs.map((r) => [`${r.registry}:${r.name}`, r])).values()];
  const toCheck = unique.filter((r) => !POPULAR[r.registry].has(r.name)).slice(0, opts.limit ?? 80);
  const findings: Finding[] = [];
  const unchecked: string[] = [];

  const emit = (rule: RuleMeta, ref: PackageRef, confidence: number, extra: { title?: string; description?: string; severity?: Finding["severity"] } = {}) => {
    findings.push(
      makeFinding({
        rule,
        file: ref.file,
        location: { line: ref.line, column: 1, endLine: ref.line, endColumn: ref.snippet.length + 1 },
        snippet: ref.snippet,
        confidence,
        detector: "supply",
        ...extra,
      })
    );
  };

  await mapLimit(toCheck, 8, async (ref) => {
    const similar = lookalikeOf(ref.name, ref.registry);
    let info: RegistryInfo;
    try {
      info = await lookup(ref.name, ref.registry, opts.signal);
    } catch {
      unchecked.push(ref.name);
      if (similar) emit(PACKAGE_RULES.lookalike, ref, 0.6, { title: `\`${ref.name}\` looks like \`${similar}\`` });
      return;
    }
    const where = ref.registry === "npm" ? "npm" : "PyPI";

    if (!info.exists) {
      const scoped = ref.name.startsWith("@");
      emit(PACKAGE_RULES.missing, ref, scoped ? 0.55 : ref.via === "manifest" ? 0.95 : 0.85, {
        title: `\`${ref.name}\` does not exist on ${where}${similar ? ` (did you mean \`${similar}\`?)` : ""}`,
        severity: scoped ? "medium" : "high",
        description: scoped ? `${PACKAGE_RULES.missing.description} Scoped names are often private packages, so check whether this one comes from your own registry.` : undefined,
      });
      return;
    }

    if (similar) emit(PACKAGE_RULES.lookalike, ref, 0.75, { title: `\`${ref.name}\` looks like \`${similar}\`` });

    const ageDays = info.created ? (now - Date.parse(info.created)) / 86_400_000 : Infinity;
    if (ageDays < FRESH_DAYS) {
      emit(PACKAGE_RULES.fresh, ref, 0.7, {
        title: `\`${ref.name}\` was first published ${Math.max(0, Math.round(ageDays))} day${Math.round(ageDays) === 1 ? "" : "s"} ago`,
        severity: similar || !info.repository ? "high" : "medium",
      });
    }
    if (info.installScripts?.length) {
      emit(PACKAGE_RULES.installScript, ref, 0.8, {
        title: `\`${ref.name}\` runs ${info.installScripts.join(" / ")} on install`,
        severity: ageDays < FRESH_DAYS || similar ? "medium" : "low",
      });
    }
    if (info.deprecated) emit(PACKAGE_RULES.deprecated, ref, 0.9, { title: `\`${ref.name}\` is deprecated`, description: `${PACKAGE_RULES.deprecated.description} Note from the maintainers: "${info.deprecated.slice(0, 160)}"` });
  });

  return { checked: toCheck.length - unchecked.length, skippedPopular: unique.length - toCheck.length, unreachable: unchecked.length, unchecked, findings };
}
