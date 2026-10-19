/**
 * Dependency manifest parsers. Each returns exact (name, version) pairs that
 * can be checked against the OSV vulnerability database.
 */

export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "RubyGems" | "Packagist";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Where the version came from: an exact lockfile pin or a manifest range floor. */
  exact: boolean;
  manifest: string;
  line?: number;
}

const MANIFESTS: Array<{ test: RegExp; parse: (text: string, path: string) => Dependency[] }> = [
  { test: /(^|\/)package-lock\.json$/, parse: parsePackageLock },
  { test: /(^|\/)package\.json$/, parse: parsePackageJson },
  { test: /(^|\/)(?:requirements[\w.-]*\.txt|constraints\.txt)$/, parse: parseRequirements },
  { test: /(^|\/)go\.mod$/, parse: parseGoMod },
  { test: /(^|\/)Cargo\.lock$/, parse: parseCargoLock },
  { test: /(^|\/)Gemfile\.lock$/, parse: parseGemfileLock },
  { test: /(^|\/)composer\.lock$/, parse: parseComposerLock },
];

export function isManifest(path: string): boolean {
  return MANIFESTS.some((m) => m.test.test(path));
}

export function parseManifest(path: string, text: string): Dependency[] {
  const handler = MANIFESTS.find((m) => m.test.test(path));
  if (!handler) return [];
  try {
    return handler.parse(text, path);
  } catch {
    return [];
  }
}

function lineOf(text: string, needle: string): number | undefined {
  const idx = text.indexOf(needle);
  return idx === -1 ? undefined : text.slice(0, idx).split("\n").length;
}

/** Turns "^1.2.3", "~1.2", ">=2.0.0 <3" into the lowest version the range admits. */
export function rangeFloor(range: string): string | null {
  const m = /(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(-[\w.]+)?/.exec(range.trim());
  if (!m || /^(?:file:|link:|git|http|workspace:|npm:)/.test(range)) return null;
  const part = (p?: string) => (p && /^\d+$/.test(p) ? p : "0");
  return `${m[1]}.${part(m[2])}.${part(m[3])}${m[4] ?? ""}`;
}

function parsePackageLock(text: string, path: string): Dependency[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; link?: boolean }>;
    dependencies?: Record<string, { version?: string }>;
  };
  const out = new Map<string, Dependency>();
  if (lock.packages) {
    for (const [key, meta] of Object.entries(lock.packages)) {
      if (!key || meta.link || !meta.version) continue;
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      out.set(`${name}@${meta.version}`, { name, version: meta.version, ecosystem: "npm", exact: true, manifest: path });
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) {
      if (meta.version) out.set(`${name}@${meta.version}`, { name, version: meta.version, ecosystem: "npm", exact: true, manifest: path });
    }
  }
  return [...out.values()];
}

function parsePackageJson(text: string, path: string): Dependency[] {
  const pkg = JSON.parse(text) as Record<string, Record<string, string> | undefined>;
  const out: Dependency[] = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, range] of Object.entries(pkg[field] ?? {})) {
      const version = rangeFloor(range);
      if (version) out.push({ name, version, ecosystem: "npm", exact: /^\d/.test(range.trim()), manifest: path, line: lineOf(text, `"${name}"`) });
    }
  }
  return out;
}

function parseRequirements(text: string, path: string): Dependency[] {
  const out: Dependency[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) return;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==|>=|~=|===)\s*([\w.!+-]+)/.exec(line);
    if (m) out.push({ name: m[1].toLowerCase(), version: m[3], ecosystem: "PyPI", exact: m[2] === "==" || m[2] === "===", manifest: path, line: i + 1 });
  });
  return out;
}

function parseGoMod(text: string, path: string): Dependency[] {
  const out: Dependency[] = [];
  let inBlock = false;
  text.split("\n").forEach((raw, i) => {
    const line = raw.split("//")[0].trim();
    if (/^require\s*\($/.test(line)) return void (inBlock = true);
    if (inBlock && line === ")") return void (inBlock = false);
    const m = (inBlock ? /^(\S+)\s+(v[\w.+-]+)/ : /^require\s+(\S+)\s+(v[\w.+-]+)/).exec(line);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: "Go", exact: true, manifest: path, line: i + 1 });
  });
  return out;
}

function parseCargoLock(text: string, path: string): Dependency[] {
  const out: Dependency[] = [];
  for (const block of text.split("[[package]]").slice(1)) {
    const name = /name\s*=\s*"([^"]+)"/.exec(block)?.[1];
    const version = /version\s*=\s*"([^"]+)"/.exec(block)?.[1];
    if (name && version && /source\s*=/.test(block)) out.push({ name, version, ecosystem: "crates.io", exact: true, manifest: path });
  }
  return out;
}

function parseGemfileLock(text: string, path: string): Dependency[] {
  const out: Dependency[] = [];
  const specs = text.split(/^\s*specs:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
  for (const m of specs.matchAll(/^ {4}([\w.-]+) \(([\w.]+)\)$/gm)) {
    out.push({ name: m[1], version: m[2], ecosystem: "RubyGems", exact: true, manifest: path });
  }
  return out;
}

function parseComposerLock(text: string, path: string): Dependency[] {
  const lock = JSON.parse(text) as { packages?: Array<{ name: string; version: string }>; "packages-dev"?: Array<{ name: string; version: string }> };
  return [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])].map((p) => ({
    name: p.name,
    version: p.version.replace(/^v/, ""),
    ecosystem: "Packagist" as const,
    exact: true,
    manifest: path,
  }));
}
