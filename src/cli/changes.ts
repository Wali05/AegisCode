import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, posix } from "node:path";
import { scanProject } from "../lib/engine";
import { detectLanguage } from "../lib/engine/language";
import { isManifest } from "../lib/deps/manifests";
import { checkPackages, extractPackageRefs } from "../lib/deps/packages";
import { diffFindings, type Comparison } from "../lib/baseline";

/**
 * Scans what changed instead of the whole repository, and reports only the
 * findings a change introduces. This is what runs in the pre-commit hook and
 * behind the MCP `scan_changes` tool: an agent (or a person) gets blocked on
 * the risk they just added, never on years of existing debt.
 */

export type ChangeMode = { kind: "staged" } | { kind: "working" } | { kind: "since"; ref: string };

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

function tryGit(cwd: string, args: string[]): string | null {
  try {
    return git(cwd, args);
  } catch {
    return null;
  }
}

export function repoRoot(cwd: string): string {
  const root = tryGit(cwd, ["rev-parse", "--show-toplevel"]);
  if (!root) throw new Error("Not inside a git repository.");
  return root.trim();
}

/** A changed file. `previous` is set when git detected a rename, so the old content can be found. */
export interface Change {
  path: string;
  previous?: string;
}

/**
 * Parses `git diff --name-status -z`. NUL-separated output is the only form in
 * which git prints paths verbatim: the default quotes anything non-ASCII
 * ("caf\303\251.js"), and such a file would then silently drop out of the scan.
 */
export function parseNameStatus(out: string | null): Change[] {
  const parts = (out ?? "").split("\0");
  const changes: Change[] = [];
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++];
    if (!status) continue;
    if (/^[RC]/.test(status)) {
      const from = parts[i++];
      const to = parts[i++];
      if (to) changes.push(status.startsWith("R") ? { path: to, previous: from } : { path: to });
    } else if (parts[i]) changes.push({ path: parts[i++] });
  }
  return changes;
}

const DIFF = ["diff", "--name-status", "-z", "-M", "--diff-filter=ACMR"];
const nulList = (out: string | null): Change[] => (out ?? "").split("\0").filter(Boolean).map((path) => ({ path }));

/** Later lists win, but a rename recorded by an earlier one is kept. */
function mergeChanges(...lists: Change[][]): Change[] {
  const byPath = new Map<string, Change>();
  for (const c of lists.flat()) byPath.set(c.path, { path: c.path, previous: c.previous ?? byPath.get(c.path)?.previous });
  return [...byPath.values()];
}

interface Snapshot {
  label: string;
  read: (path: string) => string | null;
}

/** Which files changed, and how to read each side of the change. */
function describe(root: string, mode: ChangeMode): { changes: Change[]; before: Snapshot; after: Snapshot } {
  const working: Snapshot = { label: "working tree", read: (p) => (existsSync(join(root, p)) ? readFileSync(join(root, p), "utf8") : null) };
  const atRev = (rev: string, label: string): Snapshot => ({ label, read: (p) => tryGit(root, ["show", `${rev}:${p}`]) });
  const hasHead = tryGit(root, ["rev-parse", "--verify", "HEAD"]) !== null;
  const head = hasHead ? atRev("HEAD", "HEAD") : { label: "empty repository", read: () => null };

  if (mode.kind === "staged") {
    return { changes: parseNameStatus(tryGit(root, [...DIFF, "--cached"])), before: head, after: atRev("", "staged changes") };
  }
  const untracked = () => nulList(tryGit(root, ["ls-files", "--others", "--exclude-standard", "-z"]));
  if (mode.kind === "working") {
    return { changes: mergeChanges(parseNameStatus(tryGit(root, [...DIFF, "HEAD"])), untracked()), before: head, after: working };
  }
  const base = tryGit(root, ["merge-base", mode.ref, "HEAD"])?.trim();
  if (!base) throw new Error(`Can't find a common ancestor with "${mode.ref}". Is the branch fetched?`);
  // Compare the merge base with the working tree in one step, so a file renamed
  // in one commit and edited in the next is still followed back to its old name.
  return { changes: mergeChanges(parseNameStatus(tryGit(root, [...DIFF, base])), untracked()), before: atRev(base, mode.ref), after: working };
}

const JS_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const MAX_CONTEXT = 80;

/**
 * Adds the local modules that changed files import (two levels deep), read from
 * the same snapshot, so a new route calling an unchanged helper is still traced
 * into the helper. Findings in context files go through the same before/after
 * comparison, so only flows the change creates are reported as new.
 */
function withImportedContext(files: Array<{ path: string; code: string }>, snap: Snapshot): Array<{ path: string; code: string }> {
  const out = new Map(files.map((f) => [f.path, f]));
  let frontier = files;
  for (let depth = 0; depth < 2 && out.size < MAX_CONTEXT; depth++) {
    const next: Array<{ path: string; code: string }> = [];
    for (const f of frontier) {
      if (!/\.[cm]?[jt]sx?$/.test(f.path)) continue;
      for (const m of f.code.matchAll(/(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](\.{1,2}\/[^"']+)["']/g)) {
        const base = posix.normalize(posix.join(posix.dirname(f.path), m[1])).replace(/\.[cm]?js$/, "");
        for (const candidate of [base, ...JS_EXT.map((e) => base + e), ...JS_EXT.map((e) => `${base}/index${e}`)]) {
          if (out.has(candidate)) break;
          const code = snap.read(candidate);
          if (code === null) continue;
          const file = { path: candidate, code };
          out.set(candidate, file);
          next.push(file);
          break;
        }
        if (out.size >= MAX_CONTEXT) break;
      }
    }
    frontier = next;
  }
  return [...out.values()];
}

export interface ChangeScan extends Comparison {
  files: string[];
  baseLabel: string;
  headLabel: string;
}

export async function scanChanges(cwd: string, mode: ChangeMode, opts: { packages?: boolean } = {}): Promise<ChangeScan> {
  const root = repoRoot(cwd);
  const { changes, before, after } = describe(root, mode);
  const relevant = changes.filter((c) => (detectLanguage(c.path) !== "unknown" && !/\.json$/i.test(c.path)) || isManifest(c.path)).slice(0, 400);

  // A renamed file is read from its old path but filed under its new one, so
  // the issues it already had are matched up instead of being reported as new.
  const load = (snap: Snapshot, side: "before" | "after") =>
    relevant.flatMap((c) => {
      const code = snap.read(side === "before" ? (c.previous ?? c.path) : c.path);
      return code === null || code.length > 500_000 ? [] : [{ path: c.path, code }];
    });
  const beforeFiles = withImportedContext(load(before, "before"), before);
  const afterFiles = withImportedContext(load(after, "after"), after);

  const refsOf = (files: Array<{ path: string; code: string }>) => files.flatMap((f) => extractPackageRefs(f.path, f.code, detectLanguage(f.path, f.code)));
  const scan = (files: Array<{ path: string; code: string }>) => scanProject(files.filter((f) => !/\.json$/.test(f.path) || isManifest(f.path))).flatMap((r) => r.findings);

  const baseFindings = scan(beforeFiles);
  const headFindings = scan(afterFiles);
  // Only packages this change starts depending on are looked up on the registry.
  if (opts.packages !== false) {
    const known = new Set(refsOf(beforeFiles).map((r) => `${r.file}|${r.name}`));
    const fresh = refsOf(afterFiles).filter((r) => !known.has(`${r.file}|${r.name}`));
    if (fresh.length) headFindings.push(...(await checkPackages(fresh)).findings);
  }

  return { files: relevant.map((c) => c.path), baseLabel: before.label, headLabel: after.label, ...diffFindings(baseFindings, headFindings) };
}
