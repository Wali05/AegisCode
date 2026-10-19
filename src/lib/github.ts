import { isAnalyzablePath } from "./engine/language";
import { isManifest } from "./deps/manifests";

export type GitHubTarget =
  | { kind: "file"; owner: string; repo: string; segments: string[] }
  | { kind: "repo"; owner: string; repo: string; segments: string[] };

export class GitHubError extends Error {
  constructor(message: string, readonly status: number, readonly hint?: string) {
    super(message);
  }
}

const NAME = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * Parses any GitHub URL a user is likely to paste:
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo/tree/feat/x/src
 *   https://github.com/owner/repo/blob/main/src/index.ts
 *   https://raw.githubusercontent.com/owner/repo/main/src/index.ts
 *   owner/repo
 * Branch names may contain slashes, so ref and path are resolved later against GitHub.
 */
export function parseGitHubUrl(input: string): GitHubTarget {
  const raw = input.trim();
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(raw)) {
    const [owner, repo] = raw.split("/");
    return { kind: "repo", owner, repo: repo.replace(/\.git$/, ""), segments: [] };
  }
  let url: URL;
  try {
    url = new URL(raw.startsWith("http") ? raw : `https://${raw}`);
  } catch {
    throw new GitHubError("That doesn't look like a URL.", 400, "Paste a link such as https://github.com/owner/repo/blob/main/src/app.ts");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new GitHubError("Only http(s) GitHub URLs are supported.", 400);
  const host = url.hostname.toLowerCase();
  const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);

  if (host === "raw.githubusercontent.com") {
    if (parts.length < 4) throw new GitHubError("Raw URLs must include owner, repo, ref and a file path.", 400);
    const [owner, repo, ...rest] = parts;
    assertNames(owner, repo);
    return { kind: "file", owner, repo, segments: rest[0] === "refs" && rest[1] === "heads" ? rest.slice(2) : rest };
  }

  if (host !== "github.com" && host !== "www.github.com") {
    throw new GitHubError("Only github.com and raw.githubusercontent.com links are supported.", 400);
  }
  if (parts.length < 2) throw new GitHubError("The URL must point to a repository or a file.", 400, "Example: https://github.com/owner/repo");
  const [owner, repoRaw, kind, ...rest] = parts;
  const repo = repoRaw.replace(/\.git$/, "");
  assertNames(owner, repo);

  if (!kind) return { kind: "repo", owner, repo, segments: [] };
  if (kind === "blob" && rest.length >= 2) return { kind: "file", owner, repo, segments: rest };
  if (kind === "tree" && rest.length >= 1) return { kind: "repo", owner, repo, segments: rest };
  throw new GitHubError("Unsupported GitHub URL. Link to a repository, a /tree/ folder, or a /blob/ file.", 400);
}

function assertNames(owner: string, repo: string) {
  if (!NAME.test(owner) || !NAME.test(repo)) throw new GitHubError("Invalid owner or repository name.", 400);
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

export interface GitHubClientOptions {
  token?: string;
  signal?: AbortSignal;
}

const enc = (p: string) => p.split("/").map(encodeURIComponent).join("/");

export class GitHubClient {
  /** Set when GitHub rejects the configured token; later calls go out anonymously. */
  private tokenRejected = false;

  constructor(private opts: GitHubClientOptions = {}) {}

  get authenticated(): boolean {
    return !!this.opts.token && !this.tokenRejected;
  }

  private auth(): Record<string, string> {
    return this.authenticated ? { Authorization: `Bearer ${this.opts.token}` } : {};
  }

  /** Fetch with the token, falling back to an anonymous request if the token is rejected (public repos still work). */
  private async request(url: string, headers: Record<string, string>): Promise<Response> {
    const signal = this.opts.signal ?? AbortSignal.timeout(15_000);
    const res = await fetch(url, { headers: { ...headers, ...this.auth() }, signal });
    if (res.status === 401 && this.authenticated) {
      this.tokenRejected = true;
      return fetch(url, { headers, signal });
    }
    return res;
  }

  private async api<T>(path: string): Promise<T> {
    const res = await this.request(`https://api.github.com${path}`, { Accept: "application/vnd.github+json", "User-Agent": "AegisCode", "X-GitHub-Api-Version": "2022-11-28" });
    if (res.ok) return (await res.json()) as T;
    throw this.toError(res);
  }

  private toError(res: Response): GitHubError {
    if (res.status === 404) return new GitHubError("Not found on GitHub.", 404, this.authenticated ? "Check the URL and that the token can read this repository." : "Private repositories need a GITHUB_TOKEN on the server.");
    if ((res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0") {
      const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
      const mins = reset ? Math.max(1, Math.ceil((reset - Date.now()) / 60_000)) : 60;
      return new GitHubError("GitHub API rate limit reached.", 429, `Resets in ~${mins} min. Set GITHUB_TOKEN to raise the limit to 5,000 requests/hour.`);
    }
    return new GitHubError(`GitHub responded with ${res.status}.`, 502);
  }

  /** Fetches raw file content. Uses raw.githubusercontent.com (no API quota). */
  async raw(owner: string, repo: string, ref: string, path: string): Promise<string | null> {
    const url = `https://raw.githubusercontent.com/${enc(owner)}/${enc(repo)}/${enc(ref)}/${enc(path)}`;
    let res = await this.request(url, { "User-Agent": "AegisCode" });
    // raw.githubusercontent answers 404 (not 401) for a token it doesn't accept; public files still load anonymously.
    if (res.status === 404 && this.authenticated) res = await fetch(url, { signal: this.opts.signal ?? AbortSignal.timeout(15_000) });
    if (res.status === 404) return null;
    if (!res.ok) throw this.toError(res);
    return res.text();
  }

  /**
   * Resolves `segments` (ref + path joined by "/") to a concrete file. Raw URLs
   * resolve slashed branch names server-side, so one fetch gets the right content;
   * the ref/path split (used for labels and commit lookup) is then confirmed via
   * the branches API, longest candidate first, falling back to a single-segment ref.
   */
  async resolveFile(owner: string, repo: string, segments: string[]): Promise<{ ref: string; path: string; content: string }> {
    const content = await this.raw(owner, repo, segments[0], segments.slice(1).join("/"));
    if (content === null) {
      throw new GitHubError("File not found on GitHub.", 404, this.authenticated ? "Check the branch and path in the URL." : "If the repository is private, set GITHUB_TOKEN on the server.");
    }
    // Common branch names, SHAs and version tags can't be the start of a slashed branch — skip the API probes.
    const plain = /^(?:main|master|develop|dev|trunk|HEAD|[0-9a-f]{7,40}|v?\d[\w.-]*)$/.test(segments[0]);
    for (let k = plain ? 0 : Math.min(segments.length - 1, 5); k >= 2; k--) {
      const ref = segments.slice(0, k).join("/");
      try {
        await this.api(`/repos/${enc(owner)}/${enc(repo)}/branches/${enc(ref)}`);
        return { ref, path: segments.slice(k).join("/"), content };
      } catch {
        /* not a branch — try a shorter prefix */
      }
    }
    return { ref: segments[0], path: segments.slice(1).join("/"), content };
  }

  async lastCommit(owner: string, repo: string, ref: string, path: string): Promise<CommitInfo | null> {
    try {
      const commits = await this.api<Array<{ sha: string; html_url: string; commit: { message: string; author?: { name?: string; date?: string } }; author?: { login?: string; avatar_url?: string } | null }>>(
        `/repos/${enc(owner)}/${enc(repo)}/commits?sha=${encodeURIComponent(ref)}&path=${encodeURIComponent(path)}&per_page=1`
      );
      const c = commits[0];
      if (!c) return null;
      return {
        sha: c.sha,
        url: c.html_url,
        message: c.commit.message.split("\n")[0].slice(0, 140),
        author: c.author?.login ?? c.commit.author?.name ?? "unknown",
        avatar: c.author?.avatar_url,
        date: c.commit.author?.date,
      };
    } catch {
      return null; // purely decorative; never fail an audit over it
    }
  }

  async repoInfo(owner: string, repo: string): Promise<RepoInfo> {
    const r = await this.api<{ default_branch: string; stargazers_count: number; description: string | null; language: string | null; html_url: string; private: boolean }>(`/repos/${enc(owner)}/${enc(repo)}`);
    return { defaultBranch: r.default_branch, stars: r.stargazers_count, description: r.description, language: r.language, url: r.html_url, private: r.private };
  }

  async tree(owner: string, repo: string, ref: string): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
    const t = await this.api<{ tree: Array<{ path: string; type: string; size?: number; sha: string }>; truncated: boolean }>(`/repos/${enc(owner)}/${enc(repo)}/git/trees/${encodeURIComponent(ref)}?recursive=1`);
    return { entries: t.tree.filter((e) => e.type === "blob").map((e) => ({ path: e.path, size: e.size ?? 0, sha: e.sha })), truncated: t.truncated };
  }

  /** Resolves `/tree/<ref...>/<subpath>` segments against the repository's branch list. */
  async resolveTreeRef(owner: string, repo: string, segments: string[], defaultBranch: string): Promise<{ ref: string; subpath: string }> {
    if (!segments.length) return { ref: defaultBranch, subpath: "" };
    for (let k = Math.min(segments.length, 5); k >= 1; k--) {
      const ref = segments.slice(0, k).join("/");
      try {
        await this.api(`/repos/${enc(owner)}/${enc(repo)}/branches/${enc(ref)}`);
        return { ref, subpath: segments.slice(k).join("/") };
      } catch {
        /* try a shorter prefix */
      }
    }
    return { ref: segments[0], subpath: segments.slice(1).join("/") };
  }
}

export interface CommitInfo {
  sha: string;
  url: string;
  message: string;
  author: string;
  avatar?: string;
  date?: string;
}

export interface RepoInfo {
  defaultBranch: string;
  stars: number;
  description: string | null;
  language: string | null;
  url: string;
  private: boolean;
}

export interface TreeEntry {
  path: string;
  size: number;
  sha: string;
}

// ─── Repository file selection ───────────────────────────────────────────────

const EXCLUDED_DIR = /(^|\/)(?:node_modules|vendor|dist|build|out|\.next|\.nuxt|coverage|\.git|__pycache__|\.venv|venv|env|target|bin|obj|third_party|bower_components|\.yarn|\.pnpm-store|storybook-static|public\/static|site-packages|Pods|DerivedData)(\/|$)/;
const EXCLUDED_FILE = /\.(?:min\.js|bundle\.js|map|d\.ts|lock|snap|pb\.go)$|_pb2\.py$|(?:^|\/)(?:pnpm-lock\.yaml|yarn\.lock)$/;
const HOT_PATH = /auth|login|logout|session|token|jwt|oauth|passw|crypto|secret|admin|payment|billing|checkout|stripe|upload|download|file|exec|shell|command|query|sql|db|database|model|api|route|router|controller|handler|middleware|webhook|server|proxy|redirect|user|account|search|render|template|eval|sandbox/gi;
const ENTRYPOINT = /(?:^|\/)(?:server|app|index|main|routes?|api|handler|views?|controllers?)\.[a-z]+$|(?:^|\/)(?:api|routes|controllers|handlers|pages\/api|app\/api)\//i;
const LOW_VALUE = /(?:^|\/)(?:tests?|__tests__|spec|e2e|fixtures?|examples?|samples?|docs?|demo|scripts|migrations|stories)\/|\.(?:test|spec|stories)\.[a-z]+$/i;

export interface SelectedFiles {
  sources: TreeEntry[];
  manifests: TreeEntry[];
  skipped: number;
  considered: number;
}

/** Ranks repository files by audit value and picks the top `limit`. */
export function selectFiles(entries: TreeEntry[], limit: number, subpath = ""): SelectedFiles {
  const scoped = subpath ? entries.filter((e) => e.path === subpath || e.path.startsWith(subpath.replace(/\/$/, "") + "/")) : entries;
  const candidates = scoped.filter((e) => !EXCLUDED_DIR.test(e.path) && !EXCLUDED_FILE.test(e.path));

  const manifests = candidates
    .filter((e) => isManifest(e.path))
    .filter((e, _, all) => {
      // A lockfile beats its package.json.
      if (!/package\.json$/.test(e.path)) return true;
      const dir = e.path.slice(0, e.path.lastIndexOf("/") + 1);
      return !all.some((o) => o.path === `${dir}package-lock.json`);
    })
    .sort((a, b) => a.path.split("/").length - b.path.split("/").length)
    .slice(0, 6);

  const sources = candidates
    .filter((e) => isAnalyzablePath(e.path) && !/\.json$/.test(e.path) && e.size > 0 && e.size <= 200_000)
    .map((e) => {
      const hot = Math.min((e.path.match(HOT_PATH) ?? []).length, 4);
      const depth = e.path.split("/").length;
      const score = hot * 3 + (ENTRYPOINT.test(e.path) ? 2.5 : 0) - (LOW_VALUE.test(e.path) ? 4 : 0) - depth * 0.25 + Math.log10(e.size + 10);
      return { e, score };
    })
    .sort((a, b) => b.score - a.score);

  return { sources: sources.slice(0, limit).map((s) => s.e), manifests, skipped: Math.max(0, sources.length - limit), considered: scoped.length };
}
