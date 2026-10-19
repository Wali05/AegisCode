import { createHash } from "node:crypto";
import { GitHubClient } from "../github";
import { providerFromEnv, type LlmProvider } from "../swarm/provider";
import { LruCache, RateLimiter } from "../util/concurrency";
import type { AuditReport } from "../report/types";

/**
 * Process-wide singletons. In a serverless deployment each warm instance keeps
 * its own copy — good enough for result caching and coarse abuse protection.
 */
const globalState = globalThis as unknown as {
  __aegis?: { cache: LruCache<AuditReport>; limiter: RateLimiter; provider: LlmProvider | null };
};

function state() {
  if (!globalState.__aegis) {
    const perWindow = Number(process.env.RATE_LIMIT_PER_10_MIN ?? 12);
    globalState.__aegis = {
      cache: new LruCache<AuditReport>(200, 30 * 60_000),
      limiter: new RateLimiter(perWindow, perWindow / (10 * 60_000)),
      provider: providerFromEnv(),
    };
  }
  return globalState.__aegis;
}

export const cache = () => state().cache;
export const limiter = () => state().limiter;
export const provider = () => state().provider;

export function githubToken(): string | undefined {
  return process.env.GITHUB_TOKEN || process.env.GITHUB_PAT || undefined;
}

export function github(signal?: AbortSignal) {
  return new GitHubClient({ token: githubToken(), signal });
}

export function cacheKey(parts: unknown[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

export function clientIp(headers: Headers): string {
  return headers.get("x-forwarded-for")?.split(",")[0]?.trim() || headers.get("x-real-ip") || "local";
}
