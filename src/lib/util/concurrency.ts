/** Runs `fn` over `items` with at most `limit` promises in flight. Results keep input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

/** A tiny LRU with TTL, for caching expensive audit results in-process. */
export class LruCache<V> {
  private map = new Map<string, { value: V; expires: number }>();
  constructor(private max = 100, private ttlMs = 30 * 60_000) {}

  get(key: string): V | undefined {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (hit.expires < Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, hit);
    return hit.value;
  }

  set(key: string, value: V) {
    this.map.delete(key);
    this.map.set(key, { value, expires: Date.now() + this.ttlMs });
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value!);
  }
}

/** Fixed-window token bucket keyed by client identifier. */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; updated: number }>();
  constructor(private capacity: number, private refillPerMs: number) {}

  take(key: string): { ok: boolean; retryAfterSec: number } {
    const now = Date.now();
    const b = this.buckets.get(key) ?? { tokens: this.capacity, updated: now };
    b.tokens = Math.min(this.capacity, b.tokens + (now - b.updated) * this.refillPerMs);
    b.updated = now;
    // Bound memory under abuse by dropping the oldest clients. Clearing everything
    // would hand every client a full bucket, which is exactly what a flood wants.
    if (this.buckets.size > 5000) for (const stale of [...this.buckets.keys()].slice(0, 1000)) this.buckets.delete(stale);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      // Re-insert so the map stays ordered by last use.
      this.buckets.delete(key);
      this.buckets.set(key, b);
      return { ok: true, retryAfterSec: 0 };
    }
    this.buckets.set(key, b);
    return { ok: false, retryAfterSec: this.refillPerMs > 0 ? Math.ceil((1 - b.tokens) / this.refillPerMs / 1000) : 600 };
  }
}
