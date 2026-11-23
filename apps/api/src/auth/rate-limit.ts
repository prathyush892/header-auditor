/**
 * Fixed-window attempt counter for login and registration.
 *
 * Two keys are counted per login: the client IP (stops one machine spraying
 * many accounts) and the target email (stops a botnet hammering one account
 * from many IPs). The interface is async so a Redis-backed implementation can
 * replace this in-process one when the API runs as several instances.
 */
export interface RateLimitDecision {
  readonly allowed: boolean;
  /** Attempts left in this window after this one (0 when blocked). */
  readonly remaining: number;
  /** Milliseconds until the window resets. */
  readonly retryAfterMs: number;
}

export interface RateLimiter {
  /** Counts one attempt against `key` and says whether it may proceed. */
  consume(key: string, limit: number): Promise<RateLimitDecision>;
  /** Forgets `key` (e.g. after a successful login for that account). */
  reset(key: string): Promise<void>;
}

export interface MemoryRateLimiterOptions {
  readonly windowMs: number;
  /** Upper bound on tracked keys so a flood of unique keys can't exhaust memory. */
  readonly maxKeys?: number;
  readonly now?: () => number;
}

interface Bucket {
  count: number;
  resetAt: number;
}

export const DEFAULT_MAX_KEYS = 100_000;

export class MemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly now: () => number;

  constructor(options: MemoryRateLimiterOptions) {
    if (!Number.isInteger(options.windowMs) || options.windowMs <= 0) {
      throw new RangeError("windowMs must be a positive integer");
    }
    const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    if (!Number.isInteger(maxKeys) || maxKeys < 1) {
      throw new RangeError("maxKeys must be a positive integer");
    }
    this.windowMs = options.windowMs;
    this.maxKeys = maxKeys;
    this.now = options.now ?? Date.now;
  }

  consume(key: string, limit: number): Promise<RateLimitDecision> {
    if (!Number.isInteger(limit) || limit < 1) throw new RangeError("limit must be >= 1");
    const now = this.now();
    let bucket = this.buckets.get(key);
    if (bucket === undefined || bucket.resetAt <= now) {
      if (bucket === undefined && this.buckets.size >= this.maxKeys) this.evict(now);
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    const retryAfterMs = bucket.resetAt - now;
    if (bucket.count > limit) {
      // Cap the counter so a long attack can't overflow or grow it forever.
      bucket.count = limit + 1;
      return Promise.resolve({ allowed: false, remaining: 0, retryAfterMs });
    }
    return Promise.resolve({ allowed: true, remaining: limit - bucket.count, retryAfterMs });
  }

  reset(key: string): Promise<void> {
    this.buckets.delete(key);
    return Promise.resolve();
  }

  /** Number of tracked keys (for tests and metrics). */
  get size(): number {
    return this.buckets.size;
  }

  /**
   * Drops expired buckets; if still full, drops the oldest entries (Map
   * iteration order is insertion order). Evicting gives an attacker at most a
   * fresh window for keys they pushed out themselves, never unbounded memory.
   */
  private evict(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
    const excess = this.buckets.size - this.maxKeys + 1;
    if (excess <= 0) return;
    let removed = 0;
    for (const key of this.buckets.keys()) {
      if (removed >= excess) break;
      this.buckets.delete(key);
      removed += 1;
    }
  }
}
