// ── Per-isolate KV write budget ──
//
// Every KV write costs money and counts against account quota, and the two
// write paths reachable without authentication (namespace-miss capture and the
// submit_feedback tool) let the caller choose the key. Without a bound, a loop
// over random domains is a loop over paid writes.
//
// Cloudflare KV has no atomic increment and this Worker has no rate-limiting
// binding configured, so there is no globally exact limit available. What is
// available, at zero cost, is module-scope state: it lives as long as the
// isolate does, which is typically minutes to hours. A fixed-window counter per
// isolate therefore bounds writes to (budget × live isolates) per window. That
// is not a hard global cap, but it turns "one write per request" into a small
// constant per isolate, which is the difference that matters for cost.
//
// If a hard global cap is ever needed, add a Workers Rate Limiting binding
// (wrangler.toml [[ratelimits]]) and check it in `take()` — the callers do not
// need to change.

export class WriteBudget {
  private windowStart = 0;
  private used = 0;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Consume one write from the current window. False when it is exhausted. */
  take(): boolean {
    const t = this.now();
    if (t - this.windowStart >= this.windowMs) {
      this.windowStart = t;
      this.used = 0;
    }
    if (this.used >= this.limit) return false;
    this.used++;
    return true;
  }
}

/**
 * Remembers keys written recently in this isolate so a hot key costs one
 * write per window instead of one per request. Bounded in size: when full, the
 * oldest entry is evicted (Map preserves insertion order).
 */
export class RecentKeys {
  private seen = new Map<string, number>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** True when `key` was marked within the last ttlMs. */
  has(key: string): boolean {
    const at = this.seen.get(key);
    if (at === undefined) return false;
    if (this.now() - at >= this.ttlMs) {
      this.seen.delete(key);
      return false;
    }
    return true;
  }

  mark(key: string): void {
    this.seen.delete(key);
    if (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.set(key, this.now());
  }
}
