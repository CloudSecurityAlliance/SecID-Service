// ── Per-isolate KV write budget ──
//
// Every KV write costs money and counts against account quota. submit_feedback
// is reachable without authentication and each call is a KV write, so without
// a bound a loop of tool calls is a loop of paid writes.
//
// Cloudflare KV has no atomic increment and this Worker has no rate-limiting
// binding configured, so there is no globally exact limit available. What is
// available, at zero cost, is module-scope state: it lives as long as the
// isolate does, typically minutes to hours. A fixed-window counter per isolate
// therefore bounds writes to (budget × live isolates) per window. That is not a
// hard global cap, but it turns "one write per request" into a small constant
// per isolate, which is the difference that matters for cost.
//
// If a hard global cap is ever needed, add a Workers Rate Limiting binding
// (wrangler.toml [[ratelimits]]) and check it in `take()` — callers do not
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
