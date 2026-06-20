// ── Feedback (secid_FEEDBACK KV) ──
// Two key families, both AI-to-AI by design (intake is MCP-only — no web forms):
//
//   miss:<type>/<namespace>   Passive capture. When a well-formed query names a
//                             type+namespace that isn't registered, we aggregate
//                             a demand signal. Keyed by namespace (not per
//                             request) so KV writes are bounded by *distinct*
//                             missed namespaces — a bot can't blow the quota,
//                             and the stored shape is already "namespace X,
//                             requested N times".
//
//   feedback:<uuid>           Active submission via the submit_feedback MCP tool.
//                             One row per submission (free-text message), so
//                             these are individual events, not aggregated.
//
// Inspect with:
//   wrangler kv key list --binding secid_FEEDBACK --prefix miss:
//   wrangler kv key list --binding secid_FEEDBACK --prefix feedback:
//   wrangler kv key get  --binding secid_FEEDBACK "miss:entity/example.com"

import { uuidv7 } from "./observability";

export type FeedbackCategory = "missing-namespace" | "correction" | "suggestion";

export interface FeedbackRecord {
  id: string;
  category: FeedbackCategory;
  secid: string;
  message: string;
  suggested_urls: string[];
  timestamp: string;
  source: "mcp";
}

export interface MissRecord {
  type: string;
  namespace: string;
  count: number;
  first_seen: string;
  last_seen: string;
  sample_query: string;
}

/**
 * Record a namespace-level miss, aggregating by (type, namespace).
 *
 * Read-modify-write: KV is eventually consistent, so under high concurrency
 * the count may slightly undercount — acceptable for a demand signal. Best
 * called via ctx.waitUntil() so it never blocks the response.
 */
export async function recordMiss(
  kv: KVNamespace | undefined,
  type: string,
  namespace: string,
  query: string
): Promise<void> {
  const key = `miss:${type}/${namespace}`;
  const now = new Date().toISOString();

  if (!kv) {
    console.log("[secid-feedback] miss (no KV):", key);
    return;
  }

  try {
    const existingRaw = await kv.get(key);
    let record: MissRecord;
    if (existingRaw) {
      const prev = JSON.parse(existingRaw) as MissRecord;
      record = {
        type,
        namespace,
        count: (prev.count ?? 0) + 1,
        first_seen: prev.first_seen ?? now,
        last_seen: now,
        sample_query: query,
      };
    } else {
      record = {
        type,
        namespace,
        count: 1,
        first_seen: now,
        last_seen: now,
        sample_query: query,
      };
    }
    await kv.put(key, JSON.stringify(record));
  } catch (err) {
    // Never let feedback capture affect the response path.
    console.error("[secid-feedback] KV write failed:", err);
  }
}

/**
 * Record active feedback submitted by an MCP client (the submit_feedback tool).
 * One row per submission under feedback:<uuid>. Returns the feedback id so the
 * tool can echo it to the caller. Unlike recordMiss this is awaited and its
 * success is surfaced — the agent asked us to record something.
 */
export async function recordFeedback(
  kv: KVNamespace | undefined,
  input: { category: FeedbackCategory; secid: string; message: string; suggested_urls?: string[] }
): Promise<FeedbackRecord> {
  const record: FeedbackRecord = {
    id: uuidv7(),
    category: input.category,
    secid: input.secid,
    message: input.message,
    suggested_urls: input.suggested_urls ?? [],
    timestamp: new Date().toISOString(),
    source: "mcp",
  };

  if (!kv) {
    console.log("[secid-feedback] feedback (no KV):", JSON.stringify(record));
    return record;
  }

  await kv.put(`feedback:${record.id}`, JSON.stringify(record));
  return record;
}
