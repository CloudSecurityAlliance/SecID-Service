// ── Feedback: missed-namespace capture ──
// When a well-formed query names a type+namespace that isn't in the registry,
// we record it here so we have a ranked backlog of the most-requested sources
// we don't yet cover — demand signal even from callers who never submit.
//
// Aggregated by key (miss:<type>/<namespace>), NOT one row per request, so the
// number of KV writes is bounded by *distinct* missed namespaces rather than
// request volume — a bot hammering random namespaces can't blow the KV quota,
// and the stored shape is already the thing we want ("namespace X, requested N
// times") rather than a pile of events to tally later.
//
// Stored in the secid_FEEDBACK KV namespace. Inspect with:
//   wrangler kv key list --binding secid_FEEDBACK --prefix miss:
//   wrangler kv key get  --binding secid_FEEDBACK "miss:entity/example.com"

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
