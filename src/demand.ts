// ── Demand signal: namespace misses (Workers Analytics Engine) ──
//
// When a well-formed query names a recognized type and a namespace that is not
// registered (`secid:entity/some-new-vendor.io`), that is a request for a
// source we do not cover. Those requests are worth counting: they are the
// ranked backlog of what to add next.
//
// Why Analytics Engine and not KV: this is an event log. KV is a key-value
// store with paid, rate-limited writes and no atomic increment, so a KV miss
// log was a read-modify-write per request that undercounted under load and let
// an anonymous caller choose the keys we paid to write. writeDataPoint() is a
// non-blocking append with no read, no key, and flat per-point pricing; the
// batch job aggregates later (scripts/export-misses.ts, docs/DEMAND-SIGNAL.md).
//
// What is stored — validated fields only, never caller free text:
//   index1  = namespace                (lowercased, validated DNS name)
//   blob1   = type                     (one of SECID_TYPES — the parser checked)
//   blob2   = namespace                (same as index1, so it is groupable)
//   blob3   = channel                  ("rest" | "mcp")
//   blob4   = status that triggered it (the response status, e.g. "not_found")
//   double1 = 1                        (one request)
// The raw query, subpath, version and qualifiers are deliberately not stored:
// they are caller-controlled text and the demand signal does not need them.
//
// Typos and invented domains are not our problem. A miss is recorded only for
// a syntactically valid DNS name whose last label is a TLD IANA has delegated
// (src/tlds.ts). That drops "constructor", "x.notarealtld" and 300-char junk,
// while a real domain we do not have — the thing we want to hear about — gets
// through. It does not bound volume by itself (random-label.com is valid).
// Nothing here caps volume: a request writes at most one point per resolved
// SecID (an MCP batch is capped at 10), Analytics Engine prices every point the
// same, and the batch job separates signal from noise by count and distinct
// days. A per-isolate budget is deliberately not applied — it would cost more
// in lost signal than the writes it saves.

import { IANA_TLDS } from "./tlds";

export type DemandChannel = "rest" | "mcp";

/** Analytics Engine rejects an index over 96 bytes (see docs/DEMAND-SIGNAL.md). */
export const MAX_INDEX_BYTES = 96;

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Could `namespace` name a real organisation's domain?
 *
 * Requires at least two labels, RFC 1035 label syntax (IDNs must arrive in
 * their xn-- A-label form), a total length within DNS limits, and a final
 * label that IANA has actually delegated. A path suffix (github.com/advisories)
 * is never produced for an unregistered namespace by the parser, so only the
 * domain form is accepted.
 */
export function isPlausibleNamespace(namespace: string): boolean {
  if (!namespace || namespace.length > 253) return false;
  const domain = namespace.toLowerCase();
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((l) => DNS_LABEL.test(l))) return false;
  return IANA_TLDS.has(labels[labels.length - 1]);
}

export interface DemandMiss {
  type: string;
  namespace: string;
  channel: DemandChannel;
  status: string;
}

/**
 * Build the data point for a miss, or null when the miss is not worth
 * recording. Pure, so tests can check the exact shape without a binding.
 */
export function demandDataPoint(miss: DemandMiss): AnalyticsEngineDataPoint | null {
  if (!isPlausibleNamespace(miss.namespace)) return null;
  // Domains are case-insensitive, so one domain is one demand signal.
  const ns = miss.namespace.toLowerCase();
  // Validated names are ASCII, so length is bytes. A name this long is
  // almost certainly junk; dropping it beats a rejected or truncated index.
  if (ns.length > MAX_INDEX_BYTES) return null;
  return {
    indexes: [ns],
    blobs: [miss.type, ns, miss.channel, miss.status],
    doubles: [1],
  };
}

/**
 * Record a namespace miss. Best-effort: never throws, never awaits, and is a
 * no-op when the binding is absent (tests, local dev without the binding).
 * Returns true when a data point was handed to Analytics Engine.
 */
export function recordDemandMiss(
  dataset: AnalyticsEngineDataset | undefined,
  miss: DemandMiss
): boolean {
  if (!dataset) return false;
  const point = demandDataPoint(miss);
  if (!point) return false;
  try {
    dataset.writeDataPoint(point);
    return true;
  } catch (err) {
    // Never let demand capture affect the response path.
    console.error("[secid-demand] writeDataPoint failed:", err);
    return false;
  }
}
