/**
 * Pure helpers for scripts/export-misses.ts: build the Analytics Engine SQL
 * query and aggregate its rows into the demand digest. No I/O and no Node
 * APIs, so the tests run them against fixtures (test/export-misses.test.ts).
 *
 * The dataset's columns are written by src/demand.ts:
 *   index1 = namespace, blob1 = type, blob2 = namespace, blob3 = channel,
 *   blob4 = status, double1 = 1
 */

export const DEFAULT_DATASET = "secid_demand_misses";
export const DEFAULT_DAYS = 7;
/** Analytics Engine keeps data for three months; asking for more is an error. */
export const MAX_DAYS = 90;
export const DEFAULT_ROW_LIMIT = 10_000;

const DATASET_NAME = /^[A-Za-z0-9_]+$/;

export interface QueryOptions {
  dataset?: string;
  days?: number;
  rowLimit?: number;
}

/**
 * One row per (type, namespace, channel, status, UTC day). Daily buckets are
 * what let the digest report distinct days, which separates a namespace people
 * keep asking for from one burst. `SUM(_sample_interval)` rather than
 * `count()` because Analytics Engine may sample hot indexes; the sum restores
 * the true count.
 *
 * Every interpolated value is validated first: the dataset name against a
 * strict identifier pattern, the numbers as bounded integers. Nothing from the
 * caller-written data is ever interpolated.
 */
export function buildMissesQuery(opts: QueryOptions = {}): string {
  const dataset = opts.dataset ?? DEFAULT_DATASET;
  const days = opts.days ?? DEFAULT_DAYS;
  const rowLimit = opts.rowLimit ?? DEFAULT_ROW_LIMIT;
  if (!DATASET_NAME.test(dataset)) throw new Error(`Invalid dataset name: ${JSON.stringify(dataset)}`);
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    throw new Error(`--days must be an integer from 1 to ${MAX_DAYS} (retention is three months); got ${days}`);
  }
  if (!Number.isInteger(rowLimit) || rowLimit < 1 || rowLimit > 1_000_000) {
    throw new Error(`Invalid row limit: ${rowLimit}`);
  }
  return [
    "SELECT",
    "  blob1 AS type,",
    "  blob2 AS namespace,",
    "  blob3 AS channel,",
    "  blob4 AS status,",
    "  formatDateTime(toStartOfDay(timestamp), '%Y-%m-%d') AS day,",
    "  SUM(_sample_interval) AS hits,",
    "  min(timestamp) AS first_seen,",
    "  max(timestamp) AS last_seen",
    `FROM ${dataset}`,
    `WHERE timestamp > NOW() - INTERVAL '${days}' DAY`,
    "GROUP BY type, namespace, channel, status, day",
    "ORDER BY hits DESC",
    `LIMIT ${rowLimit}`,
    "FORMAT JSON",
  ].join("\n");
}

/** A row of the SQL API's FORMAT JSON `data` array. Numbers may arrive as strings. */
export interface MissRow {
  type: string;
  namespace: string;
  channel: string;
  status: string;
  day: string;
  hits: number | string;
  first_seen: string;
  last_seen: string;
}

export interface DemandEntry {
  type: string;
  namespace: string;
  count: number;
  distinct_days: number;
  first_seen: string;
  last_seen: string;
  channels: Record<string, number>;
  statuses: Record<string, number>;
  /** Other types this namespace IS registered under — a hint, not a filter. */
  registered_as: string[];
}

/** type → set of lowercased registered namespaces. */
export type RegisteredNamespaces = Map<string, Set<string>>;

/** "2026-09-24 13:05:00" (UTC, the SQL API's DateTime form) → ISO 8601. */
function toIso(ts: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/.exec(ts);
  return m ? `${m[1]}T${m[2]}Z` : ts;
}

/**
 * Fold daily rows into one entry per (type, namespace), drop namespaces that
 * are registered for that type now, and sort by count, then distinct days.
 * Registration is compared case-insensitively, matching how src/demand.ts
 * keys misses.
 */
export function aggregateMisses(rows: MissRow[], registered: RegisteredNamespaces): DemandEntry[] {
  const byKey = new Map<string, DemandEntry & { days: Set<string> }>();

  for (const row of rows) {
    const type = String(row.type);
    const namespace = String(row.namespace).toLowerCase();
    if (!type || !namespace) continue;
    if (registered.get(type)?.has(namespace)) continue;

    const hits = Number(row.hits);
    if (!Number.isFinite(hits) || hits <= 0) continue;
    const first = toIso(String(row.first_seen));
    const last = toIso(String(row.last_seen));

    const key = `${type}\u0000${namespace}`;
    let entry = byKey.get(key);
    if (!entry) {
      entry = {
        type,
        namespace,
        count: 0,
        distinct_days: 0,
        first_seen: first,
        last_seen: last,
        // Null-prototype maps: keys come from stored data, so none may alias
        // an Object.prototype member.
        channels: Object.create(null) as Record<string, number>,
        statuses: Object.create(null) as Record<string, number>,
        registered_as: [],
        days: new Set(),
      };
      byKey.set(key, entry);
    }
    entry.count += hits;
    entry.days.add(String(row.day));
    if (first < entry.first_seen) entry.first_seen = first;
    if (last > entry.last_seen) entry.last_seen = last;
    entry.channels[row.channel] = (entry.channels[row.channel] ?? 0) + hits;
    entry.statuses[row.status] = (entry.statuses[row.status] ?? 0) + hits;
  }

  const out: DemandEntry[] = [];
  for (const { days, ...entry } of byKey.values()) {
    entry.distinct_days = days.size;
    entry.registered_as = [...registered.entries()]
      .filter(([t, set]) => t !== entry.type && set.has(entry.namespace))
      .map(([t]) => t)
      .sort();
    out.push(entry);
  }
  out.sort(
    (a, b) =>
      b.count - a.count ||
      b.distinct_days - a.distinct_days ||
      a.type.localeCompare(b.type) ||
      a.namespace.localeCompare(b.namespace)
  );
  return out;
}

/** Build the lookup from `{ type, namespace }` records read from registry JSON. */
export function registeredFrom(records: Array<{ type?: unknown; namespace?: unknown }>): RegisteredNamespaces {
  const map: RegisteredNamespaces = new Map();
  for (const r of records) {
    if (typeof r.type !== "string" || typeof r.namespace !== "string") continue;
    if (!map.has(r.type)) map.set(r.type, new Set());
    map.get(r.type)!.add(r.namespace.toLowerCase());
  }
  return map;
}
