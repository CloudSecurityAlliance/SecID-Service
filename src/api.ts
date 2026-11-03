import type { Context } from "hono";
import { resolveQuery } from "./kv-resolve";
import { RegistryContext } from "./kv-registry";
import type { AppEnv } from "./types";
import { buildErrorEntry, recordError } from "./observability";
import { TYPE_REGISTRY } from "./type-registry";

const MAX_SECID_QUERY_CHARS = 1024;
const MAX_KV_VALUE_BYTES = 25 * 1024 * 1024; // 25 MiB (Cloudflare KV max value size)

/**
 * Returns the canonical list of SecID types and their named subtypes, merged
 * with per-(type, subtype) entry counts when available.
 *
 * Types and subtypes are served from the bundled type-registry constant —
 * zero KV reads, zero latency. Counts come from the secid:subtypes KV key
 * populated at upload time (and from secid:meta for top-level type counts).
 * If either KV key is missing, the response still returns the type/subtype
 * structure with counts omitted or zero.
 */
/**
 * Pull a qualifier value out of a SecID string — `secid:control?country=JP`.
 *
 * Qualifiers are the last component in the grammar, so a trailing `?k=v&k=v`
 * segment is unambiguous. Only used for listing filters; resolution qualifiers
 * are parsed properly by the resolver.
 */
/** Thrown for a qualifier value that is not valid percent-encoding. */
class MalformedQualifierError extends Error {}

function qualifierFromSecID(secid: string, key: string): string | null {
  const hashIdx = secid.indexOf("#");
  const head = hashIdx !== -1 ? secid.slice(0, hashIdx) : secid;
  const fragment = hashIdx !== -1 ? secid.slice(hashIdx + 1) : "";
  const segments: string[] = [];
  const headQ = head.indexOf("?");
  if (headQ !== -1) segments.push(head.slice(headQ + 1));
  const fragQ = fragment.indexOf("?");
  if (fragQ !== -1) segments.push(fragment.slice(fragQ + 1));
  if (segments.length === 0) return null;

  const target = key.toLowerCase();
  let matched: string | null = null;
  for (const seg of segments) {
    for (const pair of seg.split("&")) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx === -1) continue;
      const k = pair.slice(0, eqIdx).toLowerCase();
      const v = pair.slice(eqIdx + 1);
      if (k === target && v) {
        // decodeURIComponent throws URIError on input like "%ZZ". That is a bad
        // request, not an internal failure: it must not surface as a 500 or be
        // written to the observability KV as an error record.
        try {
          matched = decodeURIComponent(v);
        } catch {
          throw new MalformedQualifierError(`Malformed percent-encoding in qualifier "${key}".`);
        }
      }
    }
  }
  return matched;
}

export async function handleTypes(c: Context<AppEnv>): Promise<Response> {
  const kv = c.env.secid_REGISTRY;
  let typeCounts: Record<string, number> = {};
  let subtypeCounts: Record<string, Record<string, number>> = {};
  if (kv) {
    const ctx = new RegistryContext(kv);
    const [meta, subtypes] = await Promise.all([
      ctx.getMeta().catch(() => null),
      ctx.getSubtypeCounts().catch(() => null),
    ]);
    if (meta?.types) typeCounts = meta.types;
    if (subtypes) subtypeCounts = subtypes;
  }
  return c.json({
    types: TYPE_REGISTRY.map((t) => ({
      type: t.type,
      description: t.short,
      long_description: t.long,
      namespace_count: typeCounts[t.type] ?? null,
      subtypes: t.subtypes.map((s) => ({
        value: s.value,
        description: s.description,
        count: subtypeCounts[t.type]?.[s.value] ?? null,
      })),
    })),
  });
}

export async function handleRegistryDownload(
  c: Context<AppEnv>
): Promise<Response> {
  const kv = c.env.secid_REGISTRY;
  if (!kv) {
    return c.json(
      { error: "Registry KV not configured" },
      503,
    );
  }
  const ctx = new RegistryContext(kv);
  const full = await ctx.getFullRegistry();
  if (!full) {
    return c.json(
      { error: "Registry data not found in KV" },
      503,
    );
  }
  const serialized = JSON.stringify(full);
  const sizeBytes = new TextEncoder().encode(serialized).byteLength;
  if (sizeBytes > MAX_KV_VALUE_BYTES) {
    return c.json(
      {
        error: `Registry payload exceeds ${MAX_KV_VALUE_BYTES} bytes (25 MiB) and cannot be served safely.`,
      },
      503,
    );
  }
  return c.json(full, 200, {
    "Content-Disposition": 'attachment; filename="secid-registry.json"',
  });
}

export async function handleResolve(c: Context<AppEnv>): Promise<Response> {
  const rawQuery = c.req.query("secid") ?? "";

  if (!rawQuery) {
    return c.json({
      secid_query: "",
      status: "error",
      results: [],
      message: "Empty query. Provide a SecID string via ?secid= parameter.",
    });
  }

  // Hono has already percent-decoded the query string once, so this is the
  // SecID as the client meant it. Do not decode it again here: resolveQuery
  // tries it as-is and falls back to one more decode only if that fails.
  const decoded = rawQuery;
  if (decoded.length > MAX_SECID_QUERY_CHARS) {
    return c.json({
      secid_query: decoded.slice(0, MAX_SECID_QUERY_CHARS),
      status: "error",
      results: [],
      message: `SecID query exceeds ${MAX_SECID_QUERY_CHARS} characters. Limit: ${MAX_SECID_QUERY_CHARS} characters.`,
    });
  }

  try {
    const kv = c.env.secid_REGISTRY;
    if (!kv) {
      return c.json({
        secid_query: decoded,
        status: "error",
        results: [],
        message: "Registry KV not configured.",
      });
    }
    // Pass top-level resolution qualifier query params (?parsability=, ?content_type=, ?lang=)
    // structurally into resolveQuery. Inline SecID qualifiers take precedence over
    // top-level HTTP query params inside mergeQualifiers().
    const resolutionQualifiers = ["parsability", "content_type", "lang"] as const;
    const extraQualifiers: Record<string, string> = {};
    let extraLen = 0;
    for (const key of resolutionQualifiers) {
      const paramVal = c.req.query(key);
      if (paramVal) {
        extraLen += key.length + paramVal.length + 2;
        extraQualifiers[key] = paramVal;
      }
    }
    if (decoded.length + extraLen > MAX_SECID_QUERY_CHARS) {
      return c.json({
        secid_query: decoded.slice(0, MAX_SECID_QUERY_CHARS),
        status: "error",
        results: [],
        message: `SecID query exceeds ${MAX_SECID_QUERY_CHARS} characters. Limit: ${MAX_SECID_QUERY_CHARS} characters.`,
      });
    }

    const result = await resolveQuery(kv, decoded, {
      demand: c.env.secid_DEMAND,
      channel: "rest",
      qualifiers: extraQualifiers,
    });

    // Optional listing filters. Two response shapes need handling:
    //   1. Type-only query (e.g., secid:methodology) returns a single wrapper
    //      result whose data.namespaces is the array. Filter that inner array.
    //   2. Other listings return per-entry results carrying the field directly.
    // Item resolutions and source-description responses pass through untouched.
    //
    // `country` is accepted both as a URL parameter and as a SecID qualifier
    // (secid:control?country=JP), because the qualifier form is what the SecID
    // grammar already documents while ?subtype= established the parameter form.
    const filters: Array<{ param: string; field: string; ci: boolean }> = [
      { param: "subtype", field: "subtypes", ci: false },
      { param: "country", field: "country", ci: true },
    ];

    const activeFilters: Array<{ param: string; field: string; ci: boolean; value: string }> = [];
    for (const f of filters) {
      const value = c.req.query(f.param) ?? qualifierFromSecID(decoded, f.param);
      if (value) activeFilters.push({ ...f, value });
    }

    if (activeFilters.length > 0) {
      const matchesAll = (entry: unknown): boolean =>
        activeFilters.every(({ field, ci, value }) => {
          const values = (entry as Record<string, unknown>)?.[field];
          if (!Array.isArray(values)) return false;
          return ci
            ? values.some((v) => String(v).toLowerCase() === value.toLowerCase())
            : values.includes(value);
        });

      const filterMeta: Record<string, string | number> = {};
      for (const { param, value } of activeFilters) {
        filterMeta[param] = value;
      }
      const filterDesc = activeFilters.map(({ param, value }) => `${param} "${value}"`).join(" and ");

      const nested =
        result.results.length === 1
          ? (result.results[0] as { data?: { namespaces?: unknown[] } }).data?.namespaces
          : null;

      if (Array.isArray(nested)) {
        const before = nested.length;
        const filtered = nested.filter(matchesAll);
        const single = result.results[0] as { data: Record<string, unknown> };
        return c.json({
          ...result,
          results: [{ ...single, data: { ...single.data, namespaces: filtered, namespace_count: filtered.length } }],
          filter: { ...filterMeta, total_before_filter: before },
          ...(filtered.length === 0 && before > 0
            ? { message: `No namespaces with ${filterDesc} found in this type.` }
            : {}),
        });
      }

      // Per-entry listings (listNamespaces, listSources) have status "found" and
      // carry a subtypes array on each result's data (or have zero entries when a
      // namespace has no match_nodes). Item resolutions, Level 3 source
      // descriptions, and non-found responses pass through untouched.
      const isPerEntryListing =
        result.status === "found" &&
        result.results.every((r) => Array.isArray((r as { data?: { subtypes?: unknown } }).data?.subtypes));

      if (isPerEntryListing) {
        const before = result.results.length;
        const filtered = result.results.filter((r) => matchesAll((r as { data?: unknown }).data));
        const isSourceListing = result.results.some(
          (r) => typeof (r as { data?: { child_count?: unknown } }).data?.child_count === "number"
        );
        const emptyMsg = isSourceListing
          ? `No sources with ${filterDesc} found in this namespace.`
          : `No namespaces with ${filterDesc} found in this type.`;
        return c.json({
          ...result,
          results: filtered,
          filter: { ...filterMeta, total_before_filter: before },
          ...(filtered.length === 0 && before > 0 ? { message: emptyMsg } : {}),
        });
      }
    }
    return c.json(result);
  } catch (err) {
    if (err instanceof MalformedQualifierError) {
      return c.json(
        { secid_query: decoded, status: "error", results: [], message: err.message },
        400,
      );
    }
    const entry = buildErrorEntry("api.resolve", decoded, err, c.req.raw);
    const errorId = await recordError(c.env.secid_OBSERVABILITY, entry);

    return c.json(
      {
        secid_query: decoded,
        status: "error",
        results: [],
        message: `Internal error resolving query. Reference: ${errorId}`,
        error_id: errorId,
      },
      500,
    );
  }
}
