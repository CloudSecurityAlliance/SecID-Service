import type { Context } from "hono";
import { resolveFromKV } from "./kv-resolve";
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

  // Decode percent-encoded characters (browser/client may have encoded # as %23, etc.)
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawQuery);
  } catch {
    return c.json({
      secid_query: rawQuery,
      status: "error",
      results: [],
      message: "Malformed percent-encoding in query parameter.",
    });
  }
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
    const result = await resolveFromKV(kv, decoded, {
      feedbackKv: c.env.secid_FEEDBACK,
      waitUntil: (p) => c.executionCtx.waitUntil(p),
    });

    // Optional ?subtype= filter — applies to namespace listings within a type.
    // Two response shapes need handling:
    //   1. Type-only query (e.g., secid:methodology) returns a single wrapper
    //      result whose data.namespaces is the array. Filter that inner array.
    //   2. Other listings (cross-source, list-by-namespace) return per-entry
    //      results with data.subtypes per result. Filter the top-level array.
    // Item resolutions and source-description responses pass through untouched.
    const subtypeFilter = c.req.query("subtype");
    if (subtypeFilter) {
      const nestedNamespaces = (
        result.results.length === 1
          ? (result.results[0] as { data?: { namespaces?: Array<{ subtypes?: string[] }> } }).data?.namespaces
          : null
      );
      if (Array.isArray(nestedNamespaces)) {
        const before = nestedNamespaces.length;
        const filtered = nestedNamespaces.filter(
          (n) => Array.isArray(n.subtypes) && n.subtypes.includes(subtypeFilter)
        );
        const single = result.results[0] as { data: Record<string, unknown> };
        return c.json({
          ...result,
          results: [{ ...single, data: { ...single.data, namespaces: filtered, namespace_count: filtered.length } }],
          filter: { subtype: subtypeFilter, total_before_filter: before },
          ...(filtered.length === 0 && before > 0
            ? { message: `No namespaces with subtype "${subtypeFilter}" found in this type.` }
            : {}),
        });
      }
      // Fallback: top-level filtering (per-entry results with data.subtypes).
      const before = result.results.length;
      const filtered = result.results.filter((r) => {
        const data = (r as { data?: { subtypes?: unknown } }).data;
        const subtypes = data?.subtypes;
        return Array.isArray(subtypes) && subtypes.includes(subtypeFilter);
      });
      return c.json({
        ...result,
        results: filtered,
        filter: { subtype: subtypeFilter, total_before_filter: before },
        ...(filtered.length === 0 && before > 0
          ? { message: `No namespaces with subtype "${subtypeFilter}" found in this type.` }
          : {}),
      });
    }
    return c.json(result);
  } catch (err) {
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
