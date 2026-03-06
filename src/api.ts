import type { Context } from "hono";
import { resolveFromKV } from "./kv-resolve";
import { RegistryContext } from "./kv-registry";
import type { AppEnv } from "./types";
import { buildErrorEntry, recordError } from "./observability";

const MAX_SECID_QUERY_CHARS = 1024;
const MAX_KV_VALUE_BYTES = 25 * 1024 * 1024; // 25 MiB (Cloudflare KV max value size)

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
    const result = await resolveFromKV(kv, decoded);
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
