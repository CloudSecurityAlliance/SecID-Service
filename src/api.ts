import type { Context } from "hono";
import { parseSecID } from "./parser";
import { resolve } from "./resolver";
import { REGISTRY } from "./registry";
import type { AppEnv } from "./types";
import { buildErrorEntry, recordError } from "./observability";

export function handleRegistryDownload(c: Context<AppEnv>): Response {
  return c.json(REGISTRY, 200, {
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

  try {
    const parsed = parseSecID(decoded, REGISTRY);
    const result = resolve(parsed, REGISTRY);
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
