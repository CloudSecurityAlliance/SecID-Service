import type { Context } from "hono";
import { parseSecID } from "./parser";
import { resolve } from "./resolver";
import { REGISTRY } from "./registry";

export async function handleResolve(c: Context): Promise<Response> {
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

  const parsed = parseSecID(decoded, REGISTRY);
  const result = resolve(parsed, REGISTRY);

  return c.json(result);
}
