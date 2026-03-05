// ── Observability ──
// Structured error recording with UUIDv7 identifiers, stored in Cloudflare KV.
// Errors are surfaced to callers via error_id; full diagnostics accessed via `wrangler kv`.
// This is always-on production infrastructure, not debug mode. See:
// CINO-Platform-Engineering/research/operational-excellence/OPERATIONAL-PHILOSOPHY.md

// ── UUIDv7 (RFC 9562 §5.7) ──
// 48-bit ms timestamp + 74 random bits. Time-sortable, no dependencies.
export function uuidv7(): string {
  const now = Date.now();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // Timestamp in first 48 bits (big-endian)
  bytes[0] = (now / 2 ** 40) & 0xff;
  bytes[1] = (now / 2 ** 32) & 0xff;
  bytes[2] = (now / 2 ** 24) & 0xff;
  bytes[3] = (now / 2 ** 16) & 0xff;
  bytes[4] = (now / 2 ** 8) & 0xff;
  bytes[5] = now & 0xff;
  bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export type CodePath =
  | "api.resolve"
  | "mcp.tool.resolve"
  | "mcp.tool.lookup"
  | "mcp.tool.describe"
  | "mcp.transport"
  | "global";

export interface ObservabilityEntry {
  error_id: string;
  timestamp: string;
  code_path: CodePath;
  original_query: string;
  parsed_result?: unknown;
  error_message: string;
  stack_trace: string | null;
  request_metadata: {
    url: string;
    method: string;
    cf_ray?: string;
    cf_colo?: string;
    user_agent?: string;
    headers: Record<string, string>;
  };
}

const SAFE_HEADERS = new Set([
  "accept",
  "accept-language",
  "content-type",
  "origin",
  "referer",
  "user-agent",
  "x-request-id",
]);

export function extractRequestMetadata(req: Request): ObservabilityEntry["request_metadata"] {
  const headers: Record<string, string> = {};
  for (const [key, value] of req.headers.entries()) {
    if (SAFE_HEADERS.has(key.toLowerCase())) {
      headers[key.toLowerCase()] = value;
    }
  }

  const cf = (req as unknown as { cf?: Record<string, unknown> }).cf;

  return {
    url: req.url,
    method: req.method,
    cf_ray: (cf?.httpProtocol as string) ?? req.headers.get("cf-ray") ?? undefined,
    cf_colo: cf?.colo as string | undefined,
    user_agent: req.headers.get("user-agent") ?? undefined,
    headers,
  };
}

export function buildErrorEntry(
  codePath: CodePath,
  originalQuery: string,
  error: unknown,
  req: Request,
  parsedResult?: unknown,
): ObservabilityEntry {
  const err = error instanceof Error ? error : new Error(String(error));
  return {
    error_id: uuidv7(),
    timestamp: new Date().toISOString(),
    code_path: codePath,
    original_query: originalQuery,
    parsed_result: parsedResult,
    error_message: err.message,
    stack_trace: err.stack ?? null,
    request_metadata: extractRequestMetadata(req),
  };
}

const TTL_30_DAYS = 30 * 24 * 60 * 60;

export async function recordError(
  kv: KVNamespace | undefined,
  entry: ObservabilityEntry,
): Promise<string> {
  if (!kv) {
    console.error("[secid-observability]", JSON.stringify(entry));
    return entry.error_id;
  }

  try {
    await kv.put(`error:${entry.error_id}`, JSON.stringify(entry), {
      expirationTtl: TTL_30_DAYS,
    });
  } catch (kvError) {
    console.error("[secid-observability] KV write failed:", kvError);
    console.error("[secid-observability]", JSON.stringify(entry));
  }

  return entry.error_id;
}
