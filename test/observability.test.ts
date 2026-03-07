import { describe, it, expect } from "vitest";
import { uuidv7, buildErrorEntry, recordError, extractRequestMetadata } from "../src/observability";

const UUID_V7_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function makeRequest(url = "https://test.local/api/v1/resolve?secid=test"): Request {
  return new Request(url, {
    method: "GET",
    headers: {
      "User-Agent": "test-agent/1.0",
      "Accept": "application/json",
      "CF-Ray": "abc123",
      "Authorization": "Bearer secret-should-not-leak",
    },
  });
}

describe("uuidv7", () => {
  it("produces valid UUIDv7 format", () => {
    const id = uuidv7();
    expect(id).toMatch(UUID_V7_REGEX);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => uuidv7()));
    expect(ids.size).toBe(100);
  });

  it("IDs are time-sortable (later >= earlier)", async () => {
    const first = uuidv7();
    // Ensure wall clock advances at least 1 ms.
    await new Promise((resolve) => setTimeout(resolve, 2));
    const second = uuidv7();
    // String comparison works because UUIDv7 has timestamp in most-significant bytes
    expect(second >= first).toBe(true);
  });
});

describe("extractRequestMetadata", () => {
  it("captures safe headers and excludes sensitive ones", () => {
    const req = makeRequest();
    const meta = extractRequestMetadata(req);

    expect(meta.url).toBe("https://test.local/api/v1/resolve?secid=test");
    expect(meta.method).toBe("GET");
    expect(meta.user_agent).toBe("test-agent/1.0");
    expect(meta.cf_ray).toBe("abc123");
    expect(meta.headers["accept"]).toBe("application/json");
    // Authorization header should NOT be captured
    expect(meta.headers["authorization"]).toBeUndefined();
  });
});

describe("buildErrorEntry", () => {
  it("captures error details and generates valid error_id", () => {
    const req = makeRequest();
    const error = new Error("test explosion");
    const entry = buildErrorEntry("api.resolve", "secid:advisory/test", error, req);

    expect(entry.error_id).toMatch(UUID_V7_REGEX);
    expect(entry.code_path).toBe("api.resolve");
    expect(entry.original_query).toBe("secid:advisory/test");
    expect(entry.error_message).toBe("test explosion");
    expect(entry.stack_trace).toContain("test explosion");
    expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(entry.request_metadata.url).toContain("test.local");
  });

  it("handles non-Error thrown values", () => {
    const req = makeRequest();
    const entry = buildErrorEntry("global", "query", "string error", req);

    expect(entry.error_message).toBe("string error");
    expect(entry.error_id).toMatch(UUID_V7_REGEX);
  });

  it("includes parsed_result when provided", () => {
    const req = makeRequest();
    const parsed = { type: "advisory", namespace: "mitre.org" };
    const entry = buildErrorEntry("api.resolve", "q", new Error("fail"), req, parsed);

    expect(entry.parsed_result).toEqual(parsed);
  });
});

describe("recordError", () => {
  it("returns error_id even without KV (console fallback)", async () => {
    const entry = buildErrorEntry("global", "test", new Error("no kv"), makeRequest());
    const errorId = await recordError(undefined, entry);

    expect(errorId).toBe(entry.error_id);
    expect(errorId).toMatch(UUID_V7_REGEX);
  });
});
