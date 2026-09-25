// Bounds on the paths an unauthenticated caller can drive: feedback writes,
// request bodies, batch fan-out, and KV reads per query.
import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { resolveFromKV } from "../src/kv-resolve";
import { parseSecID } from "../src/parser";
import { resolve } from "../src/resolver";
import { resetFeedbackLimits } from "../src/feedback";
import { REGISTRY } from "../src/registry";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY);
});
beforeEach(() => resetFeedbackLimits());

const MCP_URL = "https://test.local/mcp";
const MCP_HEADERS = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };

/** A KV stand-in that counts reads and remembers writes. */
function countingKv(inner: KVNamespace) {
  const stats = { gets: 0, puts: [] as string[] };
  const kv = {
    get: (key: string, type?: unknown) => {
      stats.gets++;
      return (inner.get as (k: string, t?: unknown) => Promise<unknown>)(key, type);
    },
    put: async (key: string) => {
      stats.puts.push(key);
    },
  } as unknown as KVNamespace;
  return { kv, stats };
}

describe("prototype keys are not namespaces", () => {
  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "parser does not treat %s as a registered namespace",
    (name) => {
      const r = parseSecID(`secid:advisory/${name}`, REGISTRY);
      expect(r.namespace).toBeNull();
      expect(r.name).toBe(name);
    },
  );

  it("secid:advisory/constructor records no miss", async () => {
    const feedback = countingKv(env.secid_FEEDBACK!);
    const points: AnalyticsEngineDataPoint[] = [];
    const demand = { writeDataPoint: (p?: AnalyticsEngineDataPoint) => p && points.push(p) };
    const result = await resolveFromKV(env.secid_REGISTRY!, "secid:advisory/constructor", {
      feedbackKv: feedback.kv,
      demand,
      channel: "rest",
    });
    expect(result.status).toBe("not_found");
    expect(feedback.stats.puts).toEqual([]);
    expect(points).toEqual([]);
  });
});

describe("cross-source miss does not scan the whole type", () => {
  it("answers an unmatched entity term in a handful of KV reads", async () => {
    const { kv, stats } = countingKv(env.secid_REGISTRY!);
    const result = await resolveFromKV(kv, "secid:entity/zzqqxxnotathing");
    expect(result.status).toBe("not_found");
    expect(result.message).toContain("No results found");
    // TypeIndex + global index. Previously: one read per entity namespace.
    expect(stats.gets).toBeLessThanOrEqual(3);
  });

  // Queries with no child-pattern match used to be answered by fetching every
  // namespace of the type. The index path must return exactly what that full
  // scan returned, which is what the in-memory resolver over the complete
  // registry computes.
  it.each([
    "secid:control/ismap",
    "secid:control/fedramp",
    "secid:weakness/cwe",
    "secid:ttp/capec",
    "secid:entity/redhat",
    "secid:entity/zzqqxxnotathing",
    "secid:reference/arxiv",
  ])("matches the full-scan result for %s", async (input) => {
    const { kv, stats } = countingKv(env.secid_REGISTRY!);
    const kvResult = await resolveFromKV(kv, input);
    const fullScan = resolve(parseSecID(input, REGISTRY), REGISTRY);
    expect(kvResult).toEqual(fullScan);
    expect(stats.gets).toBeLessThan(20);
  });
});

describe("REST qualifier decoding", () => {
  it("returns 400, not 500, for a malformed percent-encoded qualifier", async () => {
    // The query string is decoded by Hono first, so which encoding reaches the
    // qualifier decoder as "%ZZ" depends on whether the handler decodes the
    // SecID again. Neither may produce a 500 or an error record, and one of
    // them must reach the qualifier check.
    const statuses: number[] = [];
    for (const enc of ["%25ZZ", "%2525ZZ"]) {
      const res = await SELF.fetch(`https://test.local/api/v1/resolve?secid=secid:control%3Fcountry%3D${enc}`);
      statuses.push(res.status);
      const body = (await res.json()) as { status: string; message?: string; error_id?: string };
      expect(res.status).not.toBe(500);
      expect(body.error_id).toBeUndefined();
      if (res.status === 400) {
        expect(body.status).toBe("error");
        expect(body.message).toContain("Malformed percent-encoding in qualifier");
      }
    }
    expect(statuses).toContain(400);
  });
});

describe("MCP request limits", () => {
  it("rejects an oversized chunked body that carries no Content-Length", async () => {
    const big = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1, pad: "x".repeat(70_000) }),
    );
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < big.length; i += 8192) controller.enqueue(big.slice(i, i + 8192));
        controller.close();
      },
    });
    const res = await SELF.fetch(MCP_URL, { method: "POST", headers: MCP_HEADERS, body: stream });
    expect(res.status).toBe(413);
  });

  it("rejects a batch containing submit_feedback", async () => {
    const call = (id: number) => ({
      jsonrpc: "2.0",
      method: "tools/call",
      id,
      params: {
        name: "submit_feedback",
        arguments: { category: "suggestion", secid: "secid:entity/x.com", message: "m" },
      },
    });
    const res = await SELF.fetch(MCP_URL, {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify([call(1), call(2)]),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: { message: string } };
    expect(body.error?.message).toContain("batch");
  });

  it("rejects an over-long batch", async () => {
    const msgs = Array.from({ length: 11 }, (_, i) => ({ jsonrpc: "2.0", method: "tools/list", id: i }));
    const res = await SELF.fetch(MCP_URL, { method: "POST", headers: MCP_HEADERS, body: JSON.stringify(msgs) });
    expect(res.status).toBe(400);
  });

  async function submitFeedback(args: Record<string, unknown>) {
    const res = await SELF.fetch(MCP_URL, {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        id: 1,
        params: { name: "submit_feedback", arguments: args },
      }),
    });
    return (await res.json()) as { result?: { isError?: boolean; content: Array<{ text: string }> } };
  }

  it("accepts a normal submission", async () => {
    const body = await submitFeedback({ category: "suggestion", secid: "secid:entity/x.com", message: "ok" });
    expect(body.result?.isError).toBeFalsy();
    expect(JSON.parse(body.result!.content[0].text).status).toBe("received");
  });

  it.each([
    ["message over the cap", { message: "m".repeat(4001) }],
    ["secid over the cap", { secid: "s".repeat(1025) }],
    ["too many URLs", { suggested_urls: Array.from({ length: 11 }, (_, i) => `https://x.com/${i}`) }],
    ["a URL over the cap", { suggested_urls: [`https://x.com/${"a".repeat(2100)}`] }],
  ])("rejects %s", async (_label, override) => {
    const body = await submitFeedback({
      category: "suggestion",
      secid: "secid:entity/x.com",
      message: "ok",
      ...override,
    });
    expect(body.result?.isError).toBe(true);
  });
});
