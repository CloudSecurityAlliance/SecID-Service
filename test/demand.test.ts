// Namespace-miss demand signal (src/demand.ts): what reaches Analytics Engine,
// and — as important — what never does.
import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { resolveFromKV, resolveQuery } from "../src/kv-resolve";
import worker from "../src/index";
import {
  demandDataPoint,
  isPlausibleNamespace,
  recordDemandMiss,
  MAX_INDEX_BYTES,
} from "../src/demand";
import { REGISTRY } from "../src/registry";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY);
});

function fakeDataset() {
  const points: AnalyticsEngineDataPoint[] = [];
  const dataset: AnalyticsEngineDataset = {
    writeDataPoint: (p?: AnalyticsEngineDataPoint) => {
      if (p) points.push(p);
    },
  };
  return { dataset, points };
}

describe("demandDataPoint shape", () => {
  it("is exactly index=namespace, blobs=[type, namespace, channel, status], doubles=[1]", () => {
    expect(
      demandDataPoint({ type: "entity", namespace: "some-new-vendor.io", channel: "mcp", status: "not_found" }),
    ).toEqual({
      indexes: ["some-new-vendor.io"],
      blobs: ["entity", "some-new-vendor.io", "mcp", "not_found"],
      doubles: [1],
    });
  });

  it("lowercases the namespace so one domain is one signal", () => {
    const p = demandDataPoint({ type: "advisory", namespace: "Example.COM", channel: "rest", status: "not_found" });
    expect(p?.indexes).toEqual(["example.com"]);
    expect(p?.blobs?.[1]).toBe("example.com");
  });

  it.each([
    ["constructor"],
    ["__proto__"],
    ["localhost"],
    ["x.notarealtld"],
    ["-bad.com"],
    ["bad-.com"],
    ["a..com"],
    ["under_score.com"],
    ["exämple.com"],
    [`${"a".repeat(64)}.com`],
    [`${"a.".repeat(130)}com`],
    [""],
  ])("records nothing for implausible namespace case %#", (ns) => {
    expect(demandDataPoint({ type: "entity", namespace: ns, channel: "rest", status: "not_found" })).toBeNull();
  });

  it("drops a valid domain longer than the 96-byte index limit", () => {
    const long = `${"a".repeat(60)}.${"b".repeat(40)}.com`; // valid DNS, > 96 bytes
    expect(isPlausibleNamespace(long)).toBe(true);
    expect(long.length).toBeGreaterThan(MAX_INDEX_BYTES);
    expect(demandDataPoint({ type: "entity", namespace: long, channel: "rest", status: "not_found" })).toBeNull();
  });
});

describe("isPlausibleNamespace", () => {
  it("accepts every domain already in the registry", () => {
    const rejected: string[] = [];
    for (const namespaces of Object.values(REGISTRY)) {
      for (const ns of Object.keys(namespaces)) {
        if (!isPlausibleNamespace(ns.split("/")[0])) rejected.push(ns);
      }
    }
    expect(rejected).toEqual([]);
  });

  it("accepts IDN TLDs in A-label form", () => {
    expect(isPlausibleNamespace("example.xn--p1ai")).toBe(true);
  });
});

describe("recordDemandMiss is best-effort", () => {
  const miss = { type: "entity", namespace: "example.com", channel: "rest" as const, status: "not_found" };

  it("is a no-op when the binding is absent", () => {
    expect(recordDemandMiss(undefined, miss)).toBe(false);
  });

  it("never throws when writeDataPoint throws", () => {
    const throwing: AnalyticsEngineDataset = {
      writeDataPoint: () => {
        throw new Error("boom");
      },
    };
    expect(() => recordDemandMiss(throwing, miss)).not.toThrow();
    expect(recordDemandMiss(throwing, miss)).toBe(false);
  });
});

describe("resolveFromKV miss capture", () => {
  async function run(input: string, channel: "rest" | "mcp" = "rest") {
    const { dataset, points } = fakeDataset();
    const result = await resolveFromKV(env.secid_REGISTRY, input, { demand: dataset, channel });
    return { result, points };
  }

  it("writes one data point for a real unregistered domain and no caller free text", async () => {
    const { result, points } = await run(
      "secid:advisory/some-new-vendor.io/bulletins@2024?lang=en#ADV-2024-001",
      "mcp",
    );
    expect(result.status).toBe("not_found");
    expect(points).toEqual([
      {
        indexes: ["some-new-vendor.io"],
        blobs: ["advisory", "some-new-vendor.io", "mcp", "not_found"],
        doubles: [1],
      },
    ]);
    const stored = JSON.stringify(points);
    for (const fragment of ["bulletins", "2024", "lang", "ADV-2024-001", "secid:"]) {
      expect(stored).not.toContain(fragment);
    }
  });

  it("writes nothing for a typo'd TLD", async () => {
    const { result, points } = await run("secid:entity/foo.notarealtld");
    expect(result.status).toBe("not_found");
    expect(result.message).toContain("submit_feedback");
    expect(points).toEqual([]);
  });

  it("writes nothing for a registered namespace", async () => {
    const registered = Object.keys(REGISTRY.advisory)[0];
    const { points } = await run(`secid:advisory/${registered}`);
    expect(points).toEqual([]);
  });

  it("writes nothing for a case variant of a registered namespace", async () => {
    const registered = Object.keys(REGISTRY.advisory).find((ns) => /[a-z]/.test(ns) && !ns.includes("/"))!;
    const { result, points } = await run(`secid:advisory/${registered.toUpperCase()}`);
    expect(result.status).toBe("not_found");
    expect(points).toEqual([]);
  });

  it("writes nothing for a cross-source term (no namespace)", async () => {
    const { points } = await run("secid:entity/zzqqxxnotathing");
    expect(points).toEqual([]);
  });

  it("writes nothing when no demand binding is passed", async () => {
    const result = await resolveFromKV(env.secid_REGISTRY, "secid:entity/some-new-vendor.io", {});
    expect(result.status).toBe("not_found");
  });
});

describe("the Worker's real binding (miniflare)", () => {
  it("serves a namespace miss over REST without error", async () => {
    const res = await SELF.fetch("https://test.local/api/v1/resolve?secid=secid:entity/some-new-vendor.io");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("not_found");
  });
});

// resolveQuery (the entry point REST and every MCP tool use) must keep passing
// the capture through to the namespace-miss branch, and — because it may try a
// query twice (as-is, then percent-decoded) — must record at most one point.
describe("resolveQuery miss capture", () => {
  it("records a namespace miss once", async () => {
    const { dataset, points } = fakeDataset();
    const r = await resolveQuery(env.secid_REGISTRY, "secid:entity/some-new-vendor.io", { demand: dataset, channel: "rest" });
    expect(r.status).toBe("not_found");
    expect(points.map((p) => p.blobs)).toEqual([["entity", "some-new-vendor.io", "rest", "not_found"]]);
  });

  it("records once when the query is also retried percent-decoded", async () => {
    const { dataset, points } = fakeDataset();
    const r = await resolveQuery(env.secid_REGISTRY, "secid:advisory/some-new-vendor.io/x%23ADV-1", { demand: dataset, channel: "mcp" });
    expect(r.status).toBe("not_found");
    expect(points).toHaveLength(1);
    expect(points[0].blobs).toEqual(["advisory", "some-new-vendor.io", "mcp", "not_found"]);
  });
});

describe("demand capture through the Worker's handlers", () => {
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

  it("REST /api/v1/resolve records a namespace miss with channel rest", async () => {
    const { dataset, points } = fakeDataset();
    const res = await worker.fetch(
      new Request("https://x/api/v1/resolve?secid=secid:entity/some-new-vendor.io"),
      { ...env, secid_DEMAND: dataset },
      ctx,
    );
    expect(((await res.json()) as { status: string }).status).toBe("not_found");
    expect(points.map((p) => p.blobs)).toEqual([["entity", "some-new-vendor.io", "rest", "not_found"]]);
  });

  const toolArgs: Record<string, Record<string, string>> = {
    resolve: { secid: "secid:entity/some-new-vendor.io" },
    lookup: { type: "entity", identifier: "some-new-vendor.io" },
    describe: { secid: "secid:entity/some-new-vendor.io" },
  };
  for (const tool of Object.keys(toolArgs)) {
    it(`MCP ${tool} records a namespace miss with channel mcp`, async () => {
      const { dataset, points } = fakeDataset();
      const res = await worker.fetch(
        new Request("https://x/mcp", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: { name: tool, arguments: toolArgs[tool] },
          }),
        }),
        { ...env, secid_DEMAND: dataset },
        ctx,
      );
      expect(res.status).toBe(200);
      expect(points.map((p) => p.blobs)).toEqual([["entity", "some-new-vendor.io", "mcp", "not_found"]]);
    });
  }
});
