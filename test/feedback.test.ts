import { describe, it, expect } from "vitest";
import { recordMiss, type MissRecord } from "../src/feedback";

// Minimal in-memory KV stand-in (recordMiss only uses get/put).
function makeKV() {
  const store = new Map<string, string>();
  const kv = {
    get: async (k: string) => store.get(k) ?? null,
    put: async (k: string, v: string) => {
      store.set(k, v);
    },
  };
  return { kv: kv as unknown as KVNamespace, store };
}

describe("recordMiss", () => {
  it("records a first miss with count 1 under the miss:<type>/<namespace> key", async () => {
    const { kv, store } = makeKV();
    await recordMiss(kv, "entity", "example.com", "secid:entity/example.com");

    const raw = store.get("miss:entity/example.com");
    expect(raw).toBeDefined();
    const rec = JSON.parse(raw!) as MissRecord;
    expect(rec.count).toBe(1);
    expect(rec.type).toBe("entity");
    expect(rec.namespace).toBe("example.com");
    expect(rec.sample_query).toBe("secid:entity/example.com");
    expect(rec.first_seen).toBe(rec.last_seen);
  });

  it("aggregates repeated misses: count increments, first_seen preserved", async () => {
    const { kv, store } = makeKV();
    // Seed an older record so first_seen is distinguishable from now.
    store.set(
      "miss:advisory/foo.com",
      JSON.stringify({
        type: "advisory",
        namespace: "foo.com",
        count: 3,
        first_seen: "2020-01-01T00:00:00.000Z",
        last_seen: "2020-01-01T00:00:00.000Z",
        sample_query: "secid:advisory/foo.com",
      }),
    );

    await recordMiss(kv, "advisory", "foo.com", "secid:advisory/foo.com/x#Y-1");

    const rec = JSON.parse(store.get("miss:advisory/foo.com")!) as MissRecord;
    expect(rec.count).toBe(4);
    expect(rec.first_seen).toBe("2020-01-01T00:00:00.000Z"); // preserved
    expect(rec.last_seen).not.toBe("2020-01-01T00:00:00.000Z"); // bumped
    expect(rec.sample_query).toBe("secid:advisory/foo.com/x#Y-1"); // latest sample
  });

  it("is a no-op (no throw) when KV is undefined", async () => {
    await expect(
      recordMiss(undefined, "entity", "example.com", "secid:entity/example.com"),
    ).resolves.toBeUndefined();
  });

  it("never throws if the KV write fails", async () => {
    const failingKv = {
      get: async () => null,
      put: async () => {
        throw new Error("kv down");
      },
    } as unknown as KVNamespace;
    await expect(
      recordMiss(failingKv, "entity", "example.com", "secid:entity/example.com"),
    ).resolves.toBeUndefined();
  });
});
