// scripts/export-misses.ts query builder and aggregation, against fixtures.
// Nothing here talks to Cloudflare.
import { describe, it, expect } from "vitest";
import {
  aggregateMisses,
  buildMissesQuery,
  registeredFrom,
  MAX_DAYS,
  type MissRow,
} from "../scripts/demand-export";

describe("buildMissesQuery", () => {
  it("defaults to the last 7 days of secid_demand_misses, weighted by sample interval", () => {
    const q = buildMissesQuery();
    expect(q).toContain("FROM secid_demand_misses");
    expect(q).toContain("WHERE timestamp > NOW() - INTERVAL '7' DAY");
    expect(q).toContain("SUM(_sample_interval) AS hits");
    expect(q).toContain("GROUP BY type, namespace, channel, status, day");
    expect(q).toContain("FORMAT JSON");
  });

  it("uses the requested window and dataset", () => {
    const q = buildMissesQuery({ days: 30, dataset: "other_ds" });
    expect(q).toContain("INTERVAL '30' DAY");
    expect(q).toContain("FROM other_ds");
  });

  it.each([0, -1, 1.5, MAX_DAYS + 1, Number.NaN])("rejects days=%s", (days) => {
    expect(() => buildMissesQuery({ days })).toThrow();
  });

  it.each(["x; DROP TABLE y", "a b", "ds'--", ""])("rejects dataset %j", (dataset) => {
    expect(() => buildMissesQuery({ dataset })).toThrow();
  });
});

const row = (r: Partial<MissRow>): MissRow => ({
  type: "entity",
  namespace: "newvendor.io",
  channel: "mcp",
  status: "not_found",
  day: "2026-09-20",
  hits: 1,
  first_seen: "2026-09-20 10:00:00",
  last_seen: "2026-09-20 10:00:00",
  ...r,
});

describe("aggregateMisses", () => {
  const registered = registeredFrom([
    { type: "entity", namespace: "redhat.com" },
    { type: "advisory", namespace: "newvendor.io" },
  ]);

  it("folds daily rows into one entry with count, distinct days, first/last seen and channels", () => {
    const out = aggregateMisses(
      [
        row({ hits: "3", day: "2026-09-20", first_seen: "2026-09-20 08:00:00", last_seen: "2026-09-20 22:00:00" }),
        row({ hits: 2, day: "2026-09-22", channel: "rest", first_seen: "2026-09-22 01:00:00", last_seen: "2026-09-22 02:00:00" }),
        row({ hits: 1, day: "2026-09-22", first_seen: "2026-09-22 05:00:00", last_seen: "2026-09-22 05:00:00" }),
      ],
      registered,
    );
    expect(out).toEqual([
      {
        type: "entity",
        namespace: "newvendor.io",
        count: 6,
        distinct_days: 2,
        first_seen: "2026-09-20T08:00:00Z",
        last_seen: "2026-09-22T05:00:00Z",
        channels: { mcp: 4, rest: 2 },
        statuses: { not_found: 6 },
        registered_as: ["advisory"],
      },
    ]);
  });

  it("drops namespaces registered for that type, case-insensitively", () => {
    const out = aggregateMisses([row({ namespace: "RedHat.com", hits: 50 })], registered);
    expect(out).toEqual([]);
  });

  it("keeps a namespace registered only under another type, and says so", () => {
    const out = aggregateMisses([row({ type: "advisory", namespace: "redhat.com" })], registered);
    expect(out.map((e) => [e.type, e.namespace, e.registered_as])).toEqual([["advisory", "redhat.com", ["entity"]]]);
  });

  it("sorts by count, then distinct days", () => {
    const out = aggregateMisses(
      [
        row({ namespace: "a.com", hits: 5, day: "2026-09-20" }),
        row({ namespace: "b.com", hits: 3, day: "2026-09-20" }),
        row({ namespace: "b.com", hits: 2, day: "2026-09-21" }),
        row({ namespace: "c.com", hits: 9 }),
      ],
      new Map(),
    );
    expect(out.map((e) => e.namespace)).toEqual(["c.com", "b.com", "a.com"]);
  });

  it("ignores rows with no usable count", () => {
    expect(aggregateMisses([row({ hits: "x" }), row({ hits: 0 })], new Map())).toEqual([]);
  });

  it("does not let stored keys alias Object.prototype", () => {
    const [e] = aggregateMisses([row({ channel: "__proto__" })], new Map());
    expect(Object.keys(e.channels)).toEqual(["__proto__"]);
  });
});
