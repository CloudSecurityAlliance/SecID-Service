import { describe, it, expect, beforeAll } from "vitest";
import { env } from "cloudflare:test";
import worker from "../src/index";
import type { TypeIndex } from "../src/types";

// Synthetic TypeIndex seeded directly. A type-only query short-circuits on the
// secid:{type} key, so this is all the filter path needs — and it keeps the
// test stable while the bundled registry snapshot lags the real one.
beforeAll(async () => {
  const index: TypeIndex = {
    type: "control",
    description: "test",
    namespace_count: 4,
    namespaces: [
      { namespace: "ismap.go.jp", official_name: "ISMAP", common_name: "ISMAP", source_count: 1, subtypes: [], country: ["JP"] },
      { namespace: "ipa.go.jp", official_name: "IPA", common_name: null, source_count: 1, subtypes: ["strategy"], country: ["JP"] },
      { namespace: "bsi.bund.de", official_name: "BSI", common_name: null, source_count: 1, subtypes: ["strategy"], country: ["DE"] },
      { namespace: "nist.gov", official_name: "NIST", common_name: "NIST", source_count: 1, subtypes: ["glossary"] },
    ],
    child_index: [],
  } as unknown as TypeIndex;
  await env.secid_REGISTRY.put("secid:control", JSON.stringify(index));
  await env.secid_REGISTRY.put(
    "secid:control/ismap.go.jp",
    JSON.stringify({
      namespace: "ismap.go.jp",
      type: "control",
      official_name: "ISMAP",
      common_name: "ISMAP",
      tags: { country: ["JP"] },
      match_nodes: [],
    })
  );
  await env.secid_REGISTRY.put(
    "secid:*",
    JSON.stringify({
      child_index: [],
      name_index: [{ type: "control", namespace: "ismap.go.jp", aliases: ["ismap"] }],
    })
  );
});

async function get(url: string) {
  const res = await worker.fetch(new Request(`https://x${url}`), env, {
    waitUntil: () => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext);
  return (await res.json()) as any;
}

const namespacesOf = (b: any): Array<{ namespace: string; country?: string[]; subtypes?: string[] }> =>
  b.results?.[0]?.data?.namespaces ?? [];

describe("country filter", () => {
  it("carries country through on a type listing", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control");
    expect(namespacesOf(body).filter((n) => n.country?.length).length).toBe(3);
  });

  it("filters a type listing by country via query param", async () => {
    const ns = namespacesOf(await get("/api/v1/resolve?secid=secid:control&country=JP"));
    expect(ns.map((n) => n.namespace).sort()).toEqual(["ipa.go.jp", "ismap.go.jp"]);
  });

  it("reports what was filtered out", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control&country=JP");
    expect(body.filter?.country).toBe("JP");
    expect(body.filter?.total_before_filter).toBe(4);
  });

  it("accepts the SecID wildcard + qualifier form", async () => {
    // the grammar's own shape: /* lists, ?country= filters
    const body = await get(
      "/api/v1/resolve?secid=" + encodeURIComponent("secid:control/*?country=DE")
    );
    expect(namespacesOf(body).map((n) => n.namespace)).toEqual(["bsi.bund.de"]);
  });

  it("accepts the type-only + inline qualifier form without wildcard", async () => {
    const body = await get(
      "/api/v1/resolve?secid=" + encodeURIComponent("secid:control?country=DE")
    );
    expect(namespacesOf(body).map((n) => n.namespace)).toEqual(["bsi.bund.de"]);
  });

  it("lists every namespace for a bare wildcard", async () => {
    const body = await get("/api/v1/resolve?secid=" + encodeURIComponent("secid:control/*"));
    expect(namespacesOf(body)).toHaveLength(4);
  });

  it("matches country codes case-insensitively", async () => {
    const ns = namespacesOf(await get("/api/v1/resolve?secid=secid:control&country=jp"));
    expect(ns).toHaveLength(2);
  });

  it("explains an empty result rather than returning a bare empty list", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control&country=ZZ");
    expect(namespacesOf(body)).toHaveLength(0);
    expect(body.message).toMatch(/ZZ/);
  });

  it("leaves an untagged namespace out rather than guessing", async () => {
    // nist.gov has no country tag; a .gov TLD implies nothing mechanically
    const ns = namespacesOf(await get("/api/v1/resolve?secid=secid:control&country=US"));
    expect(ns).toHaveLength(0);
  });

  it("leaves the existing subtype filter working", async () => {
    const ns = namespacesOf(await get("/api/v1/resolve?secid=secid:control&subtype=glossary"));
    expect(ns.map((n) => n.namespace)).toEqual(["nist.gov"]);
  });

  it("composes subtype and country filters via query params (#59)", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control&subtype=strategy&country=JP");
    expect(namespacesOf(body).map((n) => n.namespace)).toEqual(["ipa.go.jp"]);
    expect(body.filter).toEqual({
      subtype: "strategy",
      country: "JP",
      total_before_filter: 4,
    });
  });

  it("composes subtype and country filters via inline SecID qualifiers (#59)", async () => {
    const body = await get(
      "/api/v1/resolve?secid=" + encodeURIComponent("secid:control?subtype=strategy&country=de")
    );
    expect(namespacesOf(body).map((n) => n.namespace)).toEqual(["bsi.bund.de"]);
    expect(body.filter).toEqual({
      subtype: "strategy",
      country: "de",
      total_before_filter: 4,
    });
  });

  it("explains when combined subtype and country filters match nothing (#59)", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control&subtype=glossary&country=JP");
    expect(namespacesOf(body)).toHaveLength(0);
    expect(body.filter).toEqual({
      subtype: "glossary",
      country: "JP",
      total_before_filter: 4,
    });
    expect(body.message).toBe('No namespaces with subtype "glossary" and country "JP" found in this type.');
  });

  it("preserves filter metadata on an empty namespace source listing (#60)", async () => {
    const body = await get("/api/v1/resolve?secid=secid:control/ismap.go.jp&country=JP");
    expect(body.status).toBe("found");
    expect(body.results).toEqual([]);
    expect(body.filter).toEqual({
      country: "JP",
      total_before_filter: 0,
    });
  });

  it("does not clear a typeScopedSearch identity result for a URL-less empty-match_nodes namespace", async () => {
    const body = await get("/api/v1/resolve?secid=" + encodeURIComponent("secid:control/ISMAP") + "&country=JP");
    expect(body.status).toBe("found");
    expect(body.results).toHaveLength(1);
    expect(body.results[0].secid).toBe("secid:control/ismap.go.jp");
    expect(body.results[0].data?.weight).toBe(90);
    expect(body.filter).toBeUndefined();
  });
});
