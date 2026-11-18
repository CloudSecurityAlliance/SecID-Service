import { describe, expect, it } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve } from "../src/resolver";
import { resolveQuery } from "../src/kv-resolve";
import type { Registry, RegistryNamespace, ResolveResponse } from "../src/types";

// Independent of the live registry: Service must deploy before the CWE data.
const ns: RegistryNamespace = {
  schema_version: "1.0", namespace: "test.example", type: "weakness", status: "draft",
  status_notes: null, official_name: "Test", common_name: null, alternate_names: null,
  notes: null, wikidata: null, wikipedia: null, urls: [],
  match_nodes: [{ patterns: ["^cwe$"], description: "CWE fixture", weight: 100,
    data: { version_required: false, versions_available: [
      { version: "5.0" }, { version: "4.19", aliases: [{ label: "old", on_match: "resolve" }] },
      { version: "empty" }, { version: "metadata-only" },
    ] },
    children: [
      { patterns: ["(?i)^CWE-(?:79|1448)$"], description: "Live", weight: 100,
        data: { url: "https://test.example/live/{id_upper}" } },
      // A version-shaped leaf remains an ordinary item, not a release tree.
      { patterns: ["^8\\.0$"], description: "Schema", weight: 100,
        data: { type: "version", url: "https://test.example/schema/8.0" } },
      ...["5.0", "4.19", "empty"].map((v) => ({
        patterns: ["^" + v.replaceAll(".", "\\.") + "$"], description: v, weight: 100,
        data: { type: "version", urls: [{ type: "bulk_data", url: `https://test.example/${v}.zip` }] },
        children: v === "empty" ? [] : [{
          patterns: [v === "5.0" ? "(?i)^CWE-(?:79|1448)$" : "(?i)^CWE-79$"],
          description: "Archive entry", weight: 100,
          data: { url: `https://test.example/${v}.zip`, content_type: "application/zip" },
        }],
      })),
    ],
  }],
};
const registry: Registry = { weakness: { "test.example": ns } };
const local = (query: string) => resolve(parseSecID(query, registry), registry);
const urls = (r: ResolveResponse) => r.results.flatMap((x) => "url" in x ? [x.url] : []);
const scoped = "secid:weakness/test.example/cwe";

describe("optional release branches", () => {
  it("preserves live scoped and cross-source item lookup", () => {
    for (const q of [`${scoped}#cwe-79`, "secid:weakness/CWE-79", "secid:weakness/test.example/CWE-79"]) {
      expect(urls(local(q))).toEqual(["https://test.example/live/CWE-79"]);
    }
  });
  it("finds bare lowercase IDs through the KV global index", async () => {
    const index = ns.match_nodes[0].children!.map((c) => ({ type: "weakness", namespace: ns.namespace,
      name_slug: "cwe", patterns: c.patterns, description: c.description, weight: c.weight, level: "child" }));
    const store: Record<string, unknown> = { "secid:*": { child_index: index },
      "secid:weakness/test.example": ns };
    const kv = { get: async (k: string) => store[k] ?? null } as unknown as KVNamespace;
    expect(urls(await resolveQuery(kv, "cwe-79"))).toEqual(["https://test.example/live/CWE-79"]);
  });
  it("honors explicit versions and aliases, including source descriptions", () => {
    for (const v of ["5.0", "4.19", "old"]) {
      const expected = v === "old" ? "4.19" : v;
      const r = local(`${scoped}@${v}#cwe-79`);
      expect(r.status).toBe("found");
      expect(urls(r)).toEqual([`https://test.example/${expected}.zip`]);
      expect(r.results[0].secid).toBe(`${scoped}@${expected}#cwe-79`);
      const description = local(`${scoped}@${v}`).results[0];
      expect("data" in description && description.data.urls).toEqual([{ type: "bulk_data", url: `https://test.example/${expected}.zip` }]);
    }
  });
  it("never substitutes live content for an absent release or item", () => {
    for (const q of ["@4.19#CWE-1448", "@5.0#CWE-999999", "@empty#CWE-79", "@missing#CWE-79", "@metadata-only#CWE-79"]) {
      const r = local(scoped + q);
      expect(r.status).not.toBe("found");
      expect(urls(r)).toEqual([]);
    }
  });
  it("does not confuse release branches with unversioned items", () => {
    expect(urls(local(`${scoped}#5.0`))).toEqual([]);
    expect(urls(local("secid:weakness/5.0"))).toEqual([]);
    expect(urls(local(`${scoped}#8.0`))).toEqual(["https://test.example/schema/8.0"]);
  });
});
