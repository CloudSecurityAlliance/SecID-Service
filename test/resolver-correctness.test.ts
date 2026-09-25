// Resolver correctness: percent-decoding order, @version handling, bare-search
// not_found, own-property lookups, note pass-through, URL template safety and
// pattern caching.
import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { resolveFromKV, resolveQuery } from "../src/kv-resolve";
import { parseSecID } from "../src/parser";
import { resolve, toRegExp } from "../src/resolver";
import { REGISTRY } from "../src/registry";
import type { Registry, RegistryNamespace, ResolveResponse, TypeIndex } from "../src/types";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY!);
});

const resolveLocal = (q: string) => resolve(parseSecID(q, REGISTRY), REGISTRY);
const secids = (r: ResolveResponse) => r.results.map((x) => (x as { secid: string }).secid);

async function rest(query: string): Promise<ResolveResponse & { status: string }> {
  const res = await SELF.fetch(`https://test.local/api/v1/resolve?secid=${query}`);
  return (await res.json()) as ResolveResponse;
}

/** A one-namespace registry, for behaviour the real registry has no example of. */
function fakeNamespace(match_nodes: RegistryNamespace["match_nodes"]): RegistryNamespace {
  return {
    schema_version: "1.0",
    namespace: "test.example",
    type: "reference",
    status: "draft",
    status_notes: null,
    official_name: "Test",
    common_name: null,
    alternate_names: null,
    notes: null,
    wikidata: null,
    wikipedia: null,
    urls: [],
    match_nodes,
  };
}

/** KV stand-in serving a single-namespace reference registry. */
function fakeKv(ns: RegistryNamespace): KVNamespace {
  const typeIndex: TypeIndex = {
    type: "reference",
    description: "test",
    namespace_count: 1,
    namespaces: [{ namespace: ns.namespace, official_name: ns.official_name, common_name: null, source_count: 1 }],
    child_index: ns.match_nodes.flatMap((n) =>
      (n.children ?? []).map((c) => ({
        namespace: ns.namespace,
        name_slug: "items",
        patterns: c.patterns,
        description: c.description,
        weight: c.weight,
        has_url: !!c.data.url,
      })),
    ),
  };
  const store: Record<string, unknown> = {
    "secid:reference": typeIndex,
    [`secid:reference/${ns.namespace}`]: ns,
  };
  return { get: async (k: string) => store[k] ?? null } as unknown as KVNamespace;
}

describe("percent-decoding: as-is first, decoded only as a fallback (L1)", () => {
  it("keeps a literal '%' instead of rejecting it as malformed", async () => {
    const body = await rest(encodeURIComponent("secid:reference/github.com/users#x%zz"));
    expect(body.status).not.toBe("error");
    expect(body.message ?? "").not.toContain("Malformed");
    expect(body.secid_query).toBe("secid:reference/github.com/users#x%zz");
  });

  it("tries an escape literally, and decodes it only when the literal form does not resolve", async () => {
    // Hono decodes %252D to %2D. "CVE%2D2024-1234" matches no CVE pattern;
    // decoded once it is CVE-2024-1234. Before, the handler decoded eagerly.
    const body = await rest("secid:advisory/mitre.org/cve%23CVE%252D2024-1234");
    expect(body.status).toBe("found");
    expect(body.secid_query).toBe("secid:advisory/mitre.org/cve#CVE%2D2024-1234");
    expect(secids(body)[0]).toBe("secid:advisory/mitre.org/cve#CVE-2024-1234");
  });

  it("prefers the as-is form when it resolves", async () => {
    const kv = fakeKv(
      fakeNamespace([
        {
          patterns: ["(?i)^items$"],
          description: "Items",
          weight: 100,
          data: {},
          children: [
            { patterns: ["^[A-Za-z0-9%]+$"], description: "Item", weight: 100, data: { url: "https://test.example/{id}" } },
          ],
        },
      ]),
    );
    const r = await resolveQuery(kv, "secid:reference/test.example/items#x%41");
    expect(r.status).toBe("found");
    expect(secids(r)).toEqual(["secid:reference/test.example/items#x%41"]);
  });

  it("resolves A&A-01 sent as %26 exactly once", async () => {
    const body = await rest("secid:control/cloudsecurityalliance.org/ccm%23A%26A-01");
    expect(body.status).toBe("found");
    expect(secids(body)[0]).toBe("secid:control/cloudsecurityalliance.org/ccm#A&A-01");
  });

  it("still rescues a doubly-encoded '#'", async () => {
    const body = await rest("secid:advisory/mitre.org/cve%2523CVE-2024-1234");
    expect(body.status).toBe("found");
    expect(secids(body)[0]).toBe("secid:advisory/mitre.org/cve#CVE-2024-1234");
  });

  it("MCP resolve decodes an encoded '#' as a fallback too", async () => {
    const r = await resolveQuery(env.secid_REGISTRY!, "secid:advisory/mitre.org/cve%23CVE-2024-1234");
    expect(r.status).toBe("found");
    expect(r.secid_query).toBe("secid:advisory/mitre.org/cve%23CVE-2024-1234");
  });
});

describe("@version the source does not have (M2)", () => {
  it("unversioned source: corrected, version dropped, no message", () => {
    const r = resolveLocal("secid:advisory/mitre.org/cve@bogus#CVE-2024-1234");
    expect(r.status).toBe("corrected");
    expect(r).not.toHaveProperty("message");
    expect(secids(r).every((s) => !s.includes("@bogus"))).toBe(true);
    expect(secids(r)).toContain("secid:advisory/mitre.org/cve#CVE-2024-1234");
  });

  it("source listing versions: unknown version is related, with the available list", () => {
    const r = resolveLocal("secid:control/nist.gov/csf@9.9");
    expect(r.status).toBe("related");
    expect(r.message).toMatch(/Known versions: 2\.0\b.*1\.1\b/);
    expect(secids(r)).toEqual(["secid:control/nist.gov/csf"]);
  });

  it("source listing versions: unknown version with a subpath is not_found, never another version's item", () => {
    const r = resolveLocal("secid:control/nist.gov/csf@9.9#PR.AC-1");
    expect(r.status).toBe("not_found");
    expect(r.results).toEqual([]);
    expect(r.message).toContain("https://github.com/CloudSecurityAlliance/SecID/issues");
  });

  it("listed version still resolves as found", () => {
    const r = resolveLocal("secid:control/nist.gov/csf@2.0");
    expect(r.status).toBe("found");
    expect(secids(r)).toEqual(["secid:control/nist.gov/csf@2.0"]);
  });

  it("case-only difference is corrected to the source's spelling", () => {
    const r = resolveLocal("secid:control/nist.gov/800-53@REV5#AC-1");
    expect(r.status).toBe("corrected");
    expect(r).not.toHaveProperty("message");
    expect(secids(r)[0]).toBe("secid:control/nist.gov/800-53@rev5#AC-1");
  });

  it("version-required source without a subpath: unknown version is related with versions_available", () => {
    const r = resolveLocal("secid:weakness/owasp.org/top10@bogus");
    expect(r.status).toBe("related");
    const data = (r.results[0] as unknown as { data: { versions_available: unknown[] } }).data;
    expect(data.versions_available.length).toBeGreaterThan(0);
  });

  it("version-required source with a subpath: unknown version is not_found with guidance (ADR-015)", () => {
    const r = resolveLocal("secid:weakness/owasp.org/top10@1999#A01");
    expect(r.status).toBe("not_found");
    expect(r.results).toEqual([]);
    expect(r.message).toContain("Known versions:");
    expect(r.message).toContain("submit_feedback");
    expect(r.message).toContain("https://github.com/CloudSecurityAlliance/SecID/issues");
  });

  it("no corrected response carries a message (API-RESPONSE-FORMAT.md)", () => {
    for (const q of [
      "secid:advisory/mitre.org/cve@bogus#CVE-2024-1234",
      "secid:control/nist.gov/800-53@REV5#AC-1",
      "secid:advisory/redhat.com/RHSA-2026:1234",
    ]) {
      const r = resolveLocal(q);
      expect(r.status, q).toBe("corrected");
      expect(r, q).not.toHaveProperty("message");
    }
  });

  it("version-required source: known version unchanged", () => {
    expect(resolveLocal("secid:weakness/owasp.org/top10@2021").status).toBe("found");
    expect(resolveLocal("secid:weakness/owasp.org/top10@2021#A01").status).toBe("found");
  });
});

describe("version aliases (ADR-015)", () => {
  const AICM = "secid:control/cloudsecurityalliance.org/aicm";
  const CAIQ = "secid:control/cloudsecurityalliance.org/aicm-caiq";

  for (const label of ["1.1", "v1.1"]) {
    it(`aicm@${label} echoes the canonical version 1.1.1`, () => {
      const r = resolveLocal(`${AICM}@${label}#LOG-15`);
      expect(r.status).toBe("found");
      expect(r.secid_query).toBe(`${AICM}@${label}#LOG-15`);
      expect(secids(r).length).toBeGreaterThan(0);
      expect(secids(r).every((s) => s === `${AICM}@1.1.1#LOG-15`)).toBe(true);
    });
  }

  it("aicm@1.1 without a subpath describes 1.1.1", () => {
    const r = resolveLocal(`${AICM}@1.1`);
    expect(r.status).toBe("found");
    expect(secids(r)).toEqual([`${AICM}@1.1.1`]);
  });

  it("aicm@1.1.0 is a real version and stays unchanged", () => {
    const r = resolveLocal(`${AICM}@1.1.0#LOG-15`);
    expect(r.status).toBe("found");
    expect(secids(r).every((s) => s === `${AICM}@1.1.0#LOG-15`)).toBe(true);
  });

  it("aicm@1.1.1 resolves as itself", () => {
    const r = resolveLocal(`${AICM}@1.1.1#LOG-15`);
    expect(r.status).toBe("found");
    expect(secids(r).every((s) => s === `${AICM}@1.1.1#LOG-15`)).toBe(true);
  });

  for (const label of ["1.1", "v1.1"]) {
    it(`AI-CAIQ (aicm-caiq)@${label} echoes 1.1.0`, () => {
      const r = resolveLocal(`${CAIQ}@${label}#LOG-15.1`);
      expect(r.status).toBe("found");
      expect(secids(r).length).toBeGreaterThan(0);
      expect(secids(r).every((s) => s === `${CAIQ}@1.1.0#LOG-15.1`)).toBe(true);
    });
  }

  it("the REST path echoes the canonical version too", async () => {
    const body = await rest(`${AICM}@1.1%23LOG-15`);
    expect(body.status).toBe("found");
    expect(secids(body)[0]).toBe(`${AICM}@1.1.1#LOG-15`);
  });

  it("aicm@9.9#LOG-15 is not_found with the version list and the issues link", () => {
    const r = resolveLocal(`${AICM}@9.9#LOG-15`);
    expect(r.status).toBe("not_found");
    expect(r.results).toEqual([]);
    expect(r.message).toContain("1.1.1 (current");
    expect(r.message).toContain("aliases 1.1, v1.1");
    expect(r.message).toContain("https://github.com/CloudSecurityAlliance/SecID/issues");
  });

  describe("on_match redirect", () => {
    const registry: Registry = {
      reference: {
        "test.example": fakeNamespace([
          {
            patterns: ["(?i)^spec$"],
            description: "Versioned spec",
            weight: 100,
            data: {
              version_required: true,
              versions_available: [
                { version: "2.0", status: "current", aliases: [{ label: "2", on_match: "redirect" }] },
              ],
            },
            children: [
              {
                patterns: ["^2\\.0$", "^2$"],
                description: "Spec 2.0",
                weight: 100,
                data: {},
                children: [
                  { patterns: ["^S-\\d+$"], description: "Section", weight: 100, data: { url: "https://test.example/2.0/{id}" } },
                ],
              },
            ],
          },
        ]),
      },
    };
    const run = (q: string) => resolve(parseSecID(q, registry), registry);

    it("returns corrected with no results and the canonical SecID in the message", () => {
      const r = run("secid:reference/test.example/spec@2#S-1");
      expect(r.status).toBe("corrected");
      expect(r.results).toEqual([]);
      expect(r.message).toContain("secid:reference/test.example/spec@2.0#S-1");
    });

    it("the canonical version resolves normally", () => {
      const r = run("secid:reference/test.example/spec@2.0#S-1");
      expect(r.status).toBe("found");
      expect(secids(r)).toEqual(["secid:reference/test.example/spec@2.0#S-1"]);
    });
  });
});

describe("bare search that matches nothing (L4)", () => {
  it("is not_found with search guidance, not 'Invalid type'", async () => {
    const r = await resolveFromKV(env.secid_REGISTRY!, "zzqqxxnonsense");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("No matches");
    expect(r.message).not.toContain("Invalid type");
  });

  it("an explicit secid: with an unknown type still reports the invalid type", async () => {
    const r = await resolveFromKV(env.secid_REGISTRY!, "secid:frobnicate/mitre.org");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("Invalid type");
  });
});

describe("own-property and pass-through fixes", () => {
  const registry: Registry = {
    reference: {
      "test.example": fakeNamespace([
        {
          patterns: ["(?i)^items$"],
          description: "Items",
          weight: 100,
          data: {},
          children: [
            {
              patterns: ["^[a-z]+$"],
              description: "Lookup item",
              weight: 100,
              data: { lookup_table: { alpha: "https://test.example/alpha" } },
            },
            {
              patterns: ["^ITEM-\\d+$"],
              description: "URL-less item",
              weight: 90,
              data: { note: "Look this up in the printed catalogue." },
            },
          ],
        },
      ]),
    },
  };

  it("lookup_table ignores Object.prototype members (L5)", () => {
    const r = resolve(parseSecID("secid:reference/test.example/items#constructor", registry), registry);
    expect(r.results.some((x) => "url" in x)).toBe(false);
    const ok = resolve(parseSecID("secid:reference/test.example/items#alpha", registry), registry);
    expect((ok.results[0] as { url: string }).url).toBe("https://test.example/alpha");
  });

  it("type-scoped search keeps a URL-less item's note (L6)", () => {
    const r = resolve(parseSecID("secid:reference/ITEM-7", registry), registry);
    expect(r.status).toBe("found");
    expect((r.results[0] as unknown as { data: { note: string } }).data.note).toBe("Look this up in the printed catalogue.");
  });

  it("namespace-scoped search keeps it too", () => {
    const r = resolve(parseSecID("secid:reference/test.example/ITEM-7", registry), registry);
    expect(r.status).toBe("corrected");
    expect((r.results[0] as unknown as { data: { note: string } }).data.note).toBe("Look this up in the printed catalogue.");
  });
});

describe("pattern compilation cache (L2)", () => {
  it("returns the same RegExp for the same pattern", () => {
    expect(toRegExp("(?i)^cve$")).toBe(toRegExp("(?i)^cve$"));
    expect(toRegExp("(?i)^cve$").test("CVE")).toBe(true);
  });

  it("keeps throwing for an invalid pattern", () => {
    expect(() => toRegExp("(")).toThrow();
    expect(() => toRegExp("(")).toThrow();
  });
});
