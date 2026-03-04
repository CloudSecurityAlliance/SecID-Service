import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve } from "../src/resolver";
import { REGISTRY } from "../src/registry";
import type { ResolutionResult, RegistryResult, ResolveResponse, MatchNode, ExampleObject } from "../src/types";

// Helper: parse + resolve in one step
function resolveSecID(input: string): ResolveResponse {
  return resolve(parseSecID(input, REGISTRY), REGISTRY);
}

// ── Auto-Generated Tests from Registry Examples ──
// Walk all JSON registry files, extract structured ExampleObject entries from
// children's data.examples, and turn each into a test case.

describe("registry example fixtures", () => {
  const fixtures: Array<{
    secid: string;
    expectedUrl: string;
    note?: string;
  }> = [];

  // Walk all types and namespaces
  for (const [type, namespaces] of Object.entries(REGISTRY)) {
    for (const [nsKey, ns] of Object.entries(namespaces)) {
      for (const node of ns.match_nodes) {
        const nameSlug = extractTestNameSlug(node);

        // Check children for structured examples
        if (node.children) {
          for (const child of node.children) {
            if (!child.data.examples) continue;
            for (const ex of child.data.examples) {
              if (typeof ex === "string") continue;
              const exObj = ex as ExampleObject;
              if (!exObj.input || !exObj.url) continue;

              // Build the secid query
              const version = exObj.version ? `@${exObj.version}` : "";
              const secid = `secid:${type}/${nsKey}/${nameSlug}${version}#${exObj.input}`;
              fixtures.push({
                secid,
                expectedUrl: exObj.url,
                note: exObj.note,
              });
            }
          }

          // Also check grandchildren (version-required sources like OWASP)
          for (const child of node.children) {
            if (!child.children) continue;
            for (const grandchild of child.children) {
              if (!grandchild.data.examples) continue;
              for (const ex of grandchild.data.examples) {
                if (typeof ex === "string") continue;
                const exObj = ex as ExampleObject;
                if (!exObj.input || !exObj.url) continue;

                // Use version from the example if available, otherwise derive from pattern
                const exVersion = exObj.version
                  ?? child.patterns[0]?.replace(/[\^$\\]/g, "");
                const version = exVersion ? `@${exVersion}` : "";
                const secid = `secid:${type}/${nsKey}/${nameSlug}${version}#${exObj.input}`;
                fixtures.push({
                  secid,
                  expectedUrl: exObj.url,
                  note: exObj.note,
                });
              }
            }
          }
        }
      }
    }
  }

  it(`has fixtures extracted from registry (sanity check)`, () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });

  // Generate a test for each fixture
  for (const fixture of fixtures) {
    it(`resolves ${fixture.secid}`, () => {
      const result = resolveSecID(fixture.secid);
      expect(result.status).toBe("found");
      const urls = result.results
        .filter((r): r is ResolutionResult => "url" in r)
        .map((r) => r.url);
      expect(urls).toContain(fixture.expectedUrl);
    });
  }
});

// ── Manual Tests: Variable Extraction ──

describe("variable extraction", () => {
  it("resolves CVE with year and bucket variables", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2021-44228");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    // Primary CVE.org URL
    expect(urls).toContain("https://www.cve.org/CVERecord?id=CVE-2021-44228");
    // GitHub cvelistV5 URL with bucket
    expect(urls).toContain(
      "https://github.com/CVEProject/cvelistV5/blob/main/cves/2021/44xxx/CVE-2021-44228.json"
    );
  });

  it("returns multiple results with different weights for CVE", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2024-1234");
    expect(r.status).toBe("found");
    const resolutions = r.results.filter(
      (r): r is ResolutionResult => "url" in r
    );
    // Should have at least 2 results (web + github, maybe API)
    expect(resolutions.length).toBeGreaterThanOrEqual(2);
    // First result should have highest weight
    expect(resolutions[0].weight).toBeGreaterThanOrEqual(resolutions[1].weight);
  });

  it("resolves SUSE-SU with colon-in-ID variable extraction", () => {
    const r = resolveSecID("secid:advisory/suse.com/suse-su#SUSE-SU-2024:0001-1");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    expect(urls.length).toBeGreaterThan(0);
    // URL should contain the year and formatted number
    expect(urls[0]).toContain("2024");
  });
});

// ── Manual Tests: Range Table ──

describe("range table lookup", () => {
  it("resolves Debian DSA with year derived from range table", () => {
    const r = resolveSecID("secid:advisory/debian.org/dsa#DSA-5678-1");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    // DSA-5678: 5678 >= 5593 (2024 start) → year 2024
    expect(urls[0]).toContain("/2024/");
    expect(urls[0]).toContain("dsa-5678");
  });

  it("resolves earlier DSA to correct year", () => {
    const r = resolveSecID("secid:advisory/debian.org/dsa#DSA-2500-1");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    // DSA-2500: 2500 >= 2377 (2012 start) but < 2597 (2013 start) → 2012
    expect(urls[0]).toContain("/2012/");
  });
});

// ── Manual Tests: Lookup Table (OWASP Top 10) ──

describe("lookup table resolution", () => {
  it("resolves OWASP Top 10 2021 A01 via lookup table", () => {
    const r = resolveSecID("secid:weakness/owasp.org/top10@2021#A01");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls[0]).toContain("owasp.org");
  });
});

// ── Manual Tests: Version-Required Without Version ──

describe("version-required handling", () => {
  it("returns related status when version is missing", () => {
    const r = resolveSecID("secid:weakness/owasp.org/top10#A01");
    expect(r.status).toBe("related");
    expect(r.message).toContain("version");
  });
});

// ── Manual Tests: Cross-Source Search ──

describe("cross-source search", () => {
  it("finds CVE across namespaces (type-scoped)", () => {
    const r = resolveSecID("secid:advisory/CVE-2024-1234");
    // Should find results across multiple namespaces
    expect(r.results.length).toBeGreaterThan(0);
    const secids = r.results.map((r) => (r as ResolutionResult | RegistryResult).secid);
    // At minimum, mitre.org/cve should be present
    expect(secids.some((s) => s.includes("mitre.org"))).toBe(true);
  });
});

// ── Manual Tests: Progressive Resolution ──

describe("progressive resolution", () => {
  it("type-only returns namespace listing", () => {
    const r = resolveSecID("secid:advisory");
    expect(r.status).toBe("found");
    expect(r.results.length).toBeGreaterThan(0);
    // All results should be RegistryResults
    for (const result of r.results) {
      expect(result).toHaveProperty("data");
    }
  });

  it("type+namespace returns source listing", () => {
    const r = resolveSecID("secid:advisory/mitre.org");
    expect(r.status).toBe("found");
    expect(r.results.length).toBeGreaterThan(0);
    for (const result of r.results) {
      expect(result).toHaveProperty("data");
    }
  });

  it("type+namespace+name returns source detail", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve");
    expect(r.status).toBe("found");
    expect(r.results.length).toBe(1);
    const data = (r.results[0] as RegistryResult).data;
    expect(data).toHaveProperty("official_name");
    expect(data).toHaveProperty("urls");
  });
});

// ── Manual Tests: RHSA (Colon in ID) ──

describe("colon-in-ID handling", () => {
  it("resolves RHSA with colon preserved", () => {
    const r = resolveSecID("secid:advisory/redhat.com/errata#RHSA-2024:1234");
    expect(r.status).toBe("found");
    const urls = r.results
      .filter((r): r is ResolutionResult => "url" in r)
      .map((r) => r.url);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls[0]).toContain("RHSA-2024:1234");
  });
});

// ── Manual Tests: Error Cases ──

describe("error cases", () => {
  it("returns error for empty input", () => {
    const r = resolveSecID("");
    expect(r.status).toBe("error");
  });

  it("returns not_found for invalid type", () => {
    const r = resolveSecID("secid:frobnicate/mitre.org/cve");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("Valid types");
  });

  it("returns not_found for unregistered namespace", () => {
    const r = resolveSecID("secid:advisory/unknown.org/foo");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("unknown.org");
  });
});

// ── Helper ──

function extractTestNameSlug(node: MatchNode): string {
  const pat = node.patterns[0] ?? "";
  const cleaned = pat
    .replace(/^\(\?i\)/i, "")
    .replace(/^\^/, "")
    .replace(/\$$/, "");
  if (/^[\w-]+$/.test(cleaned)) {
    return cleaned.toLowerCase();
  }
  return node.description.toLowerCase().replace(/\s+/g, "-");
}
