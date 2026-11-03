import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { resolve, buildUrl } from "../src/resolver";
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

// ── Manual Tests: Content Type ──

describe("content_type on results", () => {
  it("includes content_type from registry on resolution results", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2024-1234");
    expect(r.status).toBe("found");
    const resolutions = r.results.filter((r): r is ResolutionResult => "url" in r);
    // cve.org result should have text/html
    const cveOrg = resolutions.find((r) => r.url.includes("cve.org"));
    expect(cveOrg?.content_type).toBe("text/html");
    // API result should have application/json
    const api = resolutions.find((r) => r.url.includes("cveawg.mitre.org"));
    expect(api?.content_type).toBe("application/json");
    // Raw GitHub result should have application/json
    const raw = resolutions.find((r) => r.url.includes("raw.githubusercontent.com"));
    expect(raw?.content_type).toBe("application/json");
  });

  it("filters results by content_type qualifier", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2024-1234?content_type=application/json");
    expect(r.status).toBe("found");
    const resolutions = r.results.filter((r): r is ResolutionResult => "url" in r);
    // Should only have JSON results (API + raw GitHub)
    for (const res of resolutions) {
      expect(res.content_type).toBe("application/json");
    }
    expect(resolutions.length).toBe(2);
  });

  it("returns not_found when content_type has no matches", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2024-1234?content_type=application/pdf");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("application/pdf");
    expect(r.message).toContain("Available");
  });

  it("source-level qualifier filters same as item-level", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve?content_type=application/json#CVE-2024-1234");
    expect(r.status).toBe("found");
    const resolutions = r.results.filter((r): r is ResolutionResult => "url" in r);
    for (const res of resolutions) {
      expect(res.content_type).toBe("application/json");
    }
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

// ── Resolver-side URL validation (F-01-01) ──
// buildUrl must encode user-derived values and refuse to emit a URL whose
// scheme/authority differs from the template's literal scheme/host.

describe("buildUrl URL validation (F-01-01)", () => {
  it("substitutes a normal path-position {id}, host unchanged", () => {
    expect(buildUrl("https://www.cve.org/CVERecord?id={id}", { id: "CVE-2021-44228" }))
      .toBe("https://www.cve.org/CVERecord?id=CVE-2021-44228");
  });

  it("preserves reserved characters in identifiers on the template's own host", () => {
    // RHSA IDs contain a colon — it must NOT be mangled (regression guard).
    expect(buildUrl("https://access.redhat.com/errata/{id}", { id: "RHSA-2024:1234" }))
      .toBe("https://access.redhat.com/errata/RHSA-2024:1234");
    // '/' and ':' stay literal (DOIs, owner/repo); '?' would end the path
    // early and start a query the template never declared, so it is encoded.
    expect(buildUrl("https://host.example/{id}", { id: "a/b:c?d=e" }))
      .toBe("https://host.example/a/b:c%3Fd=e");
    // '&' is literal in a path (CCM A&A-01).
    expect(buildUrl("https://host.example/controls/{id}", { id: "A&A-01" }))
      .toBe("https://host.example/controls/A&A-01");
  });

  it("drops a result when substitution changes the host (authority injection)", () => {
    expect(buildUrl("https://{id}.example.com/", { id: "evil.com" })).toBeNull();
    expect(buildUrl("https://{id}/path", { id: "evil.com" })).toBeNull();
  });

  it("refuses a non-absolute or non-http(s) template", () => {
    expect(buildUrl("/relative/{id}", { id: "x" })).toBeNull();
    expect(buildUrl("{id}", { id: "https://evil.example/" })).toBeNull();
    expect(buildUrl("javascript:alert({id})", { id: "1" })).toBeNull();
  });

  it("encodes query separators so a value cannot add or split parameters", () => {
    expect(buildUrl("https://host.example/search?q={id}&lang=en", { id: "A&A-01+x" }))
      .toBe("https://host.example/search?q=A%26A-01%2Bx&lang=en");
    expect(buildUrl("https://host.example/search?q={id}", { id: "x#frag" }))
      .toBe("https://host.example/search?q=x%23frag");
  });

  it("refuses dot-segments that would climb out of the template's path", () => {
    expect(buildUrl("https://host.example/advisories/{id}", { id: "../admin" })).toBeNull();
    expect(buildUrl("https://host.example/advisories/{id}", { id: "a/../../admin" })).toBeNull();
    expect(buildUrl("https://host.example/advisories/{id}", { id: ".." })).toBeNull();
    // Percent-encoded dot-segments are defused by encoding '%'.
    expect(buildUrl("https://host.example/advisories/{id}", { id: "%2e%2e/admin" }))
      .toBe("https://host.example/advisories/%252e%252e/admin");
    // Backslash is a path separator to the WHATWG parser.
    expect(buildUrl("https://host.example/advisories/{id}", { id: "a\\b" }))
      .toBe("https://host.example/advisories/a%5Cb");
    // Dots inside a segment are ordinary identifier characters.
    expect(buildUrl("https://host.example/{id}", { id: "T1059.003" }))
      .toBe("https://host.example/T1059.003");
  });

  it("does not re-expand placeholders that appear inside a substituted value", () => {
    expect(buildUrl("https://host.example/{id}/{year}", { id: "{year}", year: "2024" }))
      .toBe("https://host.example/{year}/2024");
  });
});

describe("qualifier filtering across cross-source and subpath resolution (#55)", () => {
  it("filters type-scoped cross-source search by ?parsability=structured and excludes URL-less notes", () => {
    const r = resolveSecID("secid:advisory/CVE-2026-0019?parsability=structured");
    expect(r.status).toBe("found");
    expect(r.results.length).toBeGreaterThan(0);
    for (const entry of r.results) {
      expect("url" in entry).toBe(true);
      expect((entry as { parsability?: string }).parsability).toBe("structured");
    }
  });

  it("filters type-scoped cross-source search by combined ?parsability=structured&content_type=application/json", () => {
    const r = resolveSecID("secid:advisory/CVE-2026-0019?parsability=structured&content_type=application/json");
    expect(r.status).toBe("found");
    expect(r.results.length).toBeGreaterThan(0);
    for (const entry of r.results) {
      expect("url" in entry).toBe(true);
      expect((entry as { parsability?: string }).parsability).toBe("structured");
      expect((entry as { content_type?: string }).content_type).toBe("application/json");
    }
  });

  it("filters namespace-scoped corrected search by ?parsability=structured", () => {
    const r = resolveSecID("secid:advisory/mitre.org/CVE-2026-0019?parsability=structured");
    expect(r.status).toBe("corrected");
    expect(r.results.length).toBe(2);
    for (const entry of r.results) {
      expect((entry as { parsability?: string }).parsability).toBe("structured");
      expect((entry as { content_type?: string }).content_type).toBe("application/json");
    }
  });

  it("reports available parsability values when ?parsability filter removes all results", () => {
    const r = resolveSecID("secid:advisory/debian.org/tracker#CVE-2026-0019?parsability=structured");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain('No results with parsability "structured". Available: scraped.');
  });

  it("reports combined qualifier mismatch when each qualifier exists on different results", () => {
    const r = resolveSecID("secid:advisory/mitre.org/cve#CVE-2026-0019?parsability=structured&content_type=text/html");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain("No results matched the combined qualifiers");
  });

  it("returns not_found when ?parsability=structured is applied to a URL-less note source", () => {
    const r = resolveSecID("secid:advisory/oracle.com/vm#OVMSA-2024-0001?parsability=structured");
    expect(r.status).toBe("not_found");
    expect(r.message).toContain('No results with parsability "structured"');
  });
});

describe("vendor-specific CVE resolution and structured API filtering (#218)", () => {
  it("resolves Red Hat CVE-2023-44487 across redhat.com/cve (HTML + Hydra JSON) and redhat.com/bugzilla", () => {
    const cve = resolveSecID("secid:advisory/redhat.com/cve#CVE-2023-44487");
    expect(cve.status).toBe("found");
    const cveUrls = cve.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(cveUrls).toContain("https://access.redhat.com/security/cve/CVE-2023-44487");
    expect(cveUrls).toContain("https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-44487.json");

    const structured = resolveSecID("secid:advisory/redhat.com/cve#CVE-2023-44487?parsability=structured");
    expect(structured.status).toBe("found");
    const structuredUrls = structured.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(structuredUrls).toEqual(["https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-44487.json"]);

    const bz = resolveSecID("secid:advisory/redhat.com/bugzilla#CVE-2023-44487");
    expect(bz.status).toBe("found");
    const bzUrls = bz.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(bzUrls).toEqual(["https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2023-44487"]);
  });

  it("resolves Microsoft CVE-2024-21412 across MSRC HTML and SUG v2.0 JSON API", () => {
    const msrc = resolveSecID("secid:advisory/microsoft.com/msrc#CVE-2024-21412");
    expect(msrc.status).toBe("found");
    const urls = msrc.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(urls).toContain("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412");
    expect(urls).toContain("https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2024-21412");

    const structured = resolveSecID("secid:advisory/microsoft.com/msrc#CVE-2024-21412?parsability=structured");
    expect(structured.status).toBe("found");
    const structuredUrls = structured.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(structuredUrls).toEqual(["https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2024-21412"]);
  });

  it("resolves Palo Alto Networks CVE-2024-3400 across HTML, CVE JSON 5.x, and CSAF JSON", () => {
    const pan = resolveSecID("secid:advisory/paloaltonetworks.com/pan-sa#CVE-2024-3400");
    expect(pan.status).toBe("found");
    const urls = pan.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(urls).toEqual([
      "https://security.paloaltonetworks.com/CVE-2024-3400",
      "https://security.paloaltonetworks.com/json/CVE-2024-3400",
      "https://security.paloaltonetworks.com/csaf/CVE-2024-3400",
    ]);

    const structured = resolveSecID("secid:advisory/paloaltonetworks.com/pan-sa#CVE-2024-3400?parsability=structured");
    expect(structured.status).toBe("found");
    const structuredUrls = structured.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(structuredUrls).toEqual([
      "https://security.paloaltonetworks.com/json/CVE-2024-3400",
      "https://security.paloaltonetworks.com/csaf/CVE-2024-3400",
    ]);
  });

  it("resolves Ubuntu CVE-2024-3094 to /security/{id} HTML and /security/cves/{id}.json API", () => {
    const ubuntu = resolveSecID("secid:advisory/ubuntu.com/cve-tracker#CVE-2024-3094");
    expect(ubuntu.status).toBe("found");
    const urls = ubuntu.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(urls).toEqual([
      "https://ubuntu.com/security/CVE-2024-3094",
      "https://ubuntu.com/security/cves/CVE-2024-3094.json",
    ]);
    expect(urls).not.toContain("https://ubuntu.com/security/cves/CVE-2024-3094");

    const structured = resolveSecID("secid:advisory/ubuntu.com/cve-tracker#CVE-2024-3094?parsability=structured");
    expect(structured.status).toBe("found");
    const structuredUrls = structured.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(structuredUrls).toEqual(["https://ubuntu.com/security/cves/CVE-2024-3094.json"]);
  });

  it("resolves SUSE CVE-2023-44487 across suse.com/cve and suse.com/bugzilla", () => {
    const suseCve = resolveSecID("secid:advisory/suse.com/cve#CVE-2023-44487");
    expect(suseCve.status).toBe("found");
    const cveUrls = suseCve.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(cveUrls).toEqual(["https://www.suse.com/security/cve/CVE-2023-44487.html"]);

    const suseBz = resolveSecID("secid:advisory/suse.com/bugzilla#CVE-2023-44487");
    expect(suseBz.status).toBe("found");
    const bzUrls = suseBz.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url);
    expect(bzUrls).toEqual(["https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-44487"]);
  });

  it("resolves Debian, Oracle, and CISA Vulnrichment vendor-specific CVEs", () => {
    const debian = resolveSecID("secid:advisory/debian.org/tracker#CVE-2023-44487");
    expect(debian.status).toBe("found");
    expect(debian.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url))
      .toEqual(["https://security-tracker.debian.org/tracker/CVE-2023-44487"]);

    const oracle = resolveSecID("secid:advisory/oracle.com/alert#CVE-2021-44228");
    expect(oracle.status).toBe("found");
    expect(oracle.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url))
      .toEqual(["https://www.oracle.com/security-alerts/alert-cve-2021-44228.html"]);

    const cisa = resolveSecID("secid:advisory/cisa.gov/vulnrichment#CVE-2024-3400?parsability=structured");
    expect(cisa.status).toBe("found");
    expect(cisa.results.filter((r): r is ResolutionResult => "url" in r).map((r) => r.url))
      .toEqual(["https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/3xxx/CVE-2024-3400.json"]);
  });
});
