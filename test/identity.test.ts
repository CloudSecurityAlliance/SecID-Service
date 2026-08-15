import { describe, it, expect } from "vitest";
import { namespaceAliases, matchesNamespaceIdentity } from "../src/identity";

const ns = { official_name: "X", common_name: null, alternate_names: null };

describe("namespaceAliases", () => {
  it("keeps the leading label and full domain", () => {
    expect(namespaceAliases("ismap.go.jp", ns)).toContain("ismap");
    expect(namespaceAliases("ismap.go.jp", ns)).toContain("ismap.go.jp");
  });

  it("drops the TLD and country second-level suffixes", () => {
    const a = namespaceAliases("ismap.go.jp", ns);
    expect(a).not.toContain("jp");
    expect(a).not.toContain("go");
  });

  it("drops generic suffixes", () => {
    expect(namespaceAliases("cloudsecurityalliance.org", ns)).not.toContain("org");
    expect(namespaceAliases("aws.amazon.com", ns)).not.toContain("com");
    expect(namespaceAliases("uidai.gov.in", ns)).not.toContain("gov");
  });

  it("indexes non-leading domain labels", () => {
    // aws.amazon.com should be findable by 'amazon', not only 'aws'
    const a = namespaceAliases("aws.amazon.com", ns);
    expect(a).toContain("aws");
    expect(a).toContain("amazon");
  });

  it("indexes path segments", () => {
    const a = namespaceAliases("amazon.com/aws/s3", ns);
    expect(a).toContain("aws");
    expect(a).toContain("s3");
    expect(a).toContain("amazon");
  });

  it("indexes a single path segment", () => {
    expect(namespaceAliases("github.com/advisories", ns)).toContain("advisories");
  });

  it("still indexes declared names", () => {
    const a = namespaceAliases("ismap.go.jp", {
      official_name: "Information system Security Management and Assessment Program",
      common_name: "ISMAP",
      alternate_names: ["ISMAP-CSM"],
    });
    expect(a).toContain("ismap");
    expect(a).toContain("ismap-csm");
  });

  it("dedupes when a label repeats a declared name", () => {
    const a = namespaceAliases("ismap.go.jp", { common_name: "ISMAP" });
    expect(a.filter((x) => x === "ismap")).toHaveLength(1);
  });
});

describe("matchesNamespaceIdentity", () => {
  it("matches a path segment case-insensitively", () => {
    expect(matchesNamespaceIdentity("amazon.com/aws/s3", ns, "S3")).toBe(true);
  });

  it("does not match a public suffix", () => {
    expect(matchesNamespaceIdentity("ismap.go.jp", ns, "jp")).toBe(false);
    expect(matchesNamespaceIdentity("aws.amazon.com", ns, "com")).toBe(false);
  });

  it("does not substring-match", () => {
    // 'security' must not match cloudsecurityalliance.org — token, not substring
    expect(matchesNamespaceIdentity("cloudsecurityalliance.org", ns, "security")).toBe(false);
  });
});

describe("the leading label is never stripped", () => {
  const bare = { official_name: "X", common_name: null, alternate_names: null };

  it("keeps a leading label that looks like a suffix", () => {
    // go.dev is the Go project; gov.uk is the UK government
    expect(namespaceAliases("go.dev", bare)).toContain("go");
    expect(namespaceAliases("gov.uk", bare)).toContain("gov");
  });

  it("keeps an organisation name that collides with a suffix word", () => {
    // NIC = Saudi Arabia's National Information Center
    expect(namespaceAliases("nic.gov.sa", bare)).toContain("nic");
  });

  it("still drops the same word in the middle", () => {
    expect(namespaceAliases("uidai.gov.in", bare)).toContain("uidai");
    expect(namespaceAliases("uidai.gov.in", bare)).not.toContain("gov");
  });
});
