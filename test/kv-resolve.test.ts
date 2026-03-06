import { describe, it, expect, beforeAll } from "vitest";
import { env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { resolveFromKV } from "../src/kv-resolve";
import { RegistryContext } from "../src/kv-registry";
import { extractSecIDType } from "../src/parser";
import { REGISTRY } from "../src/registry";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY);
});

describe("extractSecIDType", () => {
  it("extracts advisory type", () => {
    expect(extractSecIDType("secid:advisory/mitre.org/cve#CVE-2024-1234")).toBe("advisory");
  });
  it("extracts type without prefix", () => {
    expect(extractSecIDType("ttp/mitre.org/attack#T1059")).toBe("ttp");
  });
  it("returns null for invalid type", () => {
    expect(extractSecIDType("secid:frobnicate/foo")).toBeNull();
  });
  it("returns null for empty string", () => {
    expect(extractSecIDType("")).toBeNull();
  });
  it("handles case-insensitive prefix", () => {
    expect(extractSecIDType("SECID:Advisory/mitre.org")).toBe("advisory");
  });
});

describe("RegistryContext", () => {
  it("fetches type index", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const idx = await ctx.getTypeIndex("advisory");
    expect(idx).not.toBeNull();
    expect(idx!.type).toBe("advisory");
    expect(idx!.namespaces.length).toBeGreaterThan(10);
    expect(idx!.child_index.length).toBeGreaterThan(0);
  });

  it("caches type index on second call", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const first = await ctx.getTypeIndex("advisory");
    const second = await ctx.getTypeIndex("advisory");
    expect(first).toBe(second); // Same reference = cached
  });

  it("fetches namespace data", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const ns = await ctx.getNamespace("advisory", "mitre.org");
    expect(ns).not.toBeNull();
    expect(ns!.namespace).toBe("mitre.org");
    expect(ns!.match_nodes.length).toBeGreaterThan(0);
  });

  it("fetches multiple namespaces in parallel", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const nsMap = await ctx.getNamespaces("advisory", ["mitre.org", "nist.gov"]);
    expect(nsMap.size).toBe(2);
    expect(nsMap.get("mitre.org")).toBeDefined();
    expect(nsMap.get("nist.gov")).toBeDefined();
  });

  it("returns null for nonexistent namespace", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const ns = await ctx.getNamespace("advisory", "nonexistent.example");
    expect(ns).toBeNull();
  });

  it("fetches full registry", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const full = await ctx.getFullRegistry();
    expect(full).not.toBeNull();
    expect(Object.keys(full!)).toContain("advisory");
    expect(Object.keys(full!.advisory)).toContain("mitre.org");
  });

  it("fetches meta", async () => {
    const ctx = new RegistryContext(env.secid_REGISTRY);
    const meta = await ctx.getMeta();
    expect(meta).not.toBeNull();
    expect(meta!.total_namespaces).toBeGreaterThan(100);
    expect(meta!.types.advisory).toBeGreaterThan(10);
  });
});

describe("resolveFromKV", () => {
  it("resolves a CVE", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:advisory/mitre.org/cve#CVE-2024-1234"
    );
    expect(result.status).toBe("found");
    expect(result.results.length).toBeGreaterThan(0);
    expect((result.results[0] as { url: string }).url).toContain("cve.org");
  });

  it("resolves type-only listing", async () => {
    const result = await resolveFromKV(env.secid_REGISTRY, "secid:advisory");
    expect(result.status).toBe("found");
    expect(result.results.length).toBeGreaterThan(10);
  });

  it("resolves namespace listing", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:advisory/mitre.org"
    );
    expect(result.status).toBe("found");
    expect(result.results.length).toBeGreaterThan(0);
  });

  it("resolves source description", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:advisory/mitre.org/cve"
    );
    expect(result.status).toBe("found");
    const first = result.results[0] as { data: Record<string, unknown> };
    expect(first.data.official_name).toBeDefined();
  });

  it("handles cross-source search", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:advisory/CVE-2024-1234"
    );
    expect(result.results.length).toBeGreaterThan(1);
    const secids = result.results.map((r) => (r as { secid: string }).secid);
    expect(secids.some((s) => s.includes("mitre.org"))).toBe(true);
  });

  it("handles invalid type", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:frobnicate/mitre.org"
    );
    expect(result.status).toBe("not_found");
  });

  it("handles empty input", async () => {
    const result = await resolveFromKV(env.secid_REGISTRY, "");
    expect(result.status).toBe("error");
  });

  it("resolves RHSA with colon in subpath", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:advisory/redhat.com/errata#RHSA-2024:1234"
    );
    expect(result.status).toBe("found");
    expect(result.results.length).toBeGreaterThan(0);
  });

  it("resolves ATT&CK technique", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:ttp/mitre.org/attack#T1059.003"
    );
    expect(result.status).toBe("found");
    expect((result.results[0] as { url: string }).url).toContain("attack.mitre.org");
  });

  it("resolves versioned source (OWASP Top 10)", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:weakness/owasp.org/top10@2021#A01"
    );
    expect(result.status).toBe("found");
    expect((result.results[0] as { url: string }).url).toContain("owasp.org");
  });

  it("returns related for version-required source without version", async () => {
    const result = await resolveFromKV(
      env.secid_REGISTRY,
      "secid:weakness/owasp.org/top10#A01"
    );
    expect(result.status).toBe("related");
    expect(result.message).toContain("version");
  });

  it("matches KV results against bundled results for CVE", async () => {
    const { parseSecID } = await import("../src/parser");
    const { resolve } = await import("../src/resolver");

    const input = "secid:advisory/mitre.org/cve#CVE-2021-44228";
    const kvResult = await resolveFromKV(env.secid_REGISTRY, input);
    const bundledResult = resolve(parseSecID(input, REGISTRY), REGISTRY);

    expect(kvResult.status).toBe(bundledResult.status);
    expect(kvResult.results.length).toBe(bundledResult.results.length);
    // Compare URLs from first result
    const kvUrl = (kvResult.results[0] as { url?: string }).url;
    const bundledUrl = (bundledResult.results[0] as { url?: string }).url;
    expect(kvUrl).toBe(bundledUrl);
  });
});
