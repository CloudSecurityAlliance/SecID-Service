import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY);
});

describe("REST API", () => {
  describe("GET /health", () => {
    it("returns 200 with ok status", async () => {
      const res = await SELF.fetch("https://test.local/health");
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ status: "ok" });
    });
  });

  describe("GET /api/v1/resolve", () => {
    it("returns error for empty query", async () => {
      const res = await SELF.fetch("https://test.local/api/v1/resolve");
      expect(res.status).toBe(200);
      const body = (await res.json()) as { status: string; message: string };
      expect(body.status).toBe("error");
      expect(body.message).toContain("Empty query");
    });

    it("returns error for oversized query", async () => {
      const longSecid = `secid:advisory/${"A".repeat(1100)}`;
      const res = await SELF.fetch(
        `https://test.local/api/v1/resolve?secid=${encodeURIComponent(longSecid)}`
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { status: string; message: string };
      expect(body.status).toBe("error");
      expect(body.message).toContain("exceeds 1024");
    });

    it("resolves a CVE", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2024-1234"
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        status: string;
        secid_query: string;
        results: Array<{ url?: string }>;
      };
      expect(body.status).toBe("found");
      expect(body.secid_query).toContain("CVE-2024-1234");
      expect(body.results.length).toBeGreaterThan(0);
      expect(body.results[0].url).toContain("cve.org");
    });

    it("has correct envelope shape", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:advisory"
      );
      const body = (await res.json()) as Record<string, unknown>;
      expect(body).toHaveProperty("secid_query");
      expect(body).toHaveProperty("status");
      expect(body).toHaveProperty("results");
    });

    it("returns not_found for invalid type", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:frobnicate/mitre.org"
      );
      const body = (await res.json()) as { status: string; message: string };
      expect(body.status).toBe("not_found");
    });

    it("has CORS headers", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:advisory",
        { method: "OPTIONS", headers: { Origin: "https://example.com" } }
      );
      // CORS middleware should handle preflight
      expect(res.headers.get("access-control-allow-origin")).toBeTruthy();
    });

    it("handles percent-encoded subpath", async () => {
      // %23 = #, %3A = :
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:advisory/redhat.com/errata%23RHSA-2024%3A1234"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string }>;
      };
      expect(body.status).toBe("found");
    });
  });

  describe("lang qualifier", () => {
    // GDPR article with ?lang=de → URL with /DE/ and lang: "de" on result
    it("resolves GDPR article with ?lang=de", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23art-32%3Flang%3Dde"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string; weight?: number }>;
      };
      expect(body.status).toBe("found");
      expect(body.results.length).toBeGreaterThan(0);
      expect(body.results[0].url).toContain("/DE/");
      expect(body.results[0].lang).toBe("de");
    });

    // GDPR article with no ?lang= → default English URL with /EN/
    it("resolves GDPR article with default language", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23art-32"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string; weight?: number }>;
      };
      expect(body.status).toBe("found");
      expect(body.results.length).toBeGreaterThan(0);
      expect(body.results[0].url).toContain("/EN/");
      expect(body.results[0].lang).toBe("en");
      // Default lang gets +1 weight nudge (100 base → 101)
      expect(body.results[0].weight).toBe(101);
    });

    // ?lang=xx (not available) → not_found with available languages
    it("returns not_found for unavailable language", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23art-32%3Flang%3Dxx"
      );
      const body = (await res.json()) as {
        status: string;
        message?: string;
      };
      expect(body.status).toBe("not_found");
      expect(body.message).toContain("not available");
      expect(body.message).toContain("en");
    });

    // ?lang=de&content_type=text/html → both filters applied
    it("applies lang and content_type together", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23art-5%3Flang%3Dde%26content_type%3Dtext/html"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string; content_type?: string }>;
      };
      expect(body.status).toBe("found");
      expect(body.results[0].url).toContain("/DE/");
      expect(body.results[0].lang).toBe("de");
      expect(body.results[0].content_type).toBe("text/html");
    });

    // ?content_type=text/html&lang=de → same result (order doesn't matter)
    it("qualifier order does not matter", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23art-5%3Fcontent_type%3Dtext/html%26lang%3Dde"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string; content_type?: string }>;
      };
      expect(body.status).toBe("found");
      expect(body.results[0].url).toContain("/DE/");
      expect(body.results[0].lang).toBe("de");
    });

    // Lang on a child that has no lang config → qualifier ignored, normal resolution
    it("ignores lang qualifier on non-lang-aware source", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2024-1234%3Flang%3Dde"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string }>;
      };
      expect(body.status).toBe("found");
      expect(body.results.length).toBeGreaterThan(0);
      // No lang field on the result since CVE doesn't have lang config
      expect(body.results[0].lang).toBeUndefined();
    });

    // GDPR recital also works with lang
    it("resolves GDPR recital with ?lang=fr", async () => {
      const res = await SELF.fetch(
        "https://test.local/api/v1/resolve?secid=secid:regulation/europa.eu/gdpr%23recital-78%3Flang%3Dfr"
      );
      const body = (await res.json()) as {
        status: string;
        results: Array<{ url?: string; lang?: string }>;
      };
      expect(body.status).toBe("found");
      expect(body.results[0].url).toContain("/FR/");
      expect(body.results[0].lang).toBe("fr");
    });
  });
});
