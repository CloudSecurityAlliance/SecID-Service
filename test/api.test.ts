import { describe, it, expect } from "vitest";
import { SELF } from "cloudflare:test";

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
});
