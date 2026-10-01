import { describe, it, expect } from "vitest";
import { SELF } from "cloudflare:test";
import { isBrowserNavigation, MCP_ENDPOINT_ALLOW, statusForMethod } from "../src/method-gate";

// The HTTP method contract for /mcp and /mcp/, one row per request shape.
// Same table as CSA-MCP-Core src/mcp/method-gate.test.ts. Expectations are
// written by hand, not derived from method-gate.ts, so the table is tested
// against the contract rather than against itself.

const SDK_CLIENT = "application/json, text/event-stream"; // what the TS SDK sends on its stream GET
const CHROME_NAV = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const SETUP = "https://test.local/#mcp-setup";

describe("isBrowserNavigation — browsers are identified positively", () => {
  it.each([
    ["MCP SDK stream GET", { accept: SDK_CLIENT }, false],
    ["bare text/event-stream", { accept: "text/event-stream" }, false],
    ["mixed text/html + text/event-stream", { accept: "text/html, text/event-stream" }, false],
    ["MCP-Protocol-Version present", { accept: "text/html", "mcp-protocol-version": "2025-06-18" }, false],
    ["Mcp-Session-Id present", { accept: "text/html", "mcp-session-id": "abc" }, false],
    ["*/* (curl, health checks)", { accept: "*/*" }, false],
    ["no Accept at all", {}, false],
    ["modern browser navigation", { accept: CHROME_NAV, "sec-fetch-mode": "navigate" }, true],
    ["Sec-Fetch-Mode navigate with */*", { accept: "*/*", "sec-fetch-mode": "navigate" }, true],
    ["older browser, text/html only", { accept: "text/html" }, true],
    ["fetch() from a page asking for JSON", { accept: "application/json", "sec-fetch-mode": "cors" }, false],
  ] as const)("%s → browser=%s", (_name, headers, expected) => {
    expect(isBrowserNavigation(new Headers(headers as Record<string, string>))).toBe(expected);
  });
});

describe("statusForMethod — RFC 9110 §9.1: known-but-unserved 405, unregistered 501", () => {
  it.each([
    ["GET", true, true, 302],
    ["HEAD", true, true, 302],
    ["GET", false, true, 405],
    ["GET", true, false, 405],
    ["DELETE", true, true, 405],
    ["PUT", false, true, 405],
    ["PATCH", false, true, 405],
    ["QUERY", false, true, 405],
    ["TRACE", false, true, 405],
    ["CONNECT", false, true, 405],
    ["FOO", false, true, 501],
  ] as const)("%s browser=%s setupUrl=%s → %i", (method, browser, hasUrl, expected) => {
    expect(statusForMethod(method, browser, hasUrl)).toBe(expected);
  });
});

describe("the method table, end to end through the worker", () => {
  // TRACE/CONNECT cannot be constructed by fetch() and workerd rejects
  // unregistered method strings; Cloudflare's edge answers those in
  // production. All are covered by statusForMethod above.
  const cases: Array<[string, string, Record<string, string>, number]> = [
    ["GET SDK client", "GET", { accept: SDK_CLIENT }, 405],
    ["GET SDK client + protocol header", "GET", { accept: SDK_CLIENT, "mcp-protocol-version": "2025-06-18" }, 405],
    ["GET mixed html + event-stream", "GET", { accept: "text/html, text/event-stream" }, 405],
    ["GET */*", "GET", { accept: "*/*" }, 405],
    ["GET no Accept", "GET", {}, 405],
    ["GET browser navigation", "GET", { accept: CHROME_NAV, "sec-fetch-mode": "navigate" }, 302],
    ["GET older browser", "GET", { accept: "text/html" }, 302],
    ["HEAD SDK client", "HEAD", { accept: SDK_CLIENT }, 405],
    ["HEAD browser navigation", "HEAD", { accept: CHROME_NAV, "sec-fetch-mode": "navigate" }, 302],
    ["DELETE", "DELETE", { accept: SDK_CLIENT }, 405],
    ["PUT", "PUT", { accept: SDK_CLIENT }, 405],
    ["PATCH", "PATCH", { accept: SDK_CLIENT }, 405],
    ["QUERY", "QUERY", { accept: SDK_CLIENT }, 405],
  ];

  for (const path of ["/mcp", "/mcp/"]) {
    it.each(cases)(`%s (${path})`, async (_name, method, headers, expected) => {
      const res = await SELF.fetch(`https://test.local${path}`, { method, headers, redirect: "manual" });
      expect(res.status).toBe(expected);
      expect(res.headers.get("vary")).toBe("Accept, Sec-Fetch-Mode");
      expect(res.headers.get("cache-control")).toBe("no-store");
      if (expected === 302) {
        expect(res.headers.get("location")).toBe(SETUP);
        expect(res.headers.get("allow")).toBeNull();
      } else {
        expect(res.headers.get("allow")).toBe(MCP_ENDPOINT_ALLOW);
        expect(res.headers.get("location")).toBeNull();
        if (method !== "HEAD") {
          const body = (await res.json()) as { jsonrpc: string; id: unknown; error: { message: string } };
          expect(body.jsonrpc).toBe("2.0");
          expect(body.id).toBeNull();
          expect(body.error.message).toContain(SETUP);
        }
      }
    });
  }

  it("POST /mcp/ (trailing slash) reaches the MCP handler too", async () => {
    const res = await SELF.fetch("https://test.local/mcp/", {
      method: "POST",
      headers: { "content-type": "application/json", accept: SDK_CLIENT },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
      }),
    });
    expect(res.status).toBe(200);
  });

  it("CORS preflight advertises only what is served, and never credentials", async () => {
    const res = await SELF.fetch("https://test.local/mcp", {
      method: "OPTIONS",
      headers: { origin: "https://example.org", "access-control-request-method": "POST" },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    const methods = (res.headers.get("access-control-allow-methods") ?? "").split(",").map((m) => m.trim());
    expect(methods).toEqual(expect.arrayContaining(["GET", "POST", "OPTIONS"]));
    for (const m of ["PUT", "DELETE", "PATCH", "QUERY"]) expect(methods).not.toContain(m);
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it("the gate does not touch the API routes", async () => {
    const res = await SELF.fetch("https://test.local/health");
    expect(res.status).toBe(200);
  });
});
