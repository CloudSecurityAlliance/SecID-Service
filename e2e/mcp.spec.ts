import { test, expect } from "@playwright/test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

// The MCP endpoint, checked against the deployed site — part of the
// post-deploy gate in .github/workflows/registry-kv-upload.yml.
//
// Two layers, from the fleet HTTP method contract written after the
// 2026-09-30 GET /mcp reconnect-loop incident:
//   1. the real client: connect, list tools, call one, and count every HTTP
//      request it makes. A server that answers the stream GET wrongly makes
//      the SDK reconnect once a second; a correct one gets a single 405.
//   2. the method table: one request per row, status and headers asserted.
// No browser needed — these use the SDK and Playwright's request fixture.

const SDK_CLIENT = "application/json, text/event-stream";

test.describe("MCP endpoint", () => {
  test("a real MCP client connects, lists tools, resolves, and does not loop", async ({ baseURL }) => {
    test.setTimeout(60_000);
    const log: Array<{ method: string; status: number; redirected: boolean }> = [];
    const countingFetch: typeof fetch = async (input, init) => {
      const res = await fetch(input, init);
      log.push({ method: init?.method ?? "GET", status: res.status, redirected: res.redirected });
      return res;
    };

    const client = new Client({ name: "secid-post-deploy", version: "0" });
    await client.connect(new StreamableHTTPClientTransport(new URL("/mcp", baseURL), { fetch: countingFetch }));

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(expect.arrayContaining(["resolve", "lookup", "describe"]));

    const result = await client.callTool({
      name: "resolve",
      arguments: { secid: "secid:advisory/mitre.org/cve#CVE-2021-44228" },
    });
    const text = (result.content as Array<{ text?: string }>)[0]?.text ?? "";
    expect(result.isError ?? false).toBe(false);
    expect(text).toContain('"status": "found"');

    // Give a looping client time to show itself: the SDK's reconnect delay is 1 s.
    await new Promise((r) => setTimeout(r, 15_000));
    await client.close();

    const gets = log.filter((e) => e.method === "GET");
    // Bounded, not "exactly one": some clients retry a 405 up to their limit.
    expect(gets.length).toBeLessThanOrEqual(3);
    for (const g of gets) {
      expect(g.status).toBe(405);
      expect(g.redirected).toBe(false);
    }
  });

  const table: Array<[string, string, Record<string, string>, number]> = [
    ["GET, MCP client", "GET", { accept: SDK_CLIENT }, 405],
    ["GET, client listing text/html too", "GET", { accept: "text/html, text/event-stream" }, 405],
    ["GET, */*", "GET", { accept: "*/*" }, 405],
    ["HEAD, MCP client", "HEAD", { accept: SDK_CLIENT }, 405],
    ["DELETE", "DELETE", { accept: SDK_CLIENT }, 405],
    ["PUT", "PUT", { accept: SDK_CLIENT }, 405],
    ["PATCH", "PATCH", { accept: SDK_CLIENT }, 405],
    ["GET, browser navigation", "GET", { accept: "text/html,application/xhtml+xml,*/*;q=0.8", "sec-fetch-mode": "navigate" }, 302],
  ];

  for (const [name, method, headers, expected] of table) {
    test(`method table: ${name} → ${expected}`, async ({ request }) => {
      const res = await request.fetch("/mcp", { method, headers, maxRedirects: 0 });
      expect(res.status()).toBe(expected);
      expect(res.headers().vary).toBe("Accept, Sec-Fetch-Mode");
      if (expected === 405) {
        expect(res.headers().allow).toBe("POST, OPTIONS");
        expect(res.headers().location).toBeUndefined();
      } else {
        expect(res.headers().location).toMatch(/\/#mcp-setup$/);
      }
    });
  }

  test("CORS preflight advertises only served methods, never credentials", async ({ request }) => {
    const res = await request.fetch("/mcp", {
      method: "OPTIONS",
      headers: { origin: "https://example.org", "access-control-request-method": "POST" },
    });
    expect(res.status()).toBe(204);
    expect(res.headers()["access-control-allow-origin"]).toBe("*");
    const methods = (res.headers()["access-control-allow-methods"] ?? "").split(",").map((m) => m.trim());
    for (const m of ["PUT", "DELETE", "PATCH"]) expect(methods).not.toContain(m);
    expect(res.headers()["access-control-allow-credentials"]).toBeUndefined();
  });
});
