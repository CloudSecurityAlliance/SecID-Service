import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";

beforeAll(async () => {
  await seedRegistryKV(env.secid_REGISTRY);
});

// ── Helpers ──

const MCP_URL = "https://test.local/mcp";

/** Build a JSON-RPC 2.0 request */
function jsonrpc(method: string, params: Record<string, unknown> = {}, id: number = 1) {
  return {
    jsonrpc: "2.0" as const,
    method,
    params,
    id,
  };
}

/** POST a JSON-RPC message to /mcp and parse the JSON response */
async function mcpPost(body: unknown): Promise<{ status: number; body: unknown }> {
  const res = await SELF.fetch(MCP_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify(body),
  });
  // Response may be JSON or SSE — try JSON first
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Might be SSE or error text
    parsed = text;
  }
  return { status: res.status, body: parsed };
}

/** Send initialize → initialized, return session (if any) */
async function mcpInitialize(): Promise<{ initResult: Record<string, unknown> }> {
  const { body } = await mcpPost(
    jsonrpc("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0" },
    })
  );
  const result = body as { result?: Record<string, unknown> };
  // Send initialized notification (no id = notification)
  await SELF.fetch(MCP_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  return { initResult: result.result ?? {} };
}

/** Full flow: initialize + call a tool */
async function mcpCallTool(
  toolName: string,
  args: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
  await mcpInitialize();
  return mcpPost(jsonrpc("tools/call", { name: toolName, arguments: args }));
}

// ── Unit Tests: MCP Tool Logic ──
// These test the resolve/lookup/describe logic via the MCP protocol,
// verifying the tool handlers produce correct results.

describe("MCP tool handlers", () => {
  describe("resolve tool", () => {
    it("resolves a CVE to URLs", async () => {
      const { body } = await mcpCallTool("resolve", {
        secid: "secid:advisory/mitre.org/cve#CVE-2024-1234",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      expect(resp.result).toBeDefined();
      const text = resp.result!.content[0].text;
      const data = JSON.parse(text);
      expect(data.status).toBe("found");
      expect(data.results.length).toBeGreaterThan(0);
      expect(data.results[0].url).toContain("cve.org");
    });

    it("handles empty secid gracefully", async () => {
      const { body } = await mcpCallTool("resolve", { secid: "" });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.status).toBe("error");
    });

    it("returns cross-source results for bare identifier", async () => {
      const { body } = await mcpCallTool("resolve", {
        secid: "secid:advisory/CVE-2024-1234",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.results.length).toBeGreaterThan(1);
    });

    it("rejects oversized secid input", async () => {
      const { body } = await mcpCallTool("resolve", {
        secid: `secid:advisory/${"A".repeat(1100)}`,
      });
      const resp = body as {
        error?: { code: number; message: string };
        result?: { content: Array<{ text: string }> };
      };
      if (resp.error) {
        expect(resp.error.message).toContain("1024");
      } else {
        const data = JSON.parse(resp.result!.content[0].text) as { message: string; status: string };
        expect(data.status).toBe("error");
        expect(data.message).toContain("Limit: 1024 characters");
      }
    });
  });

  describe("lookup tool", () => {
    it("finds CVE across advisory namespaces", async () => {
      const { body } = await mcpCallTool("lookup", {
        type: "advisory",
        identifier: "CVE-2024-1234",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.results.length).toBeGreaterThan(1);
      const secids = data.results.map((r: { secid: string }) => r.secid);
      expect(secids.some((s: string) => s.includes("mitre.org"))).toBe(true);
    });
  });

  describe("describe tool", () => {
    it("returns source metadata without resolving a subpath", async () => {
      const { body } = await mcpCallTool("describe", {
        secid: "secid:advisory/mitre.org/cve",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.status).toBe("found");
      expect(data.results.length).toBe(1);
      expect(data.results[0].data.official_name).toBeDefined();
    });

    it("strips subpath when present", async () => {
      const { body } = await mcpCallTool("describe", {
        secid: "secid:advisory/mitre.org/cve#CVE-2024-1234",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      // Should return source-level data, not a resolved URL
      expect(data.results[0].data).toBeDefined();
      expect(data.results[0].url).toBeUndefined();
    });

    it("lists namespaces for type-only query", async () => {
      const { body } = await mcpCallTool("describe", {
        secid: "secid:advisory",
      });
      const resp = body as { result?: { content: Array<{ text: string }> } };
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.status).toBe("found");
      expect(data.results.length).toBe(1);
      const result = data.results[0].data;
      expect(result.description).toBeDefined();
      expect(result.namespace_count).toBeGreaterThan(10);
      expect(result.namespaces.length).toBeGreaterThan(10);
    });
  });
});

// ── Smoke Tests: HTTP Endpoint ──
// Verify the /mcp endpoint responds correctly to MCP protocol messages.

describe("MCP HTTP endpoint", () => {
  it("rejects GET without proper headers", async () => {
    const res = await SELF.fetch(MCP_URL, { method: "GET" });
    // GET without Accept header returns 406 (Not Acceptable)
    expect([400, 405, 406]).toContain(res.status);
  });

  it("accepts POST with JSON-RPC initialize", async () => {
    const { status, body } = await mcpPost(
      jsonrpc("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0" },
      })
    );
    expect(status).toBe(200);
    const resp = body as { result?: { serverInfo?: { name: string } } };
    expect(resp.result?.serverInfo?.name).toBe("secid");
  });

  it("rejects oversized content-length", async () => {
    const res = await SELF.fetch(MCP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "Content-Length": "70000",
      },
      body: "{}",
    });
    expect(res.status).toBe(413);
    const body = (await res.json()) as { error?: { message: string } };
    expect(body.error?.message).toContain("exceeds");
  });

  it("returns error for unknown method", async () => {
    await mcpInitialize();
    const { body } = await mcpPost(jsonrpc("nonexistent/method", {}));
    const resp = body as { error?: { code: number; message: string } };
    expect(resp.error).toBeDefined();
    expect(resp.error!.code).toBeDefined();
  });

  it("lists tools via tools/list", async () => {
    await mcpInitialize();
    const { body } = await mcpPost(jsonrpc("tools/list", {}));
    const resp = body as { result?: { tools: Array<{ name: string }> } };
    expect(resp.result?.tools).toBeDefined();
    const toolNames = resp.result!.tools.map((t) => t.name);
    expect(toolNames).toContain("resolve");
    expect(toolNames).toContain("lookup");
    expect(toolNames).toContain("describe");
  });

  it("lists resources via resources/list", async () => {
    await mcpInitialize();
    const { body } = await mcpPost(jsonrpc("resources/list", {}));
    const resp = body as { result?: { resources: Array<{ uri: string }> } };
    expect(resp.result?.resources).toBeDefined();
    const uris = resp.result!.resources.map((r) => r.uri);
    expect(uris).toContain("secid://registry");
    expect(uris).toContain("secid://registry/advisory");
  });

  it("reads registry resource", async () => {
    await mcpInitialize();
    const { body } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://registry" })
    );
    const resp = body as {
      result?: { contents: Array<{ text: string }> };
    };
    expect(resp.result?.contents).toBeDefined();
    const data = JSON.parse(resp.result!.contents[0].text);
    expect(data.types.advisory).toBeGreaterThan(0);
    expect(data.types.weakness).toBeGreaterThan(0);
  });

  it("reads type-specific resource", async () => {
    await mcpInitialize();
    const { body } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://registry/advisory" })
    );
    const resp = body as {
      result?: { contents: Array<{ text: string }> };
    };
    const data = JSON.parse(resp.result!.contents[0].text);
    expect(data.type).toBe("advisory");
    expect(data.namespaces.length).toBeGreaterThan(10);
  });
});

// ── End-to-End Tests: Full MCP Protocol Flow ──
// Simulate a real MCP client session: initialize → list tools → call tool → verify result.

describe("MCP end-to-end flow", () => {
  it("full session: initialize, tools/list, tools/call, verify result", async () => {
    // Step 1: Initialize
    const { body: initBody } = await mcpPost(
      jsonrpc("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "e2e-test", version: "1.0" },
      })
    );
    const initResp = initBody as { result?: { serverInfo: { name: string }; capabilities: unknown } };
    expect(initResp.result?.serverInfo.name).toBe("secid");
    expect(initResp.result?.capabilities).toBeDefined();

    // Step 2: Send initialized notification
    await SELF.fetch(MCP_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });

    // Step 3: List tools
    const { body: toolsBody } = await mcpPost(jsonrpc("tools/list", {}, 2));
    const toolsResp = toolsBody as { result?: { tools: Array<{ name: string; description: string; inputSchema: unknown }> } };
    const tools = toolsResp.result!.tools;
    expect(tools.length).toBe(3);

    // Verify resolve tool has correct input schema
    const resolveTool = tools.find((t) => t.name === "resolve");
    expect(resolveTool?.inputSchema).toBeDefined();

    // Step 4: Call resolve tool
    const { body: callBody } = await mcpPost(
      jsonrpc("tools/call", {
        name: "resolve",
        arguments: { secid: "secid:advisory/mitre.org/cve#CVE-2021-44228" },
      }, 3)
    );
    const callResp = callBody as { result?: { content: Array<{ type: string; text: string }> } };
    expect(callResp.result?.content).toBeDefined();
    expect(callResp.result!.content[0].type).toBe("text");

    const resolveData = JSON.parse(callResp.result!.content[0].text);
    expect(resolveData.status).toBe("found");
    expect(resolveData.results[0].url).toContain("cve.org");
    expect(resolveData.results[0].url).toContain("CVE-2021-44228");
  });

  it("full session: initialize, resources/list, resources/read", async () => {
    await mcpInitialize();

    // List resources
    const { body: listBody } = await mcpPost(jsonrpc("resources/list", {}, 2));
    const listResp = listBody as { result?: { resources: Array<{ uri: string; name: string }> } };
    const resources = listResp.result!.resources;
    expect(resources.length).toBe(14); // 1 registry + 10 type listings + 2 docs + 1 feedback

    // Read a specific resource
    const { body: readBody } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://registry/ttp" }, 3)
    );
    const readResp = readBody as { result?: { contents: Array<{ text: string }> } };
    const ttpData = JSON.parse(readResp.result!.contents[0].text);
    expect(ttpData.type).toBe("ttp");
    expect(ttpData.namespaces.some((n: { namespace: string }) => n.namespace === "mitre.org")).toBe(true);
  });

  it("doc resources are readable and contain expected content", async () => {
    await mcpInitialize();

    // Read build-a-client guide
    const { body: buildBody } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://docs/build-a-client" }, 2)
    );
    const buildResp = buildBody as { result?: { contents: Array<{ text: string; mimeType: string }> } };
    const buildText = buildResp.result!.contents[0].text;
    expect(buildResp.result!.contents[0].mimeType).toBe("text/markdown");
    expect(buildText).toContain("Encoding Gotcha");
    expect(buildText).toContain("%23");
    expect(buildText).toContain("Implementation Checklist");

    // Read prompt template
    const { body: promptBody } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://docs/prompt-template" }, 3)
    );
    const promptResp = promptBody as { result?: { contents: Array<{ text: string; mimeType: string }> } };
    const promptText = promptResp.result!.contents[0].text;
    expect(promptText).toContain("{LANGUAGE}");
    expect(promptText).toContain("SecIDClient");
  });

  it("tool call with Debian DSA exercises range table through MCP", async () => {
    const { body } = await mcpCallTool("resolve", {
      secid: "secid:advisory/debian.org/dsa#DSA-5678-1",
    });
    const resp = body as { result?: { content: Array<{ text: string }> } };
    const data = JSON.parse(resp.result!.content[0].text);
    expect(data.status).toBe("found");
    expect(data.results[0].url).toContain("/2024/");
  });

  it("lookup tool with OWASP versioned source", async () => {
    const { body } = await mcpCallTool("resolve", {
      secid: "secid:weakness/owasp.org/top10@2021#A01",
    });
    const resp = body as { result?: { content: Array<{ text: string }> } };
    const data = JSON.parse(resp.result!.content[0].text);
    expect(data.status).toBe("found");
    expect(data.results[0].url).toContain("owasp.org");
  });
});
