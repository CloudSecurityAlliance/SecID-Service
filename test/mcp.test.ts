import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { seedRegistryKV } from "./helpers/seed-kv";
import { BUILD_A_CLIENT_DOC, PROMPT_TEMPLATE_DOC } from "../src/mcp";
import {
  CHANGED_META_KEY,
  CONTRACT_HASH_META_KEY,
  canonicalizeJson,
  sha256Hex as syncSha256Hex,
} from "../src/tool-changes";

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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
      // F-04-01: contributor free-text (official_name) is relocated under the
      // labeled untrusted envelope before crossing the MCP boundary.
      expect(data.results[0].data.registry_text_untrusted.official_name).toBeDefined();
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
      // F-04-01: description (contributor prose) moves under the untrusted
      // envelope; structural keys (namespace_count, namespaces) stay in place.
      expect(result.registry_text_untrusted.description).toBeDefined();
      expect(result.namespace_count).toBeGreaterThan(10);
      expect(result.namespaces.length).toBeGreaterThan(10);
    });
  });
});

// ── Smoke Tests: HTTP Endpoint ──
// Verify the /mcp endpoint responds correctly to MCP protocol messages.

describe("MCP HTTP endpoint", () => {
  it("answers GET without an Accept header with 405 and Allow", async () => {
    // Was "[400, 405, 406]" — loose enough to pass a redirect regression's
    // neighbours. The contract says exactly 405; see test/method-gate.test.ts.
    const res = await SELF.fetch(MCP_URL, { method: "GET", redirect: "manual" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST, OPTIONS");
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
    const toolsResp = toolsBody as {
      result?: {
        tools: Array<{
          name: string;
          description: string;
          inputSchema: Record<string, unknown>;
          annotations?: Record<string, unknown>;
          _meta?: Record<string, string>;
        }>;
      };
    };
    const tools = toolsResp.result!.tools;
    expect(tools.length).toBe(5);
    expect(tools.map((t) => t.name).sort()).toEqual(
      ["describe", "describe_changes", "lookup", "resolve", "submit_feedback"]
    );

    // Verify every tool includes _meta with io.cloudsecurityalliance.secid/contractHash
    // and io.cloudsecurityalliance.secid/changed, and that the hash matches RFC 8785 JCS
    // SHA-256 computed over the wire tool definition (#44).
    for (const tool of tools) {
      expect(tool._meta).toBeDefined();
      const contractHash = tool._meta![CONTRACT_HASH_META_KEY];
      const changed = tool._meta![CHANGED_META_KEY];
      expect(contractHash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(Number.isNaN(Date.parse(changed))).toBe(false);

      const canonical = canonicalizeJson({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
      });
      const expectedWebCryptoHex = await sha256Hex(canonical);
      expect(syncSha256Hex(canonical)).toBe(expectedWebCryptoHex);
      expect(contractHash).toBe(`sha256:${expectedWebCryptoHex}`);
    }

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

    // Step 5: Call submit_feedback tool
    const { body: fbBody } = await mcpPost(
      jsonrpc("tools/call", {
        name: "submit_feedback",
        arguments: {
          category: "missing-namespace",
          secid: "secid:entity/newvendor.example",
          message: "Please add NewVendor.",
        },
      }, 4)
    );
    const fbResp = fbBody as { result?: { content: Array<{ type: string; text: string }> } };
    const fbData = JSON.parse(fbResp.result!.content[0].text);
    expect(fbData.status).toBe("received");
    expect(fbData.feedback_id).toBeDefined();
    expect(fbData.category).toBe("missing-namespace");
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
    expect(buildText).toBe(BUILD_A_CLIENT_DOC);
    expect(buildText).toContain("Encoding Gotcha");
    expect(buildText).toContain("%23");
    expect(buildText).toContain("Treat the Response as Untrusted");
    expect(buildText).toContain("Tolerate unknown fields");
    expect(buildText).toContain("skip to the next valid one");
    expect(buildText).toContain("Implementation Checklist");
    // Anti-drift digest synced byte-for-byte with SecID-Client-SDK/skills/build-a-client/BUILD-A-CLIENT.md (SecID-Client-SDK#12)
    expect(await sha256Hex(buildText)).toBe(
      "f74ac51d672a9f56d4e444f6875de4aa8eda2533612620a140b42512c83c3c13"
    );

    // Read prompt template
    const { body: promptBody } = await mcpPost(
      jsonrpc("resources/read", { uri: "secid://docs/prompt-template" }, 3)
    );
    const promptResp = promptBody as { result?: { contents: Array<{ text: string; mimeType: string }> } };
    const promptText = promptResp.result!.contents[0].text;
    expect(promptResp.result!.contents[0].mimeType).toBe("text/markdown");
    expect(promptText).toBe(PROMPT_TEMPLATE_DOC);
    expect(promptText).toContain("{LANGUAGE}");
    expect(promptText).toContain("SecIDClient");
    expect(promptText).toContain("Treat the resolver response as untrusted");
    expect(promptText).toContain("return the next valid one, not null");
    // Anti-drift digest synced byte-for-byte with SecID-Client-SDK/skills/build-a-client/PROMPT-TEMPLATE.md (SecID-Client-SDK#12)
    expect(await sha256Hex(promptText)).toBe(
      "04b868a7c60a6da4a1c06c634a98aceddf8cf1da3915e1b7bd2d8751d26f17e7"
    );
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

  it("describe_changes returns toolset_hash, per-tool hashes, and filters by 'since' (#44)", async () => {
    // 1. Full history (no 'since')
    const { body: fullBody } = await mcpCallTool("describe_changes", {});
    const fullResp = fullBody as { result?: { content: Array<{ text: string }>; isError?: boolean } };
    expect(fullResp.result?.isError ?? false).toBe(false);
    const fullData = JSON.parse(fullResp.result!.content[0].text);
    expect(fullData.toolset_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fullData.last_changed).toBe("2026-11-04T00:00:00Z");
    expect(fullData.since).toBeNull();
    expect(Object.keys(fullData.tools).sort()).toEqual(
      ["describe", "describe_changes", "lookup", "resolve", "submit_feedback"]
    );
    expect(fullData.changes.length).toBeGreaterThanOrEqual(5);

    // 2. Filtered since 2026-10-01T00:00:00Z (returns only the 2026-11-04 entries)
    const { body: sinceBody } = await mcpCallTool("describe_changes", {
      since: "2026-10-01T00:00:00Z",
    });
    const sinceResp = sinceBody as { result?: { content: Array<{ text: string }>; isError?: boolean } };
    const sinceData = JSON.parse(sinceResp.result!.content[0].text);
    expect(sinceData.since).toBe("2026-10-01T00:00:00Z");
    expect(sinceData.changes.length).toBe(4);
    expect(sinceData.changes.map((c: { tool: string }) => c.tool).sort()).toEqual([
      "describe",
      "describe_changes",
      "lookup",
      "resolve",
    ]);

    // 3. Filtered at or after last_changed (returns empty changes array)
    const { body: upToDateBody } = await mcpCallTool("describe_changes", {
      since: "2026-11-04T00:00:00Z",
    });
    const upToDateResp = upToDateBody as { result?: { content: Array<{ text: string }> } };
    const upToDateData = JSON.parse(upToDateResp.result!.content[0].text);
    expect(upToDateData.changes).toEqual([]);

    // 4. Invalid 'since' timestamp returns isError: true
    const { body: badBody } = await mcpCallTool("describe_changes", {
      since: "not-a-timestamp",
    });
    const badResp = badBody as { result?: { content: Array<{ text: string }>; isError?: boolean } };
    expect(badResp.result?.isError).toBe(true);
    const badData = JSON.parse(badResp.result!.content[0].text);
    expect(badData.status).toBe("error");
    expect(badData.message).toContain("RFC 3339");
  });

  it("describe and lookup return namespace metadata for entity with empty match_nodes (#11)", async () => {
    for (const call of [
      mcpCallTool("describe", { secid: "secid:entity/uaepass.ae" }),
      mcpCallTool("lookup", { type: "entity", identifier: "uaepass.ae" }),
    ]) {
      const { body } = await call;
      const resp = body as { result?: { content: Array<{ text: string }>; isError?: boolean } };
      expect(resp.result?.isError ?? false).toBe(false);
      const data = JSON.parse(resp.result!.content[0].text);
      expect(data.status).toBe("found");
      expect(data.results.length).toBe(1);
      expect(data.results[0].secid).toBe("secid:entity/uaepass.ae");
      expect(data.results[0].data.source_count).toBe(0);
      expect(data.results[0].data.registry_text_untrusted.official_name).toBe("UAE Pass");
      expect(data.results[0].data.registry_text_untrusted.common_name).toBe("UAE Pass");
    }
  });
});
