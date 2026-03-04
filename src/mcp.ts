import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { parseSecID } from "./parser";
import { resolve } from "./resolver";
import { REGISTRY } from "./registry";
import { SECID_TYPES } from "./types";
import type { Context } from "hono";

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "secid",
    version: "0.1.0",
  });

  // ── Tool: resolve ──
  server.tool(
    "resolve",
    "Resolve a SecID string to URL(s). Returns the resolved URLs, registry data, or guidance.",
    { secid: z.string().describe("SecID string to resolve, e.g. 'secid:advisory/mitre.org/cve#CVE-2024-1234'") },
    async ({ secid }) => {
      const parsed = parseSecID(secid, REGISTRY);
      const result = resolve(parsed, REGISTRY);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Tool: lookup ──
  server.tool(
    "lookup",
    "Search for a security identifier across all sources of a given type. Useful when you have an ID like CVE-2024-1234 but don't know which source to use.",
    {
      type: z.enum(SECID_TYPES).describe("SecID type to search within"),
      identifier: z.string().describe("The identifier to search for, e.g. 'CVE-2024-1234'"),
    },
    async ({ type, identifier }) => {
      const secid = `secid:${type}/${identifier}`;
      const parsed = parseSecID(secid, REGISTRY);
      const result = resolve(parsed, REGISTRY);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Tool: describe ──
  server.tool(
    "describe",
    "Get registry metadata about a SecID source (without resolving a specific item). Returns source descriptions, available patterns, URLs, and examples.",
    { secid: z.string().describe("SecID without subpath, e.g. 'secid:advisory/mitre.org/cve' or 'secid:advisory/mitre.org' or 'secid:advisory'") },
    async ({ secid }) => {
      const parsed = parseSecID(secid, REGISTRY);
      // Strip subpath to get source-level info
      parsed.subpath = null;
      const result = resolve(parsed, REGISTRY);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Resource: registry listing ──
  server.resource(
    "registry",
    "secid://registry",
    { description: "Full listing of all SecID types and their namespace counts" },
    async () => {
      const listing: Record<string, number> = {};
      for (const type of SECID_TYPES) {
        listing[type] = Object.keys(REGISTRY[type] ?? {}).length;
      }
      return {
        contents: [{
          uri: "secid://registry",
          mimeType: "application/json",
          text: JSON.stringify({ types: listing }, null, 2),
        }],
      };
    }
  );

  // ── Resource: type listing ──
  for (const type of SECID_TYPES) {
    server.resource(
      `registry-${type}`,
      `secid://registry/${type}`,
      { description: `All namespaces registered under the '${type}' type` },
      async () => {
        const namespaces = Object.entries(REGISTRY[type] ?? {}).map(([ns, data]) => ({
          namespace: ns,
          official_name: data.official_name,
          common_name: data.common_name,
          source_count: data.match_nodes.length,
        }));
        return {
          contents: [{
            uri: `secid://registry/${type}`,
            mimeType: "application/json",
            text: JSON.stringify({ type, namespaces }, null, 2),
          }],
        };
      }
    );
  }

  return server;
}

export async function handleMCP(c: Context): Promise<Response> {
  const server = createMcpServer();

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // Stateless — no session tracking
    enableJsonResponse: true,      // Prefer JSON for simple req/res
  });

  await server.connect(transport);
  const response = await transport.handleRequest(c.req.raw);
  return response;
}
