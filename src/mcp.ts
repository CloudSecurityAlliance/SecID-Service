import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { parseSecID } from "./parser";
import { resolve } from "./resolver";
import { REGISTRY } from "./registry";
import { SECID_TYPES } from "./types";
import type { Context } from "hono";

// ── Tool descriptions ──
// These are the primary "SDK" for AI agents. An AI seeing these for the first
// time should understand the full API contract from the descriptions alone.

const RESOLVE_DESCRIPTION = `Resolve a SecID string to URL(s) where that security resource can be found.

SecID is a universal grammar for security knowledge: secid:type/namespace/name[@version]#subpath

EXAMPLES:
  secid:advisory/mitre.org/cve#CVE-2021-44228  → CVE record URL
  secid:weakness/mitre.org/cwe#CWE-79          → CWE weakness page
  secid:ttp/mitre.org/attack#T1059.003         → ATT&CK technique page
  secid:control/nist.gov/csf@2.0#PR.AC-1       → NIST CSF control
  secid:advisory/mitre.org/cve                  → registry info about CVE as a source
  secid:advisory                                → list all advisory namespaces

RESPONSE FORMAT:
  { secid_query, status, results[], message? }

STATUS VALUES:
  found     — exact match, results contain URLs
  corrected — server fixed the input (e.g. moved identifier to correct subpath), results contain URLs
  related   — partial match, results contain registry data (may need @version)
  not_found — nothing matched, message explains why
  error     — unparseable input, message explains how to fix

TWO RESULT TYPES (check which fields are present):
  Resolution: { secid, weight, url }  — item resolved to URL(s)
  Registry:   { secid, data }         — browsing/discovery information

WEIGHTS: 100=authoritative primary, 80=high-quality secondary, 50=alternative/indirect.
Multiple results are normal — same resource at different URLs, sorted by weight descending.

CROSS-SOURCE SEARCH: Omit namespace to search all sources of that type.
  secid:advisory/CVE-2021-44228 → returns URLs from MITRE, NVD, Red Hat, etc.

QUERY DEPTH: More specific = URLs, less specific = registry browsing data.

To build an HTTP client instead of using this tool: GET https://secid.cloudsecurityalliance.org/api/v1/resolve?secid={secid} — encode # as %23 in the query parameter.`;

const LOOKUP_DESCRIPTION = `Search for a security identifier across all sources of a given type.

Use this when you have an identifier (like CVE-2021-44228, CWE-79, or T1059.003) but don't know which specific source to query. This searches every registered namespace of the given type.

This is equivalent to: resolve("secid:{type}/{identifier}")

EXAMPLES:
  lookup(type="advisory", identifier="CVE-2021-44228")
    → URLs from MITRE CVE, NVD, Red Hat, SUSE, GitHub Advisory, etc.
  lookup(type="weakness", identifier="CWE-79")
    → URLs from MITRE CWE
  lookup(type="ttp", identifier="T1059.003")
    → URL from MITRE ATT&CK

RESPONSE: Same format as resolve — { secid_query, status, results[], message? }
Results from different sources will have different secid values showing where each match was found.
Sort by weight descending — highest weight is the most authoritative source.

TYPES: advisory (CVEs, vendor advisories), weakness (CWE, OWASP), ttp (ATT&CK, CAPEC), control (NIST, ISO), regulation (GDPR, HIPAA), entity (orgs, products), reference (RFCs, arXiv, DOI)`;

const DESCRIBE_DESCRIPTION = `Get registry metadata about a SecID source, namespace, or type — without resolving a specific item.

Use this to discover what's available: what sources exist, what identifier patterns they accept, and what URLs they provide.

EXAMPLES:
  secid:advisory/mitre.org/cve   → description of CVE, accepted patterns, example IDs, source URLs
  secid:advisory/mitre.org       → list of all sources MITRE publishes (cve, cvelistV5)
  secid:advisory                 → list of all advisory namespaces (mitre.org, nist.gov, redhat.com, ...)
  secid:control                  → list of all control namespaces

If you pass a SecID with a subpath (e.g. secid:advisory/mitre.org/cve#CVE-2024-1234), the subpath is stripped and you get source-level info instead of resolution.

RESPONSE: Same envelope — { secid_query, status, results[] }
Results contain { secid, data } with registry metadata (official_name, patterns, examples, urls).

Use this to help users construct valid SecID strings or to explore what the registry covers.`;

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "secid",
    version: "0.2.0",
  });

  // ── Tool: resolve ──
  server.tool(
    "resolve",
    RESOLVE_DESCRIPTION,
    { secid: z.string().describe("Full SecID string, e.g. 'secid:advisory/mitre.org/cve#CVE-2021-44228' or 'secid:advisory/CVE-2021-44228' for cross-source search") },
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
    LOOKUP_DESCRIPTION,
    {
      type: z.enum(SECID_TYPES).describe("Security knowledge type: advisory, weakness, ttp, control, regulation, entity, or reference"),
      identifier: z.string().describe("The identifier to search for, e.g. 'CVE-2021-44228', 'CWE-79', 'T1059.003'"),
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
    DESCRIBE_DESCRIPTION,
    { secid: z.string().describe("SecID without subpath, e.g. 'secid:advisory/mitre.org/cve', 'secid:advisory/mitre.org', or 'secid:advisory'") },
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
    { description: "Full listing of all SecID types and their namespace counts. SecID covers 7 types: advisory (CVEs, vendor advisories), weakness (CWE, OWASP), ttp (ATT&CK, CAPEC), control (NIST, ISO), regulation (GDPR, HIPAA), entity (orgs, products), reference (RFCs, arXiv, DOI). 121 namespaces total." },
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
      { description: `All namespaces registered under the '${type}' type, with official names and source counts. Use the describe tool to get details about any specific namespace.` },
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
