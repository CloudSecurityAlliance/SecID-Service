import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { resolveFromKV } from "./kv-resolve";
import { RegistryContext } from "./kv-registry";
import { SECID_TYPES } from "./types";
import type { AppEnv } from "./types";
import type { Context } from "hono";
import { buildErrorEntry, recordError } from "./observability";

const MAX_SECID_QUERY_CHARS = 1024;
const MAX_MCP_BODY_BYTES = 64 * 1024; // 64 KB

// ── Documentation resources ──
// These are MCP resources containing instructions for building SecID clients.
// An AI agent can read these to generate a working client in any language.

const BUILD_A_CLIENT_DOC = `# Build a SecID Client

Everything needed to generate a working SecID client in any language.

## What You're Building

An HTTP client for a single API endpoint that resolves security knowledge identifiers to URLs.

**Base URL:** https://secid.cloudsecurityalliance.org
**Endpoint:** GET /api/v1/resolve?secid={encoded_secid}
**Auth:** None. No API keys, no tokens, no headers.

## The One Encoding Gotcha

SecID strings use # to separate subpath identifiers:

    secid:advisory/mitre.org/cve#CVE-2021-44228

In a URL query parameter, # is the fragment delimiter. You must encode it:

    CORRECT: /api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
    WRONG:   /api/v1/resolve?secid=secid:advisory/mitre.org/cve#CVE-2021-44228

Replace # with %23 in the SecID string before appending to the URL. Verify your language's URL encoder handles this — some treat # as a fragment separator and skip it.

This is the #1 failure mode for new clients.

## Response Envelope

Every response has the same shape:

    {
      "secid_query": "secid:advisory/mitre.org/cve#CVE-2021-44228",
      "status": "found",
      "results": [...],
      "message": null
    }

Fields: secid_query (string, always), status (string, always), results (array, always), message (string, only on not_found/error).

## Five Status Values

- found: Exact match. Use results directly.
- corrected: Server fixed input and resolved. Show correction; use results.
- related: Partial match. Display registry data; may need @version.
- not_found: Nothing matched. Show message field.
- error: Unparseable input. Show message field.

## Two Result Types

Distinguish by checking for the weight field:

Resolution Result (has weight + url):
    {"secid": "secid:advisory/mitre.org/cve#CVE-2021-44228", "weight": 100, "url": "https://www.cve.org/CVERecord?id=CVE-2021-44228"}

Registry Result (has data):
    {"secid": "secid:advisory/mitre.org/cve", "data": {"official_name": "Common Vulnerabilities and Exposures", ...}}

They never overlap.

## Weights

100 = authoritative primary source, 80 = high-quality secondary, 50 = alternative/indirect.
Multiple results are normal. Sort by weight descending. Highest weight = best default.

## Cross-Source Search

Omit namespace to search all sources of a type:
    secid:advisory/CVE-2021-44228
Returns URLs from MITRE, NVD, Red Hat, SUSE, etc.

## Version Disambiguation

Sources with version_required (like OWASP Top 10) return status "related" with version info when queried without @version. Detect this and prompt user to add @version.

## Query Depth

    secid:advisory/mitre.org/cve#CVE-2021-44228  → Resolution results (URLs)
    secid:advisory/mitre.org/cve                  → Registry data about CVE
    secid:advisory/mitre.org                      → List of sources from mitre.org
    secid:advisory                                → List of all advisory namespaces
    secid:disclosure/redhat.com/cna                   → CNA scope, contacts, policy URL

## Implementation Checklist

1. Encode # as %23 in query parameter
2. Accept any HTTP 200 response — status field tells you what happened
3. Parse the JSON envelope with all four fields
4. Handle all 5 status values
5. Distinguish result types by checking for weight+url vs data
6. Sort resolution results by weight descending
7. Provide a best_url helper (highest-weight URL or null)
8. Handle empty results array on not_found/error
9. Expose the message field for guidance
10. Support CLI mode (accept SecID as argument, print best URL)

## Minimal Pseudocode

    function resolve(secid_string):
        encoded = secid_string.replace("#", "%23")
        url = BASE_URL + "/api/v1/resolve?secid=" + encoded
        response = http_get(url)
        return parse_json(response.body)

    function best_url(secid_string):
        result = resolve(secid_string)
        if result.status in ["found", "corrected"]:
            urls = [r for r in result.results if r.weight exists]
            urls.sort_by(weight, descending)
            return urls[0].url if urls else null
        return null
`;

const PROMPT_TEMPLATE_DOC = `# SecID Client Prompt Template

Copy everything below, replace {LANGUAGE} with your language, and give to an AI assistant.

---

Build me a SecID client library in {LANGUAGE}. Single file, zero external dependencies (stdlib only). Include CLI mode.

## SecID

Universal grammar for security knowledge. Format: secid:type/namespace/name[@version]#subpath

Examples:
- secid:advisory/mitre.org/cve#CVE-2021-44228 (CVE record)
- secid:weakness/mitre.org/cwe#CWE-79 (CWE weakness)
- secid:advisory/CVE-2021-44228 (cross-source search)
- secid:disclosure/redhat.com/cna (Red Hat CNA program — scope, contacts)

## API Contract

One endpoint: GET https://secid.cloudsecurityalliance.org/api/v1/resolve?secid={encoded_secid}
No auth. CORS enabled.

CRITICAL: # in SecID must be encoded as %23 in the query parameter.
    CORRECT: ?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
    WRONG:   ?secid=secid:advisory/mitre.org/cve#CVE-2021-44228

Response (always HTTP 200 for processed queries):
    {
      "secid_query": "string (echoed input)",
      "status": "found|corrected|related|not_found|error",
      "results": [
        {"secid": "string", "weight": 100, "url": "https://..."} // Resolution
        // OR
        {"secid": "string", "data": {"official_name": "..."}}    // Registry
      ],
      "message": "string|null (guidance on not_found/error)"
    }

Status: found (use results), corrected (use results, show correction), related (show data, may need @version), not_found (show message), error (show message).
Weights: 100=primary, 80=secondary, 50=alternative. Sort descending.

## Required API Surface

    class SecIDClient:
        constructor(base_url = "https://secid.cloudsecurityalliance.org")
        resolve(secid: string) -> SecIDResponse
        best_url(secid: string) -> string | null
        lookup(type: string, identifier: string) -> SecIDResponse

    class SecIDResponse:
        secid_query: string
        status: string
        results: list
        message: string | null
        property best_url -> string | null
        property was_corrected -> bool
        property resolution_results -> list (weight+url only, sorted)
        property registry_results -> list (data only)

## CLI Mode

    $ {LANGUAGE} secid_client "secid:advisory/mitre.org/cve#CVE-2021-44228"
    https://www.cve.org/CVERecord?id=CVE-2021-44228

    $ {LANGUAGE} secid_client --json "secid:advisory/mitre.org/cve#CVE-2021-44228"
    {full JSON}

## Requirements

1. Single file, zero dependencies
2. # -> %23 encoding (test this!)
3. Handle all 5 status values
4. Distinguish resolution (weight+url) from registry (data) results
5. Sort by weight descending
6. best_url helper
7. CLI mode with --json flag
8. Type hints/annotations
9. Docstrings explaining encoding gotcha and status values
`;

// ── Tool descriptions ──
// These are the primary "SDK" for AI agents. An AI seeing these for the first
// time should understand the full API contract from the descriptions alone.

const RESOLVE_DESCRIPTION = `Resolve a SecID string to URL(s) where that security resource can be found.

SecID is a Cloud Security Alliance project by Kurt Seifried (Chief Innovation Officer). It provides a universal grammar for security knowledge: secid:type/namespace/name[@version]#subpath

EXAMPLES:
  secid:advisory/mitre.org/cve#CVE-2021-44228  → CVE record URL
  secid:weakness/mitre.org/cwe#CWE-79          → CWE weakness page
  secid:ttp/mitre.org/attack#T1059.003         → ATT&CK technique page
  secid:control/nist.gov/csf@2.0#PR.AC-1       → NIST CSF control
  secid:advisory/mitre.org/cve                  → registry info about CVE as a source
  secid:advisory                                → list all advisory namespaces
  secid:disclosure/redhat.com/cna                   → Red Hat CNA scope, contacts, policy URL
  secid:disclosure                                  → list all 486 disclosure namespaces (CVE CNAs)

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

VULNERABILITY REPORTING — "Who do I report this to?" / "How do I get a CVE?":
  The disclosure type contains 486 CVE Numbering Authority (CNA) programs with:
  - scope: what products/projects each CNA covers
  - contacts: email addresses and web forms for reporting
  - policy URLs: the CNA's disclosure policy
  - program role: CNA, Root, CNA-LR (last resort), Top-Level Root

  WORKFLOW — How to report a vulnerability and get a CVE ID:
  1. Find the vendor's CNA: secid:disclosure/{vendor-domain}.com
     → Check the scope field to confirm the product is covered
     → Use the contact (email or web form) to report the vulnerability
     → The CNA assigns a CVE ID and coordinates disclosure
  2. If no CNA covers the product: secid:disclosure/mitre.org/cna-lr
     → MITRE is the CNA of Last Resort for everything not covered by another CNA
     → Submit via https://cveform.mitre.org (the CVE ID Request Form)
  3. If the vendor IS a CNA, report directly to them — they assign their own CVE IDs

  EXAMPLES:
    secid:disclosure/redhat.com     → lists Red Hat's CNA, CNA-LR, and Root programs
    secid:disclosure/apple.com/cna  → Apple's CNA with contact (product-security@apple.com)
    secid:disclosure/cisco.com/cna  → Cisco's CNA with contact and PSIRT link
    secid:disclosure/mitre.org/cna-lr → MITRE's CNA-LR + CVE request form URL

  Each CNA result includes a scope field describing exactly what that program covers,
  so you can determine if a specific product falls within their scope.

PRODUCT SECURITY CAPABILITIES — "What security features does this service have?":
  The capability type identifies concrete, configurable security features of products/services:
  - configuration options (encryption types, access control settings)
  - audit commands (CLI, API, console paths to verify)
  - remediation commands (CLI, API, IaC to fix/enable)

  Examples:
    secid:capability/amazon.com/aws/s3#default-encryption  → S3 encryption options, audit/remediation CLI
    secid:capability/amazon.com/aws/cloudtrail#multi-region → CloudTrail multi-region logging
    secid:capability/microsoft.com/azure/storage#encryption-at-rest → Azure storage encryption

SECURITY METHODOLOGIES — "How do I score/map/assess this?":
  The methodology type identifies formal processes for producing security analysis:
    secid:methodology/nist.gov/ir-8477           → NIST mapping methodology (4 styles + selection)
    secid:methodology/nist.gov/ir-8477#strm      → Set Theory Relationship Mapping specifically
    secid:methodology/first.org/cvss@4.0         → CVSS v4.0 vulnerability scoring
    secid:methodology/cmu.edu/ssvc@2.0           → SSVC stakeholder-specific prioritization

QUERY DEPTH: More specific = URLs, less specific = registry browsing data.

To build an HTTP client instead of using this tool: GET https://secid.cloudsecurityalliance.org/api/v1/resolve?secid={secid} — encode # as %23 in the query parameter.

FEEDBACK: If a namespace is missing, a result is wrong, or you want to request a new source, file an issue at https://github.com/CloudSecurityAlliance/SecID/issues — the registry is open source and contributions are welcome.`;

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
  lookup(type="disclosure", identifier="redhat.com")
    → Red Hat's CNA, CNA-LR, and Root programs with scopes and contacts
  lookup(type="capability", identifier="amazon.com/aws/s3")
    → S3 security capabilities (encryption, bucket policies, access logging)

VULNERABILITY REPORTING USE CASE:
  "I found a vulnerability in X — who do I report it to?"
  Use type="disclosure" with the vendor's domain as identifier:
    lookup(type="disclosure", identifier="cisco.com")    → Cisco's CNA contact + scope
    lookup(type="disclosure", identifier="apple.com")    → Apple's CNA (product-security@apple.com)
    lookup(type="disclosure", identifier="google.com")   → Google's 5 CNA programs (Android, Cloud, Devices, Chrome, main)
  Results include scope (what products are covered), contacts (email/web form), and disclosure policy URLs.
  486 CVE Numbering Authorities are registered. If no CNA covers the product, MITRE is the CNA of Last Resort:
    lookup(type="disclosure", identifier="mitre.org")    → MITRE CNA-LR for uncovered products

RESPONSE: Same format as resolve — { secid_query, status, results[], message? }
Results from different sources will have different secid values showing where each match was found.
Sort by weight descending — highest weight is the most authoritative source.

TYPES: advisory (CVEs, vendor advisories), weakness (CWE, OWASP), ttp (ATT&CK, CAPEC), control (NIST, ISO), capability (product security features — encryption, logging, access control), methodology (scoring, mapping, risk assessment — CVSS, SSVC, IR 8477), disclosure (CVE CNAs, PSIRTs, vulnerability reporting — 486 CNAs with scope, contacts, policy), regulation (GDPR, HIPAA), entity (orgs, products), reference (RFCs, arXiv, DOI)`;

const DESCRIBE_DESCRIPTION = `Get registry metadata about a SecID source, namespace, or type — without resolving a specific item.

Use this to discover what's available: what sources exist, what identifier patterns they accept, and what URLs they provide.

EXAMPLES:
  secid:advisory/mitre.org/cve   → description of CVE, accepted patterns, example IDs, source URLs
  secid:advisory/mitre.org       → list of all sources MITRE publishes (cve, cvelistV5)
  secid:advisory                 → list of all advisory namespaces (mitre.org, nist.gov, redhat.com, ...)
  secid:control                  → list of all control namespaces
  secid:capability/amazon.com/aws   → list all AWS service security capabilities
  secid:capability                  → list all capability namespaces
  secid:disclosure/redhat.com       → list Red Hat's disclosure programs (CNA, CNA-LR, Root)
  secid:disclosure                  → list all 486 CVE CNA disclosure namespaces

DISCLOSURE / CNA DISCOVERY:
  Use describe with the disclosure type to find vulnerability reporting channels:
  secid:disclosure/apple.com/cna  → Apple's CNA: scope, contact email, disclosure policy URL
  secid:disclosure/google.com     → Google's 5 CNA programs (Android, Cloud, Devices, Chrome, Mandiant)
  Each CNA entry includes: scope (what it covers), contacts (email/form), cve_program_role, disclosure policy URL.

If you pass a SecID with a subpath (e.g. secid:advisory/mitre.org/cve#CVE-2024-1234), the subpath is stripped and you get source-level info instead of resolution.

RESPONSE: Same envelope — { secid_query, status, results[] }
Results contain { secid, data } with registry metadata (official_name, patterns, examples, urls).

Use this to help users construct valid SecID strings or to explore what the registry covers.`;

function createMcpServer(
  kv: KVNamespace | undefined,
  registryKv: KVNamespace,
  req: Request
): McpServer {
  const server = new McpServer({
    name: "secid",
    version: "0.2.0",
  });

  // ── Tool: resolve ──
  server.tool(
    "resolve",
    RESOLVE_DESCRIPTION,
    {
      secid: z
        .string()
        .describe("Full SecID string, e.g. 'secid:advisory/mitre.org/cve#CVE-2021-44228' or 'secid:advisory/CVE-2021-44228' for cross-source search"),
    },
    async ({ secid }) => {
      if (secid.length > MAX_SECID_QUERY_CHARS) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: secid.slice(0, MAX_SECID_QUERY_CHARS),
              status: "error",
              results: [],
              message: `SecID query exceeds ${MAX_SECID_QUERY_CHARS} characters. Limit: ${MAX_SECID_QUERY_CHARS} characters.`,
            }),
          }],
          isError: true,
        };
      }
      try {
        const result = await resolveFromKV(registryKv, secid);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        const entry = buildErrorEntry("mcp.tool.resolve", secid, err, req);
        const errorId = await recordError(kv, entry);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: secid,
              status: "error",
              results: [],
              message: `Internal error. Reference: ${errorId}`,
              error_id: errorId,
            }),
          }],
          isError: true,
        };
      }
    }
  );

  // ── Tool: lookup ──
  server.tool(
    "lookup",
    LOOKUP_DESCRIPTION,
    {
      type: z.enum(SECID_TYPES).describe("Security knowledge type: advisory, weakness, ttp, control, capability, methodology, disclosure, regulation, entity, or reference"),
      identifier: z
        .string()
        .describe("The identifier to search for, e.g. 'CVE-2021-44228', 'CWE-79', 'T1059.003'"),
    },
    async ({ type, identifier }) => {
      if (identifier.length > MAX_SECID_QUERY_CHARS) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: `secid:${type}/${identifier.slice(0, MAX_SECID_QUERY_CHARS)}`,
              status: "error",
              results: [],
              message: `Identifier exceeds ${MAX_SECID_QUERY_CHARS} characters. Limit: ${MAX_SECID_QUERY_CHARS} characters.`,
            }),
          }],
          isError: true,
        };
      }
      const secid = `secid:${type}/${identifier}`;
      try {
        const result = await resolveFromKV(registryKv, secid);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        const entry = buildErrorEntry("mcp.tool.lookup", secid, err, req);
        const errorId = await recordError(kv, entry);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: secid,
              status: "error",
              results: [],
              message: `Internal error. Reference: ${errorId}`,
              error_id: errorId,
            }),
          }],
          isError: true,
        };
      }
    }
  );

  // ── Tool: describe ──
  server.tool(
    "describe",
    DESCRIBE_DESCRIPTION,
    {
      secid: z
        .string()
        .describe("SecID without subpath, e.g. 'secid:advisory/mitre.org/cve', 'secid:advisory/mitre.org', or 'secid:advisory'"),
    },
    async ({ secid }) => {
      if (secid.length > MAX_SECID_QUERY_CHARS) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: secid.slice(0, MAX_SECID_QUERY_CHARS),
              status: "error",
              results: [],
              message: `SecID query exceeds ${MAX_SECID_QUERY_CHARS} characters. Limit: ${MAX_SECID_QUERY_CHARS} characters.`,
            }),
          }],
          isError: true,
        };
      }
      try {
        // Strip subpath (#...) from input for describe — return source-level info
        const hashIdx = secid.indexOf("#");
        const describeInput = hashIdx !== -1 ? secid.slice(0, hashIdx) : secid;
        const result = await resolveFromKV(registryKv, describeInput);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        const entry = buildErrorEntry("mcp.tool.describe", secid, err, req);
        const errorId = await recordError(kv, entry);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              secid_query: secid,
              status: "error",
              results: [],
              message: `Internal error. Reference: ${errorId}`,
              error_id: errorId,
            }),
          }],
          isError: true,
        };
      }
    }
  );

  // ── Resource: registry listing ──
  server.resource(
    "registry",
    "secid://registry",
    { description: "Full listing of all SecID types and their namespace counts. SecID covers 10 types: advisory (CVEs, vendor advisories), weakness (CWE, OWASP), ttp (ATT&CK, CAPEC), control (NIST, ISO), capability (product security features — encryption, logging, access control), methodology (scoring, mapping, risk assessment — CVSS, SSVC, IR 8477), disclosure (CVE CNAs, PSIRTs, bug bounties), regulation (GDPR, HIPAA), entity (orgs, products), reference (RFCs, arXiv, DOI). 616+ namespaces total." },
    async () => {
      const listing: Record<string, number> = {};
      const ctx = new RegistryContext(registryKv);
      for (const type of SECID_TYPES) {
        const idx = await ctx.getTypeIndex(type);
        listing[type] = idx?.namespaces.length ?? 0;
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
        const ctx = new RegistryContext(registryKv);
        const idx = await ctx.getTypeIndex(type);
        const namespaces = (idx?.namespaces ?? []).map((n) => ({
          namespace: n.namespace,
          official_name: n.official_name,
          common_name: n.common_name,
          source_count: n.source_count,
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

  // ── Resource: build-a-client guide ──
  server.resource(
    "docs-build-a-client",
    "secid://docs/build-a-client",
    { description: "Complete instructions for building a SecID HTTP client in any programming language. Covers the API contract, encoding rules (# must be %23), response handling, status values, result types, weights, cross-source search, version disambiguation, and a 10-item implementation checklist. Read this to generate a working client." },
    async () => ({
      contents: [{
        uri: "secid://docs/build-a-client",
        mimeType: "text/markdown",
        text: BUILD_A_CLIENT_DOC,
      }],
    })
  );

  // ── Resource: prompt template for generating clients ──
  server.resource(
    "docs-prompt-template",
    "secid://docs/prompt-template",
    { description: "Ready-to-use prompt template for generating a SecID client in any language. Replace {LANGUAGE} with your target language and give to an AI assistant. Contains the full API contract, required class interface, CLI mode spec, and implementation requirements — everything needed in a single copy-paste prompt." },
    async () => ({
      contents: [{
        uri: "secid://docs/prompt-template",
        mimeType: "text/markdown",
        text: PROMPT_TEMPLATE_DOC,
      }],
    })
  );

  // ── Resource: feedback and support ──
  server.resource(
    "docs-feedback",
    "secid://docs/feedback",
    { description: "How to report issues, request new namespaces, give feedback, or contribute to the SecID registry. Read this if a query returned not_found for a source that should be covered, or if you found incorrect data." },
    async () => ({
      contents: [{
        uri: "secid://docs/feedback",
        mimeType: "text/markdown",
        text: `# SecID Feedback & Support

## Report Issues or Request New Sources

**GitHub Issues:** https://github.com/CloudSecurityAlliance/SecID/issues

Use this to:
- Request a new namespace (e.g., "please add vendor X's advisory database")
- Report incorrect data (wrong URLs, outdated contacts, bad patterns)
- Report a bug in the resolver or MCP server
- Suggest improvements

## Contributing

The SecID registry is open source. Adding a new source is a single JSON file.

- **Registry repo:** https://github.com/CloudSecurityAlliance/SecID
- **Service repo:** https://github.com/CloudSecurityAlliance/SecID-Service
- **How to add a namespace:** https://github.com/CloudSecurityAlliance/SecID/blob/main/docs/guides/ADD-NAMESPACE.md

## Specification

- **SecID spec:** https://github.com/CloudSecurityAlliance/SecID/blob/main/SPEC.md
- **Registry format:** https://github.com/CloudSecurityAlliance/SecID/blob/main/docs/reference/REGISTRY-JSON-FORMAT.md

## Contact

SecID is a Cloud Security Alliance project.
- **Website:** https://cloudsecurityalliance.org
- **Service:** https://secid.cloudsecurityalliance.org
`,
      }],
    })
  );

  return server;
}

export async function handleMCP(c: Context<AppEnv>): Promise<Response> {
  if (!c.env.secid_REGISTRY) {
    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32603, message: "Registry KV not configured." },
        id: null,
      },
      503,
    );
  }

  const contentLength = c.req.header("content-length");
  const parsedLength = contentLength ? Number.parseInt(contentLength, 10) : NaN;
  if (Number.isFinite(parsedLength) && parsedLength > MAX_MCP_BODY_BYTES) {
    return c.json(
      {
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: `Request body exceeds ${MAX_MCP_BODY_BYTES} bytes.`,
        },
        id: null,
      },
      413,
    );
  }

  const server = createMcpServer(c.env.secid_OBSERVABILITY, c.env.secid_REGISTRY, c.req.raw);

  try {
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // Stateless — no session tracking
      enableJsonResponse: true,      // Prefer JSON for simple req/res
    });

    await server.connect(transport);
    const response = await transport.handleRequest(c.req.raw);
    return response;
  } catch (err) {
    const entry = buildErrorEntry("mcp.transport", c.req.url, err, c.req.raw);
    const errorId = await recordError(c.env.secid_OBSERVABILITY, entry);

    return c.json(
      {
        jsonrpc: "2.0",
        error: { code: -32603, message: `Internal error. Reference: ${errorId}` },
        id: null,
      },
      500,
    );
  }
}
