```
project_tracker_base: CINO Project Tracker:appf7fRQUvY9Iy7sL
project_tracker_table: Projects:tblchmbxSAavvJKaY
project_tracker_record: SecID-Service:recJ2sF2CudDqTJRN
project_source: github:CloudSecurityAlliance-Internal/CINO-Projects/projects/SecID-Service
```

# SecID-Service

REST API and MCP server for resolving security identifiers to URLs. A [Cloud Security Alliance](https://cloudsecurityalliance.org) project by Kurt Seifried, Chief Innovation Officer.

**Live at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/)**

## SecID MCP Server

Add SecID to your AI assistant as a remote MCP server:

```
https://secid.cloudsecurityalliance.org/mcp
```

That's it. No API keys, no local install, no configuration. Works with Claude Desktop, Claude Code, Cursor, Windsurf, and any MCP client that supports remote servers. Your AI assistant gets three tools (`resolve`, `lookup`, `describe`) and can immediately look up CVEs, CWEs, ATT&CK techniques, NIST controls, and 1,150+ other security knowledge sources.

**Other ways to use SecID:** [Claude Code plugin](https://github.com/CloudSecurityAlliance/SecID/tree/main/plugins/secid) (local MCP server, supports internal resolvers) | [Client SDKs](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) (Python, TypeScript, Go) | REST API (below)

## REST API

One endpoint:

```
GET https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
```

Note: `#` must be encoded as `%23` in the query parameter.

Response:

```json
{
  "secid_query": "secid:advisory/mitre.org/cve#CVE-2021-44228",
  "status": "found",
  "results": [
    {
      "secid": "secid:advisory/mitre.org/cve#CVE-2021-44228",
      "weight": 100,
      "url": "https://www.cve.org/CVERecord?id=CVE-2021-44228"
    }
  ]
}
```

No authentication. CORS enabled.

## Operational Limits

- `secid` input limit: **1024 characters** on REST and MCP tool inputs.
  - REST returns `status="error"` with: `SecID query exceeds 1024 characters. Limit: 1024 characters.`
  - MCP returns tool error content with the same explicit limit message.
- MCP HTTP request body limit (via `Content-Length`): **64 KiB** (`413` when exceeded).
- Cloudflare KV value limit: **25 MiB** per key.
  - Registry upload script enforces this limit before upload.
  - Service also checks `full:registry` payload size before serving `/api/v1/registry.json`.
- Abuse throttling/rate limiting: handled primarily at the **Cloudflare edge** (WAF/rate-limit controls), with Worker input-size guards as defense in depth.

## Architecture

- **Runtime:** Cloudflare Workers
- **Framework:** Hono + @modelcontextprotocol/sdk
- **Registry:** Compiled from [SecID](https://github.com/CloudSecurityAlliance/SecID) registry JSON files (1,150+ namespaces, 10 types)
- **Website:** Astro static site served from the same Worker

## Planned: also runs under the CSA MCP Server front door

Today SecID-Service runs only at `secid.cloudsecurityalliance.org/mcp` (anonymous, no auth — the friction-free public utility). Per [CSA-MCP-Server ADR-002](https://github.com/CloudSecurityAlliance-Internal/CSA-MCP-Server/blob/main/DECISIONS.md#adr-002-federation-strategy--monolith-composition-now-service-bindings-later-dual-shape-capabilities-with-two-welcome-variants), every capability ships in two shapes — a standalone deploy (this Worker, unchanged) AND a plugin form consumed by [CSA-MCP-Server](https://github.com/CloudSecurityAlliance-Internal/CSA-MCP-Server) at `cloudsecurityalliance.org/mcp` (Auth0-gated, alongside Search and future Working Groups / Training / Navigator).

SecID is the likely first test of the two-shapes pattern because it already exists as a working standalone Worker. The refactor is to lift the tool *logic* (the resolve / lookup / describe data work — currently in `src/mcp.ts`) into a shared package that both this Worker's `mcp.ts` AND a new front-door plugin package import. Standalone keeps anonymous access; front door adds Auth0 on top. A SecID-specific ADR (forthcoming, will live here in this repo's DECISIONS.md or DECISIONS-ADR.md) will document the concrete refactor steps when work starts.

**The umbrella SecID will join:**

| Repo | Role |
|---|---|
| [CSA-MCP-Server](https://github.com/CloudSecurityAlliance-Internal/CSA-MCP-Server) | The front-door composition — deploys to `cloudsecurityalliance.org/mcp`. Will import SecID's plugin form alongside the Search plugin. |
| [CSA-MCP-Core](https://github.com/CloudSecurityAlliance-Internal/CSA-MCP-Core) | Shared infrastructure library — auth, rate limits, observability, MCP protocol plumbing. SecID's plugin form will import this; standalone SecID may also adopt it incrementally for DRY observability/safety helpers. |
| [CSA-Search-2.0](https://github.com/CloudSecurityAlliance-Internal/CSA-Search-2.0) | First non-platform plugin (search / ask / get_artifact). The pattern SecID's plugin form will follow. |
| [CINO-Products / csa-mcp-server](https://github.com/CloudSecurityAlliance-Internal/CINO-Products/tree/main/products/csa-mcp-server) | Product-level umbrella — strategic positioning, capability roadmap. |

This is forward-looking — no code change today, just signal that the repo's role is broadening.

## Development

```bash
npm install
npm run dev              # Local dev server
npm run test             # Run tests
npm run build:registry   # Recompile registry from SecID repo
npm run deploy           # Deploy to Cloudflare
```

## Related Repositories

| Repo | Purpose |
|------|---------|
| [SecID](https://github.com/CloudSecurityAlliance/SecID) | Specification + registry data |
| **SecID-Service** (this repo) | Cloudflare Worker REST API + MCP server |
