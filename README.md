# SecID-Service

REST API and MCP server for resolving security identifiers to URLs. A [Cloud Security Alliance](https://cloudsecurityalliance.org) project by Kurt Seifried, Chief Innovation Officer.

**Live at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/)**

## SecID MCP Server

Add SecID to your AI assistant as a remote MCP server:

```
https://secid.cloudsecurityalliance.org/mcp
```

That's it. No API keys, no local install, no configuration. Works with Claude Desktop, Claude Code, Cursor, Windsurf, and any MCP client that supports remote servers. Your AI assistant gets three tools (`resolve`, `lookup`, `describe`) and can immediately look up CVEs, CWEs, ATT&CK techniques, NIST controls, and 650+ other security knowledge sources.

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
- **Registry:** Compiled from [SecID](https://github.com/CloudSecurityAlliance/SecID) registry JSON files (700+ namespaces, 10 types)
- **Website:** Astro static site served from the same Worker

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
