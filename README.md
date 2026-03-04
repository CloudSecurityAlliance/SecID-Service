# SecID-Service

REST API and MCP server for resolving security identifiers to URLs.

**Live at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/)**

## SecID MCP Server

Add SecID to your AI assistant as a remote MCP server:

```
https://secid.cloudsecurityalliance.org/mcp
```

That's it. No API keys, no local install, no configuration. Works with Claude Desktop, Claude Code, Cursor, Windsurf, and any MCP client that supports remote servers. Your AI assistant gets three tools (`resolve`, `lookup`, `describe`) and can immediately look up CVEs, CWEs, ATT&CK techniques, NIST controls, and 121 other security knowledge sources.

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

## Architecture

- **Runtime:** Cloudflare Workers
- **Framework:** Hono + @modelcontextprotocol/sdk
- **Registry:** Compiled from [SecID](https://github.com/CloudSecurityAlliance/SecID) registry JSON files (121 namespaces, 7 types)
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
