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

That's it. No API keys, no local install, no configuration. Works with Claude Desktop, Claude Code, Cursor, Windsurf, and any MCP client that supports remote servers. Your AI assistant gets three tools (`resolve`, `lookup`, `describe`) and can immediately look up CVEs, CWEs, ATT&CK techniques, NIST controls, and more than 2,100 other security knowledge sources.

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

No authentication. CORS is open (`Access-Control-Allow-Origin: *`) for `GET`, `HEAD`, `POST` and
`OPTIONS`, never with credentials — there is no ambient credential to protect.

## MCP endpoint behaviour

`https://secid.cloudsecurityalliance.org/mcp` (and `/mcp/`) is a **stateless** Streamable HTTP
endpoint: every MCP message is a `POST`. Everything else is answered explicitly, by one middleware
([`src/method-gate.ts`](src/method-gate.ts), [ADR-015](DECISIONS.md#adr-015-mcp-endpoint-answers-every-http-method-explicitly)):

| Request | Answer |
|---|---|
| `POST` | JSON-RPC (the MCP SDK's handling) |
| `GET` / `HEAD` from an MCP client | `405`, `Allow: POST, OPTIONS` — no server-push stream on a stateless server |
| `GET` / `HEAD` from a browser | `302` to the [setup instructions](https://secid.cloudsecurityalliance.org/#mcp-setup) |
| `DELETE`, `PUT`, `PATCH`, `QUERY`, `TRACE`, `CONNECT` | `405`, `Allow: POST, OPTIONS` |
| an unregistered method | `501` |

A browser is identified positively (`Sec-Fetch-Mode: navigate`, or `Accept: text/html`) and only
after ruling out every MCP-client signal (`text/event-stream` in `Accept`, `MCP-Protocol-Version`,
`Mcp-Session-Id`). Getting this wrong is not cosmetic: an MCP client handed a redirect instead of a
`405` reconnects once a second for its whole session.

## Operational Limits

- `secid` input limit: **1024 characters** on REST and MCP tool inputs.
  - REST returns `status="error"` with: `SecID query exceeds 1024 characters. Limit: 1024 characters.`
  - MCP returns tool error content with the same explicit limit message.
- MCP HTTP request body limit: **64 KiB** (`413` when exceeded).
- Cloudflare KV value limit: **25 MiB** per key.
  - Registry upload script enforces this limit before upload.
  - Service also checks `full:registry` payload size before serving `/api/v1/registry.json`.
- Abuse throttling: the Worker enforces the input-size limits above. Edge rate limiting (Cloudflare WAF) is the intended primary layer ([ADR-012](DECISIONS.md)), but that configuration lives in the Cloudflare dashboard, not in this repository — check the zone's rules rather than assuming they are active.

## Architecture

- **Runtime:** Cloudflare Workers
- **Framework:** Hono + @modelcontextprotocol/sdk
- **Registry:** Compiled from [SecID](https://github.com/CloudSecurityAlliance/SecID) registry JSON files (more than 2,100 namespaces across 10 types)
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
npm install --prefix website   # the website is a separate Astro project
npm run dev                    # Local dev server
npm run test                   # Unit/integration tests (Vitest, inside workerd)
npm run test:e2e               # Playwright against production (SITE_URL to override)
npm run build:registry         # Recompile registry from SecID repo
npm run build:website          # Rebuild the static site into website/dist
```

## Deployment

**Merging to `main` deploys to production**, through
[`.github/workflows/registry-kv-upload.yml`](.github/workflows/registry-kv-upload.yml). The same
workflow runs on `repository_dispatch` from the SecID spec repo when the registry changes, and on
manual `workflow_dispatch`. Every run, in order:

1. **Unit tests** (`npx vitest run`) against a registry snapshot built from the SecID revision
   being deployed — a red suite stops the run before anything is uploaded.
2. **KV sync** of the registry (`upload-registry-kv.ts --sync`).
3. **`wrangler deploy`** of the Worker and the website.
4. **Post-deploy verification**: the Playwright suite against production — the website, plus the
   MCP endpoint (a real MCP client, the method table above, CORS). Tests tagged `@third-party`
   (cve.org, cwe.mitre.org, …) are excluded so an outage elsewhere cannot fail a deploy.

Pull requests are gated separately by [`ci.yml`](.github/workflows/ci.yml) (typecheck, website
build, unit tests). It never deploys.

**If post-deploy verification fails, the new version is already live.** The job fails and its
summary says so. Roll back with:

```bash
npx wrangler rollback --message "post-deploy verification failed"
```

**Watch and confirm a deploy:** `gh run list --workflow=registry-kv-upload.yml --limit 3`, then
`npx wrangler deployments list` — each deployment should match one workflow run, about two minutes
after it starts. The site footer shows the deployed commit SHA.

**Every version names its source.** The workflow tags each Worker version with the SecID-Service
commit and stamps a message with that commit, the SecID registry commit, the trigger and the
Actions run — `npx wrangler versions list` (or the dashboard's Versions list) shows them. Cloudflare
still lists the author as "Unknown": that field is the API token's owner, and the deploy token is an
account token. A break-glass `npm run deploy` stamps `break-glass by <git user>`, and `+dirty` if
the working tree had uncommitted changes.

> **Correction (2026-10-01):** this section previously said Cloudflare Workers Builds deployed on
> push, with no test gate (#28). Since at least 2026-09-25 every production deployment corresponds
> one-to-one with a run of the workflow above, with no additional deployments, so Workers Builds is
> not deploying. The Cloudflare dashboard (Workers & Pages → `secid-service` → Settings → Build)
> is the place to confirm no Git connection remains.

### Deploying by hand (break-glass)

```bash
npm run deploy
```

Use this only when the automatic pipeline is unavailable. It builds the website
and then deploys, in that order, and the order matters: `wrangler.toml` sets
`[assets] directory = "./website/dist"`, and `website/dist/` is gitignored. A bare
`wrangler deploy` publishes whatever happens to be on your disk — which, on a
checkout that has not built the site recently, silently replaces the live website
with a stale build. Prefer merging to `main`.

A hand deploy skips the post-deploy verification, so run it yourself afterwards:

```bash
npx playwright test --grep-invert @third-party
```

## Related Repositories

| Repo | Purpose |
|------|---------|
| [SecID](https://github.com/CloudSecurityAlliance/SecID) | Specification + registry data |
| **SecID-Service** (this repo) | Cloudflare Worker REST API + MCP server |
