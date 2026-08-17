# INTERFACE-RESOURCES.md — SecID-Service

**Last verified:** 2026-08-07
**Scope:** Interfaces this repo exposes to callers, and first-party interfaces it
consumes. Infrastructure (KV namespaces, bindings, DNS, tokens) lives in
[OPERATIONAL-RESOURCES.md](OPERATIONAL-RESOURCES.md); backup posture in
[BACKUP-RESOURCES.md](BACKUP-RESOURCES.md). Third-party npm dependencies live in
`package.json`.

---

## Provides

### `secid-service` — mcp, http-api

One Cloudflare Worker serving two protocols at one hostname. Deliberately a
single entry: the MCP tools and the REST endpoints are the same resolver logic
behind two wire formats, and splitting them into separate entries would let the
two descriptions drift apart.

- **Endpoint:** `secid.cloudsecurityalliance.org`
  - `/mcp` — MCP JSON-RPC (also `/mcp/*` for sub-paths)
  - `/api/v1/resolve`, `/api/v1/lookup`, `/api/v1/describe` — REST
  - `/.well-known/*` — discovery metadata
- **Transport:** HTTP (remote); no stdio variant
- **Tools (MCP):** `resolve`, `lookup`, `describe`, `submit_feedback`
- **Auth:** anonymous — no token, no tier system. Every caller gets the same access.
- **Code:** [`src/index.ts`](src/index.ts) (router), [`src/mcp.ts`](src/mcp.ts)
  (MCP layer), [`src/resolver.ts`](src/resolver.ts) (shared resolution logic)
- **Status:** production
- **Health check:**
  ```bash
  curl 'https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228'
  ```
  Expect a JSON envelope containing a URL.
- **Owner:** Kurt Seifried
- **Notes:** The same Worker also serves the Astro static site (`website/dist`,
  bundled via `[assets]` in `wrangler.toml`). Not listed as an interface — it is
  a website for humans, not a programmatic surface.

---

## Uses

### SecID registry — data-feed

- **Provided by:** [`CloudSecurityAlliance/SecID`](https://github.com/CloudSecurityAlliance/SecID)
- **Surface:** `registry/**/*.json` in that repo, compiled by
  [`scripts/build-registry.ts`](scripts/build-registry.ts) and pushed into the
  `secid_REGISTRY` KV namespace
- **Why:** the registry *is* the resolver's data — without it every lookup misses
- **Transport:** cross-repo GitHub Actions `repository_dispatch` (type
  `registry-updated`), then KV upload
- **Status:** **broken** since 2026-04-30 — see
  [FRICTION-001](FRICTION/FRICTION-001.md) and
  [WAITING-FOR-001](WAITING-FOR/WAITING-FOR-001.md). The live KV data is stale
  relative to the spec repo until this is fixed.
- **Notes:** 724 namespaces as of 2026-05-07. The KV namespace itself is
  infrastructure and documented in
  [OPERATIONAL-RESOURCES.md](OPERATIONAL-RESOURCES.md); what is recorded here is
  the *dependency on another first-party repo's content*.

---

## Not listed here

| Thing | Where it lives |
|---|---|
| KV namespaces, bindings, zone/account IDs, DNS | [OPERATIONAL-RESOURCES.md](OPERATIONAL-RESOURCES.md) |
| Backup and restore posture | [BACKUP-RESOURCES.md](BACKUP-RESOURCES.md) |
| npm dependencies | `package.json` |
| Deploy chain and runbooks | [OPERATIONAL-RESOURCES.md](OPERATIONAL-RESOURCES.md) |
