# Operational Resources

Index of recurring operational work for SecID-Service. Pairs with [BACKUP-RESOURCES.md](BACKUP-RESOURCES.md) (what runs vs. how it survives).

---

## Cloudflare Worker — `secid-service`

**What it does.** Serves the live SecID resolver and MCP server at `secid.cloudsecurityalliance.org`. Hosts the `/api/v1/resolve`, `/api/v1/lookup`, `/api/v1/describe`, `/mcp`, `/.well-known/*`, and the Astro static site (`website/dist`).

- **Code:** [`src/index.ts`](src/index.ts), [`src/mcp.ts`](src/mcp.ts), [`src/resolver.ts`](src/resolver.ts)
- **Config:** [`wrangler.toml`](wrangler.toml) — Worker name `secid-service`, account `f3898058ae0b4c20c692bbfa5b9b44b0`, route `secid.cloudsecurityalliance.org/*` (zone `113bb8004441490558a7ce8b4b611cc1`)
- **Runtime:** Cloudflare Workers (V8 isolates, edge-distributed)
- **Inputs:** HTTP requests, KV reads from `secid_REGISTRY`
- **Outputs:** JSON resolver responses, MCP JSON-RPC responses, static HTML, error records into `secid_OBSERVABILITY`
- **Status:** production
- **Last touched:** 2026-04-30
- **Next review:** 2026-08-01
- **Cadence:** request-driven (no schedule)
- **Health check:** `curl https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228` — should return JSON envelope with a URL
- **Runbook:** Manual deploy via `npx wrangler deploy` (uses `CLOUDFLARE_API_TOKEN` env). Auto-deploy via `registry-kv-upload.yml` (see below)
- **Owner:** Kurt Seifried
- **Notes:** Astro site is bundled into the same Worker via `[assets]` in `wrangler.toml`

## KV namespace — `secid_REGISTRY`

**What it does.** Backing store for compiled registry data the Worker reads at request time. Each key is a namespace lookup; value is the JSON registry entry. Built from `registry/**/*.json` in the SecID spec repo via `scripts/build-registry.ts`.

- **Code:** [`scripts/build-registry.ts`](scripts/build-registry.ts), [`scripts/upload-registry-kv.ts`](scripts/upload-registry-kv.ts)
- **Binding ID:** `cfbc271787614516a39fa43d9ca4f95a` (preview: `bda410b73cc34b468c84bf2dc9fba45f`)
- **Runtime:** Cloudflare KV
- **Inputs:** registry JSON files in [CloudSecurityAlliance/SecID](https://github.com/CloudSecurityAlliance/SecID) `registry/**/*.json` (724 namespaces as of 2026-05-07)
- **Outputs:** KV keys consumed by the Worker resolver
- **Status:** production
- **Last touched:** 2026-04-30 (last successful sync — chain has been broken since)
- **Next review:** unblock as part of FRICTION-001 resolution; then quarterly thereafter
- **Cadence:** auto-synced on push to `registry/**/*.json` in the SecID repo
- **Health check:** `wrangler kv key list --namespace-id=cfbc271787614516a39fa43d9ca4f95a | wc -l` should match the namespace count produced by `build-registry.ts`
- **Runbook:** `npx tsx scripts/upload-registry-kv.ts --sync /path/to/SecID` from this repo with `CLOUDFLARE_API_TOKEN` set to a token that has Workers KV Edit permission. `--sync` mode overwrites changed keys and deletes orphans (with a 50-key safety threshold)
- **Owner:** Kurt Seifried

## KV namespace — `secid_OBSERVABILITY`

**What it does.** Always-on error and access log store with UUIDv7 IDs. Errors are written via `buildErrorEntry()` + `recordError()` from `src/observability.ts`. Used for post-hoc debugging and operational visibility.

- **Code:** [`src/observability.ts`](src/observability.ts)
- **Binding ID:** `c5cbc52b9a724433b3043efdf31857f4` (preview: `3bc7078377cb44bc8fc63e5f9f344392`)
- **Runtime:** Cloudflare KV
- **Inputs:** errors raised by Worker request handlers; request metadata
- **Outputs:** KV keys (UUIDv7-named) for inspection via `wrangler kv key list`
- **Status:** production
- **Last touched:** 2026-03-05 (initial deployment)
- **Next review:** 2026-09-01 (review retention strategy; KV has no TTL set)
- **Cadence:** continuous, request-driven
- **Health check:** `wrangler kv key list --namespace-id=c5cbc52b9a724433b3043efdf31857f4 | head` — non-empty list during error conditions, empty during clean operation
- **Runbook:** Read individual entries with `wrangler kv key get --namespace-id=c5cbc52b9a724433b3043efdf31857f4 <key>`. UUIDv7 IDs sort lexicographically by time, so most recent errors are at the end of the listing
- **Owner:** Kurt Seifried
- **Notes:** No retention policy yet; will need pruning strategy as volume grows. Philosophy doc: `CINO-Platform-Engineering/research/operational-excellence/OPERATIONAL-PHILOSOPHY.md`

## GitHub Actions — Deploy chain (cross-repo)

**What it does.** Two-stage auto-deploy from registry JSON changes to live KV + Worker:

1. **Stage 1 (SecID repo):** [`update-registry.yml`](https://github.com/CloudSecurityAlliance/SecID/blob/main/.github/workflows/update-registry.yml) — fires on push to `main` touching `registry/**/*.json`; sends `repository_dispatch` to SecID-Service using `SECID_TO_SERVICE_DISPATCH` PAT
2. **Stage 2 (this repo):** [`.github/workflows/registry-kv-upload.yml`](.github/workflows/registry-kv-upload.yml) — receives dispatch, checks out both repos, runs `build-registry.ts`, builds website, runs `vitest`, uploads to KV in `--sync` mode using `SECID_SERVICE_DEPLOY` Cloudflare token, deploys Worker

- **Runtime:** GitHub Actions runners (`ubuntu-latest`, Node 22)
- **Inputs:** push events on registry JSON; `repository_dispatch` events of type `registry-updated`
- **Outputs:** updated `secid_REGISTRY` KV; redeployed Worker
- **Status:** **broken** since 2026-04-30 — see [FRICTION-001](FRICTION/FRICTION-001.md) and [WAITING-FOR-001](WAITING-FOR/WAITING-FOR-001.md). Auto-trigger fails (`SECID_TO_SERVICE_DISPATCH` token unauthorized); manual `workflow_dispatch` of Stage 2 fails on `cve-schema` Vitest test failure
- **Last touched:** 2026-04-30
- **Next review:** weekly until FRICTION-001 is resolved; then 2026-09-01
- **Cadence:** event-driven (every push to `registry/**/*.json`)
- **Health check:** `gh run list --workflow=registry-kv-upload.yml --limit 3 -R CloudSecurityAlliance/SecID-Service` — most recent run should be `success`. Currently shows `failure`/no-recent-runs
- **Runbook:** See FRICTION-001 for current breakage and partial workarounds. Local audit (no mutations): `npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID` from this repo with a working `CLOUDFLARE_API_TOKEN`
- **Owner:** Kurt Seifried

## DNS — `secid.cloudsecurityalliance.org`

**What it does.** Resolves the public hostname to the Worker route. Configured in Cloudflare DNS for `cloudsecurityalliance.org` zone (`113bb8004441490558a7ce8b4b611cc1`).

- **Runtime:** Cloudflare DNS
- **Status:** production
- **Last touched:** initial setup (2026-04 launch)
- **Next review:** 2026-09-01
- **Cadence:** static
- **Health check:** `dig secid.cloudsecurityalliance.org +short` — should return Cloudflare anycast IPs
- **Runbook:** Cloudflare dashboard → cloudsecurityalliance.org → DNS. Worker route binding in `wrangler.toml`
- **Owner:** Kurt Seifried
- **Notes:** Backed up in [BACKUP-RESOURCES.md](BACKUP-RESOURCES.md)
