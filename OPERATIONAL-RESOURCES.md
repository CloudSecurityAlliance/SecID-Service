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
- **Last touched:** 2026-09-25
- **Next review:** 2026-08-01
- **Cadence:** request-driven (no schedule)
- **Health check:** `curl https://secid.cloudsecurityalliance.org/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228` — should return JSON envelope with a URL
- **Runbook:** Normal deploy = merge to `main` (`registry-kv-upload.yml`: unit tests → KV sync → `wrangler deploy` → Playwright verification against production). Break-glass: `npm run deploy` (builds the website first), then `npx playwright test --grep-invert @third-party`. Roll back: `npx wrangler rollback --message "<why>"`
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
- **Last touched:** 2026-11-04 (continuous auto-sync active; FRICTION-001 resolved 2026-09-25)
- **Next review:** 2027-02-01 (quarterly)
- **Cadence:** auto-synced on push to `registry/**/*.json` in the SecID repo
- **Health check:** `wrangler kv key list --namespace-id=cfbc271787614516a39fa43d9ca4f95a | wc -l` should match the namespace count produced by `build-registry.ts`
- **Runbook:** `npx tsx scripts/upload-registry-kv.ts --sync /path/to/SecID` from this repo with `CLOUDFLARE_API_TOKEN` set to a token that has Workers KV Edit permission. `--sync` mode overwrites changed keys and deletes orphans (with a 50-key safety threshold)
- **Owner:** Kurt Seifried

## KV namespace — `secid_OBSERVABILITY`

**What it does.** Always-on error and access log store with UUIDv7 IDs. Errors are written via `buildErrorEntry()` + `recordError()` from `src/observability.ts` with a 30-day `expirationTtl` (`TTL_30_DAYS = 2,592,000` seconds) and bounded by a per-isolate write budget (`ERROR_WRITES_PER_MINUTE = 60`). Used for post-hoc debugging and operational visibility.

- **Code:** [`src/observability.ts`](src/observability.ts)
- **Binding ID:** `c5cbc52b9a724433b3043efdf31857f4` (preview: `3bc7078377cb44bc8fc63e5f9f344392`)
- **Runtime:** Cloudflare KV
- **Inputs:** errors raised by Worker request handlers; request metadata (IP/User-Agent omitted for privacy)
- **Outputs:** KV keys (`error:<uuidv7>`) for inspection via `wrangler kv key list`
- **Status:** production
- **Last touched:** 2026-11-04
- **Next review:** 2027-02-01
- **Cadence:** continuous, request-driven
- **Retention:** 30-day automatic KV `expirationTtl` (`TTL_30_DAYS = 2,592,000` seconds)
- **Health check:** `wrangler kv key list --namespace-id=c5cbc52b9a724433b3043efdf31857f4 | head` — non-empty list during error conditions, empty during clean operation
- **Runbook:** Read individual entries with `wrangler kv key get --namespace-id=c5cbc52b9a724433b3043efdf31857f4 <key>`. UUIDv7 IDs sort lexicographically by time, so most recent errors are at the end of the listing
- **Owner:** Kurt Seifried
- **Notes:** 30-day KV TTL keeps error storage self-pruning. Philosophy doc: `CINO-Engineering/research/operational-excellence/OPERATIONAL-PHILOSOPHY.md`

## KV namespace — `secid_FEEDBACK`

**What it does.** Active MCP feedback inbox (`feedback:<uuidv7>`) populated by the `submit_feedback` MCP tool (`src/feedback.ts`), bounded by a per-isolate write budget (`FEEDBACK_WRITES_PER_MINUTE = 20`) and input size limits. Caller-supplied strings are isolated inside the `untrusted` envelope (`schema_version: 2`).

- **Code:** [`src/feedback.ts`](src/feedback.ts)
- **Binding ID:** `61642c6485674ef597cbff50fe9b9f18` (preview: `ef093fcb1caa4b55bb25f52b80082fc9`)
- **Runtime:** Cloudflare KV
- **Inputs:** `submit_feedback` MCP tool calls (`missing-namespace`, `correction`, `suggestion`)
- **Outputs:** KV keys (`feedback:<uuidv7>`) for maintainer/agent triage
- **Status:** production
- **Last touched:** 2026-11-04
- **Next review:** 2027-02-01
- **Cadence:** request-driven (on `submit_feedback` tool call)
- **Retention:** Open (untriaged) `feedback:<uuid>` records have **no `expirationTtl`** so inbox items are never dropped before triage. When marked resolved via `resolveFeedback()`, records are updated with a **30-day `expirationTtl`** (`RESOLVED_FEEDBACK_TTL_SECONDS = 2,592,000` seconds) so they remain auditable for 30 days and then age out automatically.
- **Health check:** `wrangler kv key list --remote --binding secid_FEEDBACK --prefix feedback:`
- **Runbook:** See [`docs/DEMAND-SIGNAL.md`](docs/DEMAND-SIGNAL.md) for listing and reading `feedback:<uuid>` entries. Note: passive namespace-miss capture (`miss:*`) was migrated out of `secid_FEEDBACK` to Cloudflare Workers Analytics Engine (`secid_DEMAND`).
- **Owner:** Kurt Seifried

## Workers Analytics Engine — `secid_DEMAND` (`secid_demand_misses`)

**What it does.** Append-only event log for passive namespace-miss demand signal (`not_found` at the namespace lookup step when the domain token looks like a valid domain). Written fire-and-forget via `writeDataPoint` (`src/demand.ts`), bounded by a per-isolate budget (`MISS_EVENTS_PER_MINUTE = 300`).

- **Code:** [`src/demand.ts`](src/demand.ts), [`docs/DEMAND-SIGNAL.md`](docs/DEMAND-SIGNAL.md)
- **Dataset:** `secid_demand_misses` (binding `secid_DEMAND`)
- **Runtime:** Cloudflare Workers Analytics Engine
- **Inputs:** namespace misses from `/api/v1/*` and `/mcp`
- **Outputs:** Analytics Engine data points (`index1 = "<type>/<namespace>"`, `blob1 = type`, `blob2 = namespace`, `blob3 = channel`, `blob4 = sanitized query sample`, `double1 = 1`)
- **Status:** production
- **Last touched:** 2026-11-04
- **Next review:** 2027-02-01
- **Cadence:** continuous, request-driven
- **Retention:** 3 months (managed automatically by Workers Analytics Engine)
- **Runbook:** Query top missing namespaces over the last 30 days via the Cloudflare Analytics Engine SQL API — see [`docs/DEMAND-SIGNAL.md`](docs/DEMAND-SIGNAL.md)
- **Owner:** Kurt Seifried

## GitHub Actions — Deploy chain (cross-repo)

**What it does.** Two-stage auto-deploy from registry JSON changes to live KV + Worker:

1. **Stage 1 (SecID repo):** [`registry-ci.yml`](https://github.com/CloudSecurityAlliance/SecID/blob/main/.github/workflows/registry-ci.yml) (replaced `update-registry.yml`) — on push to `main`, runs the registry validation gates; only if all pass does its `notify-service` job send `repository_dispatch` to SecID-Service using the `SECID_TO_SERVICE_DISPATCH` PAT, with `client_payload.ref` set to the validated commit SHA
2. **Stage 2 (this repo):** [`.github/workflows/registry-kv-upload.yml`](.github/workflows/registry-kv-upload.yml) — receives dispatch, checks out both repos, runs `build-registry.ts`, builds website, runs `vitest`, uploads to KV in `--sync` mode using `SECID_SERVICE_DEPLOY` Cloudflare token, deploys Worker

- **Runtime:** GitHub Actions runners (`ubuntu-latest`, Node 22)
- **Inputs:** push events on registry JSON; `repository_dispatch` events of type `registry-updated`
- **Outputs:** updated `secid_REGISTRY` KV; redeployed Worker
- **Status:** working — `repository_dispatch` runs succeed as of 2026-09-25. The 2026-04-30 breakage is recorded in [FRICTION-001](FRICTION/FRICTION-001.md)
- **Last touched:** 2026-09-25
- **Next review:** 2026-12-01
- **Cadence:** event-driven (every push to `registry/**/*.json`)
- **Health check:** `gh run list --workflow=registry-kv-upload.yml --limit 3 -R CloudSecurityAlliance/SecID-Service` — most recent run should be `success`
- **Post-deploy failure means live:** a run that fails at "Verify the deployed site" has already deployed — its job summary says so and carries the rollback command. Every production deployment should match one workflow run (`npx wrangler deployments list`)
- **Runbook:** See FRICTION-001 for past failure modes and workarounds. Local audit (no mutations): `npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID` from this repo with a working `CLOUDFLARE_API_TOKEN`
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
