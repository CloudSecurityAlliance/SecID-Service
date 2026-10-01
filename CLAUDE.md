# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecID-Service is the **production resolver** for the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID) — a Cloudflare Worker that serves the REST API and MCP server at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/).

The Worker reads from Cloudflare KV (binding `secid_REGISTRY`) and serves resolution requests via two transports:

- **REST API:** `GET /api/v1/resolve?secid=...` (response envelope: `{secid_query, status, results[], message?}`)
- **MCP Server:** `https://secid.cloudsecurityalliance.org/mcp` — four tools: `resolve`, `lookup`, `describe`, `submit_feedback`. Stateless, POST only; every other method is answered by `src/method-gate.ts` (README §"MCP endpoint behaviour", ADR-015)

## Multi-Repo Architecture

| Repo | Purpose |
|------|---------|
| [SecID](https://github.com/CloudSecurityAlliance/SecID) | Specification + registry data (source of truth) |
| **SecID-Service** (this repo) | Cloudflare Worker REST API + MCP server (production) |
| [SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API) | Self-hosted resolver (Python; TypeScript and Docker planned) |
| [SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) | Client libraries (Python, TypeScript, Go) |

## Repository Structure

```
SecID-Service/
├── src/
│   ├── index.ts            # Worker entry — routes /api/v1/*, /mcp, /
│   ├── api.ts              # REST API handlers
│   ├── mcp.ts              # MCP tool implementations
│   ├── method-gate.ts      # What /mcp answers for every non-POST method (ADR-015)
│   ├── parser.ts           # SecID string parsing (registry-aware)
│   ├── resolver.ts         # Resolution logic (pattern tree traversal)
│   ├── registry.ts         # Test-only registry snapshot (build-registry.ts output, gitignored)
│   ├── kv-registry.ts      # KV reads for registry data
│   ├── kv-resolve.ts       # KV-backed resolution path
│   ├── observability.ts    # Error recording to KV (UUIDv7 keys)
│   ├── feedback.ts         # submit_feedback records (secid_FEEDBACK KV)
│   ├── demand.ts           # Namespace-miss demand signal (Analytics Engine)
│   └── types.ts            # Shared types
├── scripts/
│   ├── build-registry.ts        # Compiles SecID JSON → src/registry.ts (test snapshot)
│   ├── upload-registry-kv.ts    # Uploads registry to KV (--sync deletes orphans)
│   ├── export-misses.ts         # Read-only demand digest from Analytics Engine (docs/DEMAND-SIGNAL.md)
│   ├── update-tlds.ts           # Regenerates src/tlds.ts from IANA
│   └── setup-dns.sh
├── test/                   # vitest tests (auto-generated fixtures from registry)
├── e2e/                    # Playwright against production; also the post-deploy gate
├── website/                # Astro static site (served from same Worker)
├── wrangler.toml           # Cloudflare Worker config (account, KV, routes)
└── .github/workflows/
    ├── ci.yml                  # PR gate: typecheck, website build, unit tests (never deploys)
    └── registry-kv-upload.yml  # Deploy: push to main, repository_dispatch from SecID, manual
```

## Development Commands

```bash
npm install
npm run dev              # Local dev server
npm run test             # Unit/integration tests (vitest, inside workerd)
npm run test:e2e         # Playwright against production (SITE_URL to override)
npm run build:registry   # Compile registry.ts from SecID repo
npm run deploy           # Break-glass deploy (builds website first). Normal path: merge to main

# Manual KV sync (audit + apply)
npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID  # see drift
npx tsx scripts/upload-registry-kv.ts --sync /path/to/SecID            # apply
```

## Cloudflare Setup

- **Account:** `f3898058ae0b4c20c692bbfa5b9b44b0` (Kseifried@cloudsecurityalliance.org's Account)
- **Worker route:** `secid.cloudsecurityalliance.org/*` (zone `cloudsecurityalliance.org`)
- **KV namespaces:**
  - `secid_REGISTRY` (id `cfbc271787614516a39fa43d9ca4f95a`) — registry data: one key per namespace plus the type, global and meta index keys
  - `secid_OBSERVABILITY` (id `c5cbc52b9a724433b3043efdf31857f4`) — error logging
  - `secid_FEEDBACK` (id `61642c6485674ef597cbff50fe9b9f18`) — `submit_feedback` records (`feedback:<uuid>`); legacy `miss:*` keys remain but are no longer written
- **Analytics Engine:** binding `secid_DEMAND` → dataset `secid_demand_misses` — namespace-miss demand signal (validated fields only, no caller text; three-month retention). Export with `scripts/export-misses.ts`; see [docs/DEMAND-SIGNAL.md](docs/DEMAND-SIGNAL.md)

## Deploy Chain

The full deploy chain is described in [SecID/CLAUDE.md](https://github.com/CloudSecurityAlliance/SecID/blob/main/CLAUDE.md#cicd). Briefly:

1. Registry change pushed to `CloudSecurityAlliance/SecID`
2. SecID's `registry-ci.yml` runs the registry validation gates; only if they all pass does its `notify-service` job fire `repository_dispatch` (event-type `registry-updated`, `client_payload.ref` = the validated commit SHA) using PAT `SECID_TO_SERVICE_DISPATCH`
3. This repo's `registry-kv-upload.yml` workflow runs against that SecID commit:
   - Builds + unit tests (a failure stops the run before any upload)
   - Runs `upload-registry-kv.ts --sync` using `SECID_SERVICE_DEPLOY` Cloudflare token
   - Deploys Worker
   - **Verifies production**: Playwright suite against the live site, MCP endpoint included, minus
     `@third-party` tests. A failure here means the new version IS live — the job summary carries
     the `wrangler rollback` command

A push to `main` runs the same workflow against SecID `main`, so **merging a PR deploys**. Cloudflare
Workers Builds is not deploying (every deployment matches one workflow run; README §Deployment).

The single GitHub Secret on this repo is `SECID_SERVICE_DEPLOY` (Cloudflare API token: Workers Scripts:Write + KV:Write + zone-scoped Routes:Write).

## Sync Mode (upload-registry-kv.ts)

The upload script supports three flags:

- `--sync` — upload all expected keys AND delete orphan keys (KV keys no longer produced by the registry). After this runs, KV exactly matches what the registry produces.
- `--dry-run` — show what would happen without making changes (combine with `--sync` to audit drift).
- `--force` — override the 50-orphan safety threshold (catches "registry didn't load" bugs that would mass-delete real data).
- `--preview` — use the preview KV namespace instead of production.

CI runs `--sync` by default, so KV stays continuously synchronized.

## Operational Limits

- **`secid` input:** 1024 characters (REST + MCP). Longer inputs return `status="error"`.
- **MCP HTTP body:** 64 KiB, counted on the bytes received (so a chunked body without `Content-Length` is bounded too); `413` if exceeded.
- **MCP JSON-RPC batch:** at most 10 messages, and a batch may not contain `submit_feedback` (`400`).
- **`submit_feedback` input:** `secid` ≤ 1024 chars, `message` 1–4000 chars, `suggested_urls` ≤ 10 entries of ≤ 2048 chars. Writes are capped at 20 per minute per isolate (`src/write-budget.ts`); past that the tool returns `status: "rate_limited"`.
- **`feedback:<uuid>` records** are `schema_version: 2`: all caller text sits under `untrusted`, with a `handling` note telling triage to treat it as data, never instructions.
- **Cloudflare KV value:** 25 MiB per key (script enforces before upload).
- **Test fixtures:** `test/resolver.test.ts` auto-generates one test per `data.examples` entry in registry JSON. Adding examples to the registry adds tests automatically.

## Key Design Decisions

- **Worker is stateless.** All state lives in KV; production reads it via `kv-registry.ts`. `src/registry.ts` is **not** a fallback and is not used at runtime: it is a gitignored snapshot that `build-registry.ts` generates so tests (and the seeded test KV) run against a known registry. A stale local snapshot makes tests disagree with production — rebuild it from the SecID checkout you care about.
- **Registry is the source of truth.** This repo doesn't store registry data — it loads from the SecID repo at build time and uploads to KV at deploy time.
- **Tests gate the deploy, and verify it afterwards.** If `npx vitest run` fails, the upload + deploy steps don't run; after deploy, the e2e suite must pass against production or the run fails. Test failures from registry-derived fixtures often indicate registry misconfiguration in the SecID repo, not bugs here.
- **`/mcp` answers every HTTP method explicitly** (ADR-015): 405 + `Allow` for MCP-client GET/HEAD and every registered method not served, a 302 to `/#mcp-setup` only for a positively identified browser, 501 for unregistered methods. Never redirect an MCP client or hold a stream open: either makes SDK clients reconnect once a second. Same table as CSA-MCP-Core's `src/mcp/method-gate.ts` — change both together.

## Common Operations

```bash
# Test the auto-trigger chain end-to-end (no registry change needed)
gh workflow run "Notify registry update" -R CloudSecurityAlliance/SecID

# Force a fresh KV sync without a registry change
gh workflow run "Upload registry to KV" -R CloudSecurityAlliance/SecID-Service

# Local audit (no mutations) — requires CLOUDFLARE_API_TOKEN env var
npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID

# Probe live KV directly (read-only)
CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=f3898058ae0b4c20c692bbfa5b9b44b0 \
  wrangler kv key list --remote --namespace-id=cfbc271787614516a39fa43d9ca4f95a

# Wrangler 4.x footgun: omitting --remote silently uses local emulator (returns []).
# Always pass --remote when probing production state.
```
