# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecID-Service is the **production resolver** for the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID) — a Cloudflare Worker that serves the REST API and MCP server at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/).

The Worker reads from Cloudflare KV (binding `secid_REGISTRY`) and serves resolution requests via two transports:

- **REST API:** `GET /api/v1/resolve?secid=...` (response envelope: `{secid_query, status, results[], message?}`)
- **MCP Server:** `https://secid.cloudsecurityalliance.org/mcp` — three tools: `resolve`, `lookup`, `describe`

## Multi-Repo Architecture

| Repo | Purpose |
|------|---------|
| [SecID](https://github.com/CloudSecurityAlliance/SecID) | Specification + registry data (source of truth) |
| **SecID-Service** (this repo) | Cloudflare Worker REST API + MCP server (production) |
| [SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API) | Self-hosted resolver (Python, TypeScript, Docker) |
| [SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) | Client libraries (Python, TypeScript, Go) |

## Repository Structure

```
SecID-Service/
├── src/
│   ├── index.ts            # Worker entry — routes /api/v1/*, /mcp, /
│   ├── api.ts              # REST API handlers
│   ├── mcp.ts              # MCP tool implementations
│   ├── parser.ts           # SecID string parsing (registry-aware)
│   ├── resolver.ts         # Resolution logic (pattern tree traversal)
│   ├── registry.ts         # Compiled-in fallback registry (build-registry.ts output)
│   ├── kv-registry.ts      # KV reads for registry data
│   ├── kv-resolve.ts       # KV-backed resolution path
│   ├── observability.ts    # Error recording to KV (UUIDv7 keys)
│   └── types.ts            # Shared types
├── scripts/
│   ├── build-registry.ts        # Compiles SecID JSON → src/registry.ts (fallback)
│   ├── upload-registry-kv.ts    # Uploads registry to KV (--sync deletes orphans)
│   └── setup-dns.sh
├── test/                   # vitest tests (auto-generated fixtures from registry)
├── website/                # Astro static site (served from same Worker)
├── wrangler.jsonc          # Cloudflare Worker config (account, KV, routes)
└── .github/workflows/
    └── registry-kv-upload.yml  # Triggered by repository_dispatch from SecID
```

## Development Commands

```bash
npm install
npm run dev              # Local dev server
npm run test             # Run tests
npm run build:registry   # Compile registry.ts from SecID repo
npm run deploy           # Deploy to Cloudflare (requires CLOUDFLARE_API_TOKEN)

# Manual KV sync (audit + apply)
npx tsx scripts/upload-registry-kv.ts --sync --dry-run /path/to/SecID  # see drift
npx tsx scripts/upload-registry-kv.ts --sync /path/to/SecID            # apply
```

## Cloudflare Setup

- **Account:** `f3898058ae0b4c20c692bbfa5b9b44b0` (Kseifried@cloudsecurityalliance.org's Account)
- **Worker route:** `secid.cloudsecurityalliance.org/*` (zone `cloudsecurityalliance.org`)
- **KV namespaces:**
  - `secid_REGISTRY` (id `cfbc271787614516a39fa43d9ca4f95a`) — registry data, ~700+ keys
  - `secid_OBSERVABILITY` (id `c5cbc52b9a724433b3043efdf31857f4`) — error logging

## Deploy Chain

The full deploy chain is described in [SecID/CLAUDE.md](https://github.com/CloudSecurityAlliance/SecID/blob/main/CLAUDE.md#cicd). Briefly:

1. Registry change pushed to `CloudSecurityAlliance/SecID`
2. SecID's notify workflow fires `repository_dispatch` (event-type `registry-updated`) using PAT `SECID_TO_SERVICE_DISPATCH`
3. This repo's `registry-kv-upload.yml` workflow runs:
   - Builds + tests
   - Runs `upload-registry-kv.ts --sync` using `SECID_SERVICE_DEPLOY` Cloudflare token
   - Deploys Worker

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
- **MCP HTTP body:** 64 KiB (`413` if exceeded).
- **Cloudflare KV value:** 25 MiB per key (script enforces before upload).
- **Test fixtures:** `test/resolver.test.ts` auto-generates one test per `data.examples` entry in registry JSON. Adding examples to the registry adds tests automatically.

## Key Design Decisions

- **Worker is stateless.** All state lives in KV. The Worker's compiled-in registry (`src/registry.ts`) is a fallback only; production reads from KV via `kv-registry.ts`.
- **Registry is the source of truth.** This repo doesn't store registry data — it loads from the SecID repo at build time and uploads to KV at deploy time.
- **Tests gate the deploy.** If `npx vitest run` fails, the upload + deploy steps don't run. Test failures from registry-derived fixtures often indicate registry misconfiguration in the SecID repo, not bugs here.
- **Stateless MCP must 405 GET/DELETE** on the Streamable HTTP transport — without this, SSE clients hang forever. (Known community issue across SDKs.)

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
